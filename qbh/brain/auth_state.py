"""User-configured auth identities, encrypted sessions and auditable validity."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime
from http.cookies import SimpleCookie
import json
import os
import uuid
from urllib.parse import urlsplit

import aiohttp

from qbh import db
from qbh.authorization import AuthorizationError
from qbh.scope import ScopeError
from qbh.ingest.har_importer import canonical, digest, HarImporter
from qbh.ingest.request_graph import RequestGraph
from .auth_config import origin, validate_contexts


def _now():
    return datetime.now(timezone.utc)


def _field(document, path):
    for key in path.split('.'):
        if not isinstance(document, dict):
            return None
        document = document.get(key)
    return document


def _json_response(response):
    if response.truncated:
        raise ValueError('truncated_auth_response')
    try:
        value = json.loads(response.text)
    except (ValueError, TypeError):
        return {}
    return value if isinstance(value, dict) else {}


@dataclass
class AuthContext:
    name: str
    role: str
    session_id: str = ''
    cookies: dict = field(default_factory=dict)  # Cookie names -> vault reference, never values.
    provenance: str = 'user_configuration'
    valid_until: datetime | None = None
    origin: str = ''
    status: str = 'registered'
    identity_verified: bool = False
    subject_digest: str = ''


class AuthStateMachine:
    def __init__(self, runtime):
        self.runtime = runtime
        self.scan_id = db.effective_scan_id(runtime.scan_id)
        self.contexts = {}
        self._configs = {}

    def _event(self, context, status, reason, evidence=None):
        encrypted = self.runtime.vault.encrypt(canonical(evidence)) if evidence is not None else None
        if evidence is not None and encrypted is None:
            status, reason = 'blocked', 'vault_unavailable_retryable'
        context.status = status
        context.provenance = reason
        conn = db.get_db()
        with conn:
            conn.execute('UPDATE auth_contexts SET status=?,provenance=?,session_id=?,valid_until=? '
                         'WHERE scan_id=? AND name=?',
                         (status, reason, context.session_id or None,
                          context.valid_until.isoformat() if context.valid_until else None, self.scan_id, context.name))
            conn.execute('INSERT INTO auth_context_events(scan_id,context_name,status,reason,evidence_enc,created_at) '
                         'VALUES(?,?,?,?,?,?)', (self.scan_id, context.name, status, reason, encrypted, db._now()))

    def register_context(self, name, role, credentials_source):
        spec = validate_contexts([{**credentials_source, 'name': name, 'role': role}])[0]
        context = AuthContext(name, role, origin=origin(spec['login_url']))
        self._configs[name] = spec
        self.contexts[name] = context
        conn = db.get_db()
        previous = conn.execute('SELECT * FROM auth_contexts WHERE scan_id=? AND name=?', (self.scan_id, name)).fetchone()
        if previous and previous['config_digest'] == digest(spec):
            context.session_id = previous['session_id'] or ''
            context.status = previous['status']
            context.provenance = previous['provenance']
            context.valid_until = datetime.fromisoformat(previous['valid_until']) if previous['valid_until'] else None
            if context.session_id:
                try:
                    payload = self._payload(context)
                    context.cookies = {c['name']: context.session_id for c in payload['cookies']}
                    context.identity_verified = bool(payload['identity_verified'])
                    context.subject_digest = digest(payload['subject']) if payload['subject'] is not None else ''
                    try:
                        changed = payload.get('credential_digest') != digest(self._credentials(spec))
                    except ValueError:
                        changed = False  # Existing encrypted session may be resumed without login credentials.
                    if changed:
                        context.session_id, context.valid_until = '', None
                        context.identity_verified, context.subject_digest = False, ''
                        self._event(context, 'registered', 'credential_source_changed')
                except ValueError:
                    self._event(context, 'blocked', 'session_vault_unavailable_retryable')
            return context
        with conn:
            conn.execute('INSERT INTO auth_contexts(scan_id,name,role,origin,status,provenance,config_digest) '
                         'VALUES(?,?,?,?,?,?,?) ON CONFLICT(scan_id,name) DO UPDATE SET '
                         'role=excluded.role,origin=excluded.origin,status=excluded.status,provenance=excluded.provenance,'
                         'config_digest=excluded.config_digest,session_id=NULL,valid_until=NULL',
                         (self.scan_id, name, role, context.origin, context.status, context.provenance, digest(spec)))
        self._event(context, 'registered', 'user_configured_context')
        return context

    def _payload(self, context):
        if self.contexts.get(context.name) is not context or not context.session_id:
            raise ValueError('unregistered_auth_context')
        row = db.get_db().execute('SELECT payload_enc FROM auth_sessions WHERE id=? AND scan_id=? AND context_name=?',
                                  (context.session_id, self.scan_id, context.name)).fetchone()
        plain = self.runtime.vault.decrypt(row['payload_enc']) if row else None
        if plain is None:
            raise ValueError('session_vault_unavailable')
        return json.loads(plain)

    def is_valid(self, context):
        if self.contexts.get(context.name) is not context or context.status != 'authenticated':
            return False
        if context.valid_until is None or context.valid_until <= _now():
            return False
        try:
            payload = self._payload(context)
        except ValueError:
            return False
        return bool(payload.get('authorization') or any(
            c.get('value') and (not c.get('secure') or context.origin.startswith('https:')) and (c.get('expires_at') is None or c['expires_at'] > _now().timestamp())
            for c in payload.get('cookies', [])))

    def headers_for(self, context, url):
        self.runtime._auth().ensure_active()
        self.runtime._auth().authorize_url(url)
        self.runtime._auth().require('authentication')
        if origin(url) != context.origin or not self.is_valid(context):
            raise ValueError('auth_context_not_compatible_or_expired')
        payload = self._payload(context)
        if payload['origin'] != origin(url):
            raise ValueError('credential_origin_mismatch')
        headers = {}
        if payload.get('authorization'):
            headers['Authorization'] = payload['authorization']
        cookies = SimpleCookie()
        path = urlsplit(url).path or '/'
        for cookie in payload['cookies']:
            cookie_path = cookie['path'] or '/'
            if not (path == cookie_path or path.startswith(cookie_path.rstrip('/') + '/')):
                continue
            if cookie.get('secure') and urlsplit(url).scheme != 'https':
                continue
            if cookie.get('expires_at') is not None and cookie['expires_at'] <= _now().timestamp():
                continue
            cookies[cookie['name']] = cookie['value']
        if cookies:
            headers['Cookie'] = '; '.join(m.OutputString() for m in cookies.values())
        if not headers:
            raise ValueError('no_credentials_for_request_path')
        return headers

    def get_compatible_requests(self, context):
        if not self.is_valid(context):
            return []
        result = []
        graph = RequestGraph(self.scan_id, self.runtime.vault)
        for row in db.get_db().execute('SELECT id FROM imported_requests WHERE scan_id=?', (self.scan_id,)):
            request, _ = HarImporter(self.runtime.vault).evidence(row['id'])
            try:
                self.headers_for(context, request['url'])
            except (ValueError, AuthorizationError) as exc:
                # Preserve why this identity cannot be used; the imported endpoint remains in its scan.
                with db.get_db() as conn:
                    conn.execute('INSERT INTO auth_context_events(scan_id,context_name,status,reason,evidence_enc,created_at) '
                                 'VALUES(?,?,?,?,?,?)', (self.scan_id, context.name, 'request_incompatible',
                                                        type(exc).__name__, self.runtime.vault.encrypt(canonical(
                                                            {'request_id': row['id']})), db._now()))
                continue
            result.append(graph.add_request(row['id']))
        return result

    def _credentials(self, spec):
        result = {}
        for key, reference in spec['login_fields'].items():
            if key.endswith('_env'):
                name, value = key[:-4], os.environ.get(reference)
            else:
                name = key[:-10]
                row = db.get_db().execute(
                    'SELECT s.value_enc FROM secrets s JOIN hosts h ON h.id=s.host_id '
                    'WHERE s.id=? AND h.scan_id=? AND h.subdomain=?',
                    (reference, self.scan_id, urlsplit(spec['login_url']).hostname)).fetchone()
                value = self.runtime.vault.decrypt(row['value_enc']) if row else None
            if not value:
                raise ValueError('credential_source_unavailable')
            result[name] = value
        return result

    @staticmethod
    def _cookies(jar):
        cookies = []
        for morsel in jar:
            expires_at = None
            if morsel['max-age']:
                expires_at = _now().timestamp() + int(morsel['max-age'])
            elif morsel['expires']:
                expires_at = parsedate_to_datetime(morsel['expires']).timestamp()
            cookies.append({'name': morsel.key, 'value': morsel.value, 'path': morsel['path'],
                            'secure': bool(morsel['secure']), 'expires_at': expires_at})
        return cookies

    def subject(self, context):
        if not self.is_valid(context):
            return None
        payload = self._payload(context)
        return payload['subject'] if payload['identity_verified'] else None

    def invalidate(self, context, reason='session_rejected'):
        # Caller supplies an audit code, not a provider error body.
        allowed = {'session_rejected', 'expired', 'identity_changed'}
        self._event(context, 'invalid', reason if reason in allowed else 'session_rejected')

    async def authenticate(self, context):
        if self.contexts.get(context.name) is not context:
            raise ValueError('unregistered_auth_context')
        spec = self._configs[context.name]
        if not self.runtime.vault.available:
            self._event(context, 'blocked', 'vault_unavailable_retryable')
            return False
        auth = self.runtime._auth()
        evidence = []
        try:
            auth.ensure_active()
            auth.authorize_request(spec['login_method'], spec['login_url'], 'authentication')
            auth.require('authentication')
            credentials = self._credentials(spec)
            # Fresh jar per identity; never share the scan's ambient cookie jar.
            async with aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True)) as session:
                basic = aiohttp.BasicAuth(credentials['username'], credentials['password']).encode() if spec['login_format'] == 'basic' else ''
                kwargs = ({'headers': {'Authorization': basic}} if basic else
                          {spec['login_format'] if spec['login_format'] == 'json' else 'data': credentials})
                response = await self.runtime.guardian.request(session, spec['login_method'], spec['login_url'],
                                                               allow_redirects=False, retries=0, **kwargs)
                evidence.append({'kind': 'login_response', 'status': response.status,
                                 'headers': dict(response.headers), 'body': response.text})
                document = _json_response(response)
                subject = _field(document, spec['subject_field'])
                token = _field(document, spec['token_field'])
                if token is not None and not isinstance(token, str):
                    raise ValueError('invalid_auth_token_type')
                authorization = 'Bearer ' + token if token else basic
                cookies = self._cookies(session.cookie_jar)
                if not 200 <= response.status < 300 or not (authorization or cookies):
                    raise ValueError('login_not_authenticated')
                verified = False
                if spec.get('verify_url'):
                    auth.ensure_active()
                    auth.authorize_request('GET', spec['verify_url'], 'authentication')
                    auth.require('authentication')
                    headers = {'Authorization': authorization} if authorization else {}
                    check = await self.runtime.guardian.get(session, spec['verify_url'], headers=headers,
                                                            allow_redirects=False, retries=0)
                    evidence.append({'kind': 'identity_response', 'status': check.status,
                                     'headers': dict(check.headers), 'body': check.text})
                    verified_subject = _field(_json_response(check), spec['subject_field'])
                    if not 200 <= check.status < 300 or not isinstance(verified_subject, (str, int)) or isinstance(verified_subject, bool):
                        raise ValueError('identity_verification_failed')
                    if subject is not None and str(subject) != str(verified_subject):
                        raise ValueError('identity_subject_changed')
                    async with aiohttp.ClientSession(cookie_jar=aiohttp.DummyCookieJar()) as anonymous:
                        auth.ensure_active()
                        auth.authorize_request('GET', spec['verify_url'], 'authentication')
                        control = await self.runtime.guardian.get(anonymous, spec['verify_url'],
                                                                 allow_redirects=False, retries=0, observe_block=False)
                    evidence.append({'kind': 'anonymous_identity_control', 'status': control.status,
                                     'headers': dict(control.headers), 'body': control.text})
                    if control.status not in (401, 403):
                        raise ValueError('identity_endpoint_not_protected')
                    subject, verified = verified_subject, True
                cookies = self._cookies(session.cookie_jar)
            payload = {'authorization': authorization, 'cookies': cookies, 'subject': subject,
                       'identity_verified': verified, 'origin': context.origin, 'credential_digest': digest(credentials)}
            encrypted = self.runtime.vault.encrypt(canonical(payload))
            if encrypted is None:
                raise ValueError('session_encryption_failed')
            reference = uuid.uuid4().hex
            conn = db.get_db()
            with conn:
                conn.execute('INSERT INTO auth_sessions(id,scan_id,context_name,payload_enc,created_at) VALUES(?,?,?,?,?)',
                             (reference, self.scan_id, context.name, encrypted, db._now()))
            context.session_id = reference
            context.cookies = {c['name']: reference for c in cookies}
            context.valid_until = _now() + timedelta(seconds=spec['session_ttl_seconds'])
            context.identity_verified = verified
            context.subject_digest = digest(subject) if subject is not None else ''
            self._event(context, 'authenticated', 'identity_verified' if verified else 'login_observed_identity_unverified', evidence)
            from qbh.adaptive import note_evidence
            note_evidence(self.runtime, 'auth_context_added', 'auth_session:' + reference)
            return True
        except (ValueError, ScopeError, aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
            # Credential-bearing provider exceptions are not logged or persisted verbatim.
            self._event(context, 'failed', 'authentication_failed:' + type(exc).__name__, evidence)
            return False

    async def initialize(self):
        if not hasattr(self, '_attempts'):
            self._attempts = set()
        for spec in self.runtime.cfg.auth_contexts:
            context = self.register_context(spec['name'], spec['role'], spec)
            try:
                credential_version = digest(self._credentials(spec))
            except ValueError:
                credential_version = 'unavailable'
            attempt = (context.name, digest(spec), credential_version, context.session_id)
            if not self.is_valid(context) and attempt not in self._attempts:
                self._attempts.add(attempt)
                await self.authenticate(context)
        return self.contexts
