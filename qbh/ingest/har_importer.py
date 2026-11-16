"""Offline HAR ingestion with encrypted evidence and durable entry outcomes."""
from __future__ import annotations

import base64
import hashlib
import json
import math
from datetime import datetime
from email.parser import BytesParser
from email.policy import default
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from qbh import db
from qbh.redact import redact
from qbh.tasks import task_identity
from qbh.vault import SecretVault


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def safe_url(url):
    """Opaque paths/query values can themselves be credentials: conceal them all."""
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.hostname or '', '/<redacted>', '', ''))


def headers(items):
    if not isinstance(items, list):
        raise ValueError('invalid_headers')
    result = []
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get('name'), str) or not isinstance(item.get('value'), str):
            raise ValueError('invalid_header')
        result.append({'name': item['name'], 'value': item['value']})
    return result


def parse_body(post):
    if not isinstance(post, dict):
        raise ValueError('invalid_post_data')
    mime = post.get('mimeType', '')
    text = post.get('text', '')
    if not isinstance(mime, str) or not isinstance(text, str):
        raise ValueError('invalid_body')
    if post.get('params') is not None:
        if not isinstance(post['params'], list):
            raise ValueError('invalid_body_params')
        return {'type': mime, 'fields': post['params'], 'text': text}
    if 'json' in mime and text:
        try:
            fields = json.loads(text)
        except ValueError:
            return {'type': mime, 'text': text, 'parse_error': 'invalid_json_body'}
        return {'type': mime, 'fields': fields, 'text': text}
    if 'application/x-www-form-urlencoded' in mime:
        return {'type': mime, 'fields': parse_qsl(text, keep_blank_values=True), 'text': text}
    if 'multipart/form-data' in mime:
        message = BytesParser(policy=default).parsebytes(
            ('Content-Type: ' + mime + '\r\nMIME-Version: 1.0\r\n\r\n' + text).encode())
        fields = []
        for part in message.iter_parts():
            payload = part.get_payload(decode=True) or b''
            fields.append({'name': part.get_param('name', header='content-disposition'),
                           'filename': part.get_filename(),
                           'value': None if part.get_filename() else payload.decode('utf-8', 'replace'),
                           'sha256': hashlib.sha256(payload).hexdigest()})
        return {'type': mime, 'fields': fields}
    if mime and not any(t in mime for t in ('text/', 'xml', 'javascript')):
        return {'type': mime, 'sha256': hashlib.sha256(text.encode()).hexdigest(),
                'reference_only': True}
    return {'type': mime, 'text': text}


def parse_entry(entry):
    if not isinstance(entry, dict):
        raise ValueError('invalid_entry')
    request, response = entry['request'], entry['response']
    method, url = request['method'], request['url']
    if not isinstance(method, str) or not method.isalpha() or not isinstance(url, str):
        raise ValueError('invalid_request')
    parts = urlsplit(url)
    if parts.scheme not in ('http', 'https') or not parts.hostname:
        raise ValueError('invalid_url')
    status = response['status']
    if type(status) is not int or not 0 <= status <= 599:
        raise ValueError('invalid_status')
    elapsed = entry.get('time')
    if elapsed is not None and (type(elapsed) not in (int, float) or not math.isfinite(elapsed)):
        raise ValueError('invalid_timing')
    started = entry.get('startedDateTime')
    if started is not None:
        if not isinstance(started, str):
            raise ValueError('invalid_started_time')
        datetime.fromisoformat(started.replace('Z', '+00:00'))
    for message in (request, response):
        cookies = message.get('cookies', [])
        if not isinstance(cookies, list) or any(not isinstance(c, dict) for c in cookies):
            raise ValueError('invalid_cookies')
    content = response.get('content', {})
    if not isinstance(content, dict):
        raise ValueError('invalid_content')
    if not isinstance(content.get('text', ''), str):
        raise ValueError('invalid_content_text')
    if content.get('encoding') == 'base64':
        binary = base64.b64decode(content.get('text', ''), validate=True)
        if any(t in content.get('mimeType', '') for t in ('text/', 'json', 'xml', 'javascript')):
            try:
                content = {**content, 'text': binary.decode('utf-8'), 'decoded_encoding': 'base64'}
            except UnicodeDecodeError:
                content = {**{k: v for k, v in content.items() if k != 'text'},
                           'sha256': hashlib.sha256(binary).hexdigest(), 'reference_only': True}
        else:
            content = {k: v for k, v in content.items() if k != 'text'}
            content.update(sha256=hashlib.sha256(binary).hexdigest(), reference_only=True)
    elif content.get('mimeType') and not any(t in content['mimeType'] for t in ('text/', 'json', 'xml', 'javascript')):
        content = {**{k: v for k, v in content.items() if k != 'text'},
                   'sha256': hashlib.sha256(content.get('text', '').encode()).hexdigest(), 'reference_only': True}
    req = {'method': method.upper(), 'url': url, 'headers': headers(request.get('headers', [])),
           'cookies': request.get('cookies', []), 'body': parse_body(request.get('postData', {}))}
    resp = {'status': status, 'headers': headers(response.get('headers', [])),
            'cookies': response.get('cookies', []), 'content': content}
    return req, resp


class HarImporter:
    def __init__(self, vault=None):
        self.vault = vault if vault is not None else SecretVault()

    def import_file(self, path, scan_id=None):
        raw = Path(path).read_bytes()
        document = json.loads(raw)
        entries = document['log']['entries']
        if not isinstance(entries, list):
            raise ValueError('HAR log.entries must be an array')
        db.init_db()
        if scan_id is None:
            scan_id = db.start_scan('har_import', 'import')
        if db.get_scan(scan_id) is None:
            raise ValueError('unknown_scan')
        source = hashlib.sha256(raw).hexdigest()
        report = {'scan_id': scan_id, 'imported': 0, 'duplicate': 0, 'blocked': 0, 'invalid': 0, 'entries': []}
        conn = db.get_db()
        for sequence, entry in enumerate(entries):
            request_id = None
            occurrence = None
            try:
                req, resp = parse_entry(entry)
            except (KeyError, TypeError, ValueError, AttributeError):
                status, reason = 'invalid', 'malformed_entry'
            else:
                if not self.vault.available:
                    status, reason = 'blocked', 'vault_unavailable_retryable'
                else:
                    parts = urlsplit(req['url'])
                    identity = task_identity(scan_id, 'har_import', req['url'], method=req['method'], param=digest(req))
                    encrypted_request = self.vault.encrypt(canonical(req))
                    encrypted_response = self.vault.encrypt(canonical(resp))
                    if encrypted_request is None or encrypted_response is None:
                        status, reason = 'blocked', 'vault_encryption_failed_retryable'
                    else:
                        with conn:
                            cur = conn.execute(
                                'INSERT OR IGNORE INTO imported_requests '
                                '(scan_id,method,url,host,path,query_params,headers,request_body,response_status,'
                                'response_headers,response_body,started_at,time_ms,sequence_order,dedup_identity,provenance) '
                                'VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                                (scan_id, req['method'], safe_url(req['url']), parts.hostname, '/<redacted>',
                                 canonical([['<redacted>', '<redacted>'] for k, _ in parse_qsl(parts.query)]),
                                 canonical([{'name': redact(h['name']), 'value': '<redacted>'} for h in req['headers']]),
                                 encrypted_request, resp['status'],
                                 canonical([{'name': redact(h['name']), 'value': '<redacted>'} for h in resp['headers']]),
                                 encrypted_response, entry.get('startedDateTime') if isinstance(entry.get('startedDateTime'), str) else None,
                                 entry.get('time'), sequence, identity,
                                 canonical({'source': 'har_import', 'source_sha256': source, 'sequence': sequence})))
                            status = 'imported' if cur.rowcount else 'duplicate'
                            request_id = conn.execute('SELECT id FROM imported_requests WHERE scan_id=? AND dedup_identity=?',
                                                      (scan_id, identity)).fetchone()['id']
                        occurrence = self.vault.encrypt(canonical({'request': req, 'response': resp,
                                                                    'timings': entry.get('timings'),
                                                                    'startedDateTime': entry.get('startedDateTime')}))
                        reason = 'encrypted_evidence' if status == 'imported' else 'same_request_identity'
            with conn:
                conn.execute('INSERT INTO import_entries '
                             '(scan_id,source_digest,sequence_order,request_id,status,reason,created_at,evidence_enc) VALUES (?,?,?,?,?,?,?,?)',
                             (scan_id, source, sequence, request_id, status, reason, db._now(), occurrence))
            report[status] += 1
            report['entries'].append({'sequence': sequence, 'request_id': request_id, 'status': status, 'reason': reason})
        return report

    def evidence(self, request_id):
        row = db.get_db().execute('SELECT request_body,response_body FROM imported_requests WHERE id=?', (request_id,)).fetchone()
        if row is None:
            raise ValueError('unknown_request')
        values = [self.vault.decrypt(row[k]) for k in ('request_body', 'response_body')]
        if any(v is None for v in values):
            raise ValueError('vault_evidence_unavailable')
        return tuple(json.loads(v) for v in values)


def list_imported(scan_id=None):
    sql = 'SELECT id,scan_id,source,method,url,host,response_status,sequence_order,provenance FROM imported_requests'
    args = () if scan_id is None else (scan_id,)
    return [dict(r) for r in db.get_db().execute(sql + ('' if scan_id is None else ' WHERE scan_id=?') + ' ORDER BY id', args)]
