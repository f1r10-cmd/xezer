"""Bounded read-only probes; repeated owner-only disclosure is required for confirmation."""
from dataclasses import asdict
import json

import aiohttp

from qbh.brain.auth_state import _field
from qbh.brain.diff_engine import DiffEngine
from qbh.brain.strategy import TestPlan, TestResult
from qbh.ingest.har_importer import digest

CHECKS = frozenset({'distinct_verified_subjects', 'owner_matches_subject', 'owner_only_policy',
                    'protected_object_matches', 'anonymous_denied', 'repeated_disclosure'})


def has_confirmation(result):
    """A candidate flag or HTTP 200 alone can never enter the confirmed lifecycle."""
    return result.status == 'confirmed' and result.confirmed and any(
        item.get('kind') == 'verified_access_control'
        and set(item.get('checks', {})) == CHECKS and all(value is True for value in item['checks'].values())
        and item.get('policy_ref', '').startswith('config:auth_resource_policies:')
        and len(set(item.get('session_refs', []))) == 2
        for item in result.evidence)


def _document(response):
    if response.truncated or response.status != 200:
        return {}

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('ambiguous_json')
            result[key] = value
        return result

    def invalid(value):
        raise ValueError('nonfinite_json')

    try:
        value = json.loads(response.text, object_pairs_hook=unique, parse_constant=invalid)
    except (TypeError, ValueError, RecursionError):
        return {}
    return value if isinstance(value, dict) else {}


def _identifier(value):
    return type(value) in (str, int) and value != ''


def _object(document, policy):
    owner, ident = _field(document, policy['owner_field']), _field(document, policy['object_id_field'])
    values = [_field(document, name) for name in policy['protected_fields']]
    if not _identifier(owner) or not _identifier(ident) or any(v is None or v == '' or v == [] or v == {} for v in values):
        return None
    return {'owner': owner, 'id': ident, 'protected': values}


class Strategy:
    vuln_class = 'idor'

    def _missing(self, context):
        missing = []
        if context.request.get('method', 'GET').upper() not in {'GET', 'HEAD'}:
            missing.append('read_only_request')
        if len({getattr(a, 'name', '') for a in context.auth_states}) < 2:
            missing.append('two_distinct_identities')
        if getattr(context.runtime, 'auth_state', None) is None:
            missing.append('registered_auth_state')
        return tuple(missing)

    def is_applicable(self, context):
        missing = self._missing(context)
        return (False, 'missing:' + ','.join(missing)) if missing else (True, 'bounded_cross_identity_applicability_probe')

    def plan_test(self, context):
        _, reason = self.is_applicable(context)
        return TestPlan(self.vuln_class, context.request_id, context.prerequisite_hash, reason,
                        self._missing(context), tuple(context.evidence_refs))

    async def execute_test(self, context, plan):
        missing = self._missing(context)
        if missing:
            return TestResult('deferred', 'missing:' + ','.join(missing))
        runtime, url = context.runtime, context.request['url']
        provider = runtime.auth_state
        observations, responses, evidence = [], [], []

        async def fetch(identity=None, label='initial'):
            auth = runtime._auth()
            auth.ensure_active()
            auth.authorize_request(context.request.get('method', 'GET'), url, self.vuln_class)
            auth.require(self.vuln_class)
            auth.require('active_fuzz')
            headers = provider.headers_for(identity, url) if identity is not None else {}
            # Do not forward HAR auth headers, ambient cookies, or redirects. Each actor has its own jar.
            async with aiohttp.ClientSession(cookie_jar=aiohttp.DummyCookieJar()) as session:
                response = await runtime.guardian.request(
                    session, context.request.get('method', 'GET'), url, headers=headers,
                    allow_redirects=False, retries=0, observe_block=False)
            evidence.append({'kind': 'replay_response', 'label': label,
                             'identity': identity.name if identity is not None else 'anonymous',
                             'session_ref': identity.session_id if identity is not None else None,
                             'status': response.status, 'headers': dict(response.headers),
                             'body': response.text, 'truncated': response.truncated})
            return response

        for identity in context.auth_states:
            response = await fetch(identity)
            responses.append(response)
            observations.append({'identity': identity.name, 'status': response.status,
                                 'body_digest': digest(response.text), 'truncated': response.truncated})
        comparisons = [asdict(DiffEngine().compare(responses[0], other)) for other in responses[1:]]
        evidence[:0] = [{'kind': 'identity_comparison', 'observations': observations,
                         'evidence_refs': list(plan.evidence_refs)},
                        {'kind': 'response_differences', 'comparisons': comparisons}]
        # Lack of ownership proof does not suppress the applicability probe above.
        if not context.resource_policies or not callable(getattr(provider, 'subject', None)):
            return TestResult('inconclusive', 'confirmation_missing:owner_only_policy_or_verified_subjects', evidence)
        # Overlapping policies are ambiguous; never pick a convenient one to confirm.
        if len(context.resource_policies) != 1:
            return TestResult('inconclusive', 'confirmation_missing:unambiguous_resource_policy', evidence)
        policy = context.resource_policies[0]
        for owner_idx, owner in enumerate(context.auth_states):
            subject = provider.subject(owner)
            baseline = _object(_document(responses[owner_idx]), policy)
            if not _identifier(subject) or not baseline or str(baseline['owner']) != str(subject) or owner.role not in policy['roles']:
                continue
            for other_idx, other in enumerate(context.auth_states):
                other_subject = provider.subject(other)
                if (not _identifier(other_subject) or str(subject) == str(other_subject)
                        or other.role != owner.role or other.role not in policy['roles']):
                    continue
                exposed = _object(_document(responses[other_idx]), policy)
                if exposed != baseline:
                    continue
                anonymous = await fetch(label='anonymous_control')
                if anonymous.status not in (401, 403) or anonymous.truncated:
                    return TestResult('inconclusive', 'confirmation_missing:anonymous_denial', evidence)
                repeated_owner = await fetch(owner, 'owner_repeat')
                repeated_other = await fetch(other, 'non_owner_repeat')
                repeated = [_object(_document(r), policy) for r in (repeated_owner, repeated_other)]
                if repeated != [baseline, baseline]:
                    return TestResult('inconclusive', 'confirmation_missing:stable_repeated_disclosure', evidence)
                evidence.append({'kind': 'verified_access_control', 'checks': dict.fromkeys(CHECKS, True),
                                 'policy_ref': 'config:auth_resource_policies:' + policy['id'],
                                 'session_refs': [owner.session_id, other.session_id],
                                 'object_digest': digest(baseline),
                                 'repeat_comparison': asdict(DiffEngine().compare(repeated_owner, repeated_other))})
                return TestResult('confirmed', 'repeated_owner_only_data_disclosed_to_distinct_non_owner', evidence, True)
        return TestResult('inconclusive', 'no_verified_owner_only_cross_identity_disclosure', evidence)
