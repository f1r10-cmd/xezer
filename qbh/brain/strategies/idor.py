"""Read-only cross-identity observations; confirmation requires later verification."""
from dataclasses import asdict
from qbh.brain.diff_engine import DiffEngine
from qbh.brain.strategy import TestPlan, TestResult
from qbh.ingest.har_importer import digest


class Strategy:
    vuln_class = 'idor'

    def _missing(self, context):
        missing = []
        if context.request.get('method', 'GET').upper() not in {'GET', 'HEAD'}:
            missing.append('read_only_request')
        if len({getattr(a, 'name', '') for a in context.auth_states}) < 2:
            missing.append('two_distinct_identities')
        for name in ('protected_resource', 'ownership_evidence'):
            if not context.prerequisites.get(name):
                missing.append(name)
        if getattr(context.runtime, 'auth_state', None) is None:
            missing.append('registered_auth_state')
        return tuple(missing)

    def is_applicable(self, context):
        missing = self._missing(context)
        return (False, 'missing:' + ','.join(missing)) if missing else (True, 'cross_identity_protected_resource')

    def plan_test(self, context):
        _, reason = self.is_applicable(context)
        return TestPlan(self.vuln_class, context.request_id, context.prerequisite_hash, reason,
                        self._missing(context), tuple(context.evidence_refs))

    async def execute_test(self, context, plan):
        missing = self._missing(context)
        if missing:
            return TestResult('deferred', 'missing:' + ','.join(missing))
        runtime = context.runtime
        auth = runtime._auth()
        url = context.request['url']
        observations, responses = [], []
        # A fresh session per identity is intentional: prevent cookie-jar cross-talk.
        import aiohttp
        for identity in context.auth_states:
            auth.ensure_active()
            auth.authorize_url(url)
            auth.require(self.vuln_class)
            auth.require('active_fuzz')
            headers = runtime.auth_state.headers_for(identity, url)
            async with aiohttp.ClientSession(cookie_jar=aiohttp.DummyCookieJar()) as session:
                response = await runtime.guardian.request(session, context.request.get('method', 'GET'), url,
                                                          headers=headers, allow_redirects=False)
            responses.append(response)
            observations.append({'identity': identity.name, 'status': response.status,
                                 'body_digest': digest(response.text), 'truncated': response.truncated})
        comparisons = [asdict(DiffEngine().compare(responses[0], other)) for other in responses[1:]]
        # Similarity is useful evidence but cannot prove unauthorized access.
        return TestResult('inconclusive', 'cross_identity_observations_require_ownership_and_diff_verification',
                          [{'kind': 'identity_comparison', 'observations': observations,
                            'evidence_refs': list(plan.evidence_refs)},
                           {'kind': 'response_differences', 'comparisons': comparisons}])
