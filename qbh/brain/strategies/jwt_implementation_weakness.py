"""Offline JWT inspection, sharing the existing engine's decoder."""
from qbh.engines.jwt import _b64url_decode
from qbh.ingest.har_importer import digest
from qbh.brain.strategy import TestPlan, TestResult


def _token(context):
    for header in context.request.get('headers', []):
        if header['name'].lower() == 'authorization' and header['value'].lower().startswith('bearer '):
            value = header['value'][7:].strip()
            if len(value.split('.')) == 3:
                return value
    for cookie in context.request.get('cookies', []):
        value = cookie.get('value', '')
        if isinstance(value, str) and value.startswith('eyJ') and len(value.split('.')) == 3:
            return value
    return None


class Strategy:
    vuln_class = 'jwt_implementation_weakness'

    def is_applicable(self, context):
        return (True, 'observed_jwt') if _token(context) else (False, 'missing:jwt_token')

    def plan_test(self, context):
        applicable, reason = self.is_applicable(context)
        return TestPlan(self.vuln_class, context.request_id, context.prerequisite_hash, reason,
                        () if applicable else ('jwt_token',), tuple(context.evidence_refs), ())

    async def execute_test(self, context, plan):
        token = _token(context)
        if not token:
            return TestResult('deferred', 'missing:jwt_token')
        header = _b64url_decode(token.split('.')[0])
        if not isinstance(header, dict) or not header:
            return TestResult('inconclusive', 'invalid_jwt_header')
        unsigned = str(header.get('alg', '')).lower() == 'none'
        return TestResult('candidate' if unsigned else 'completed',
                          'unsigned_token_requires_server_acceptance_verification' if unsigned else 'no_unsigned_algorithm_signal',
                          [{'kind': 'jwt_metadata', 'token_digest': digest(token),
                            'unsigned_algorithm': unsigned, 'evidence_refs': list(plan.evidence_refs)}])
