import base64
import json
from types import SimpleNamespace

import pytest

from qbh.brain.context import ContextBuilder, TestContext
from qbh.brain.strategy import discover
from qbh.ingest.har_importer import HarImporter
from qbh.vault import SecretVault


def test_plugin_discovery_does_not_need_central_registration(tmp_path, monkeypatch):
    package = tmp_path / 'extra_plugins'
    package.mkdir()
    (package / '__init__.py').write_text('')
    (package / 'new_class.py').write_text('''class Strategy:
    vuln_class = "new_class"
    def is_applicable(self, context): return True, "evidence"
    def plan_test(self, context): return None
    async def execute_test(self, context, plan): return None
''')
    monkeypatch.syspath_prepend(str(tmp_path))
    assert set(discover('extra_plugins')) == {'new_class'}
    assert {'idor', 'jwt_implementation_weakness'} <= discover().keys()


async def test_unsigned_jwt_is_candidate_never_confirmed():
    def encode(value):
        return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip('=')
    token = encode({'alg': 'none'}) + '.' + encode({'sub': 'synthetic-user'}) + '.'
    context = TestContext(1, 1, {'url': 'https://example.invalid/', 'headers': [
        {'name': 'Authorization', 'value': 'Bearer ' + token}]})
    strategy = discover()['jwt_implementation_weakness']
    result = await strategy.execute_test(context, strategy.plan_test(context))
    assert result.status == 'candidate' and not result.confirmed
    assert token not in repr(result) and 'synthetic-user' not in repr(result)


async def test_idor_does_not_infer_access_from_identifier():
    context = TestContext(1, 1, {'url': 'https://example.invalid/api/users/123'})
    strategy = discover()['idor']
    plan = strategy.plan_test(context)
    assert 'two_distinct_identities' in plan.missing_prerequisites
    # Ownership is now a confirmation requirement; it does not prevent bounded probes.
    result = await strategy.execute_test(context, plan)
    assert result.status == 'deferred' and not result.confirmed


def test_context_builder_preserves_scan_boundary(tmp_db, tmp_path, monkeypatch):
    monkeypatch.setenv('QBH_VAULT_KEY', 'synthetic-context-key')
    vault = SecretVault()
    path = tmp_path / 'request.har'
    path.write_text(json.dumps({'log': {'entries': [{'request': {'method': 'GET', 'url': 'https://example.invalid/api/123'},
                                                   'response': {'status': 200, 'content': {'text': '{"id":123}'}}}]}}))
    report = HarImporter(vault).import_file(path)
    request_id = report['entries'][0]['request_id']
    runtime = SimpleNamespace(scan_id=report['scan_id'], vault=vault)
    context = ContextBuilder(runtime).from_import(request_id)
    assert context.request['url'].endswith('/api/123')
    assert context.evidence_refs == [f'imported_request:{request_id}']
    original_hash = context.prerequisite_hash
    context.prerequisites['ownership_evidence'] = True
    assert context.prerequisite_hash != original_hash
    runtime.scan_id = 999
    with pytest.raises(ValueError, match='not_in_scan'):
        ContextBuilder(runtime).from_import(request_id)


async def test_idor_readonly_execution_uses_guardian_and_never_confirms(make_ctx, local_server):
    runtime = make_ctx()
    runtime.auth_state = SimpleNamespace(headers_for=lambda identity, url: {'X-Test-Identity': identity.name})
    context = TestContext(1, None, {'url': local_server['base'] + '/', 'method': 'GET'}, runtime=runtime,
                          auth_states=[SimpleNamespace(name='user_a', session_id='ref-a'),
                                       SimpleNamespace(name='user_b', session_id='ref-b')],
                          prerequisites={'protected_resource': True, 'ownership_evidence': True})
    strategy = discover()['idor']
    result = await strategy.execute_test(context, strategy.plan_test(context))
    assert [o['status'] for o in result.evidence[0]['observations']] == [200, 200]
    assert result.status == 'inconclusive' and not result.confirmed
    from qbh.scope import ScopeError
    context.request['url'] = 'http://outside.invalid/'
    with pytest.raises(ScopeError):
        await strategy.execute_test(context, strategy.plan_test(context))
    await runtime.aclose()
