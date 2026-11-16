import base64
import json

import pytest

from qbh import db
from qbh.brain import store
from qbh.brain.context import ContextBuilder
from qbh.brain.planner import BrainPlanner
from qbh.ingest.har_importer import HarImporter
from qbh.tasks import TaskLedger


@pytest.fixture
def brain(tmp_db, make_ctx, tmp_path, monkeypatch):
    monkeypatch.setenv('QBH_VAULT_KEY', 'synthetic-brain-key')
    runtime = make_ctx()
    runtime.task_ledger = TaskLedger()
    header = base64.urlsafe_b64encode(b'{"alg":"none"}').decode().rstrip('=')
    token = header + '.eyJzdWIiOiJ0ZXN0In0.'
    path = tmp_path / 'brain.har'
    path.write_text(json.dumps({'log': {'entries': [{
        'request': {'method': 'GET', 'url': 'http://127.0.0.1/api/user/123',
                    'headers': [{'name': 'Authorization', 'value': 'Bearer ' + token}]},
        'response': {'status': 200, 'content': {'text': '{"id":123}'}}
    }]}}))
    report = HarImporter(runtime.vault).import_file(path)
    runtime.scan_id = report['scan_id']
    context = ContextBuilder(runtime).from_import(report['entries'][0]['request_id'])
    return runtime, context, token


async def test_all_classes_persist_and_candidate_uses_existing_finding_store(brain):
    runtime, context, token = brain
    planner = BrainPlanner(runtime)
    rows = planner.prepare(context)
    assert len(rows) == 15
    assert all(row['reason'] for row in rows)
    snap = await planner.execute_ready()
    assert snap['executed'] == 1
    rows = store.list_plans(runtime.scan_id)
    jwt = next(r for r in rows if r['vuln_class'] == 'jwt_implementation_weakness')
    assert jwt['status'] == 'candidate' and jwt['finding_id']
    assert db.findings_all(runtime.scan_id)[0]['status'] == 'candidate'
    assert token not in json.dumps(rows)
    assert db.get_db().execute('SELECT result_enc FROM test_plans WHERE id=?', (jwt['id'],)).fetchone()[0]
    planner.prepare(context)
    assert (await planner.execute_ready())['executed'] == 0


async def test_rejection_survives_restart_and_prerequisite_changes(brain):
    runtime, context, _ = brain
    planner = BrainPlanner(runtime)
    row = next(r for r in planner.prepare(context) if r['vuln_class'] == 'jwt_implementation_weakness')
    store.decide(row['id'], runtime.scan_id, approve=False, reason='test_rejection')
    context.prerequisites['new_evidence'] = True
    restarted = BrainPlanner(runtime)
    restarted.prepare(context)
    assert (await restarted.execute_ready())['executed'] == 0
    assert store.get(row['id'], runtime.scan_id)['user_decision'] == 'rejected'
    assert store.get(row['id'], runtime.scan_id)['decision_reason'] == 'test_rejection'


async def test_authorization_rechecked_after_preparation_and_approval(brain):
    runtime, context, _ = brain
    planner = BrainPlanner(runtime)
    row = next(r for r in planner.prepare(context) if r['status'] == 'ready')
    store.decide(row['id'], runtime.scan_id, approve=True, reason='test_approval')
    planner.prepare(context)
    runtime._auth().rules.forbidden.add('jwt')
    await planner.execute_ready()
    assert store.get(row['id'], runtime.scan_id)['status'] == 'skipped'
    assert not db.findings_all(runtime.scan_id)


async def test_budget_preserves_deferred_plans(brain):
    runtime, context, _ = brain
    planner = BrainPlanner(runtime)
    planner.prepare(context)
    assert (await planner.execute_ready(budget=0))['executed'] == 0
    rows = store.list_plans(runtime.scan_id)
    assert len(rows) == 15
    assert any(r['reason'] == 'bounded_scheduling_budget_exhausted' for r in rows)


def test_plan_decision_scan_isolation(brain):
    runtime, context, _ = brain
    row = BrainPlanner(runtime).prepare(context)[0]
    with pytest.raises(ValueError, match='plan_not_in_scan'):
        store.decide(row['id'], runtime.scan_id + 1, approve=True, reason='test')


def test_config_recognizes_plugins_and_reports_unknown_names(load_config):
    cfg = load_config([{'domain': '127.0.0.1', 'in_scope': ['127.0.0.1']}],
                      extra={'program_rules': {'forbidden': ['idor', 'jwt_implementation_weakness', 'nonsense_name']}})
    assert not cfg.program_rules.allows('idor')
    assert not cfg.program_rules.allows('jwt_implementation_weakness')
    assert cfg.program_rules.allows('sqli')
    assert cfg.program_rules.unknown_forbidden == {'nonsense_name'}
    assert any('nonsense_name' in w for w in cfg.warnings)


def test_cli_rejection_is_persistent_and_prints_no_token(brain, capsys):
    from main import main
    runtime, context, token = brain
    rows = BrainPlanner(runtime).prepare(context)
    plan_id = next(r['id'] for r in rows if r['status'] == 'ready')
    args = ['--config', 'config/examples/example_local.yaml', '--test-plan', '--scan-id', str(runtime.scan_id)]
    assert main([*args, '--reject', plan_id, '--reason', 'synthetic_rejection']) == 0
    assert store.get(plan_id, runtime.scan_id)['status'] == 'rejected'
    assert token not in capsys.readouterr().out
    assert main(args) == 0
    assert store.get(plan_id, runtime.scan_id)['status'] == 'rejected'


async def test_real_chain_routes_brain_through_scheduler(brain):
    from qbh.chain import ChainPipeline
    runtime, _, _ = brain
    runtime._auth().rules.forbidden.update({'bypass', 'cve_poc', 'secret_replay'})
    result = await ChainPipeline(runtime).run()
    assert result.data['brain']['scheduler']['executed'] == 1
    assert len(result.data['brain']['plans']) == 15
    assert result.findings == 1
    assert db.findings_all(runtime.scan_id)[0]['status'] == 'candidate'


def test_authorization_enforces_named_tools_and_engine_aliases(load_config):
    from qbh.authorization import from_config, RuleForbidden
    cfg = load_config([{'domain': '127.0.0.1', 'in_scope': ['127.0.0.1']}],
                      extra={'program_rules': {'forbidden': ['jwt_tool', 'nuclei', 'jsanalysis']}})
    auth = from_config(cfg)
    with pytest.raises(RuleForbidden):
        auth.require_command(['python3', '/tmp/jwt_tool.py', 'synthetic-token'])
    with pytest.raises(RuleForbidden):
        auth.require_command(['/usr/bin/nuclei', '-u', 'http://127.0.0.1'])
    assert not auth.allows('js')
    auth.require_command(['ffuf', '-u', 'http://127.0.0.1/FUZZ'])


async def test_egress_blocks_forbidden_tool_before_launch(load_config):
    from qbh.authorization import from_config
    from qbh.egress import EgressController
    cfg = load_config([{'domain': '127.0.0.1', 'in_scope': ['127.0.0.1']}],
                      extra={'program_rules': {'forbidden': ['nuclei']}})
    gate = EgressController(from_config(cfg))
    blocked, _ = await gate.prepare_process(['nuclei', '-u', 'http://127.0.0.1'], [])
    assert blocked.blocked
    assert gate.audit[-1]['reason'] == 'tool_forbidden'


def test_chain_local_engine_denial_is_recorded_without_a_ledger(make_ctx):
    from qbh.chain import ChainPipeline
    runtime = make_ctx()
    runtime._auth().rules.forbidden.update({'api_fuzz', 'param_enum'})
    chain = ChainPipeline(runtime)
    assert chain._begin('schemathesis_fuzz', 'api') is None
    assert chain._begin('hidden_param_detect', 'param') is None
    assert len(chain.skipped) == 2
    assert all('authorization' in reason for reason in chain.skipped)
