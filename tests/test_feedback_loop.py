import pytest
from qbh import db
from qbh.brain.context import ContextBuilder
from qbh.brain.planner import BrainPlanner
from qbh.brain import store


@pytest.fixture
def setup_feedback(tmp_db, make_ctx, monkeypatch):
    monkeypatch.setenv('QBH_VAULT_KEY', 'synthetic-feedback-key')
    runtime = make_ctx()
    runtime.scan_id = db.start_scan('feedback', 'full')
    context = ContextBuilder(runtime).from_request({'url': 'http://127.0.0.1/object/7', 'method': 'GET'})
    return runtime, context


def test_changed_prerequisites_bounded_across_reconstruction(setup_feedback):
    runtime, context = setup_feedback
    runtime.cfg.max_reconsideration_rounds = 1
    first = BrainPlanner(runtime).prepare(context)
    plan_id = next(r['id'] for r in first if r['vuln_class'] == 'idor')
    context.prerequisites['ownership_evidence'] = True
    BrainPlanner(runtime).prepare(context)
    context.prerequisites['protected_resource'] = True
    second = BrainPlanner(runtime).prepare(context)
    assert next(r for r in second if r['id'] == plan_id)['reason'] == 'max_reconsideration_rounds_reached'
    # Same blocked version cannot evade the cap on the next pass.
    third = BrainPlanner(runtime).prepare(context)
    assert next(r for r in third if r['id'] == plan_id)['reason'] == 'max_reconsideration_rounds_reached'
    rows = db.get_db().execute('SELECT round,permitted FROM plan_reconsiderations WHERE plan_id=? ORDER BY id', (plan_id,)).fetchall()
    assert [tuple(r) for r in rows] == [(1, 1), (2, 0)]


def test_unchanged_failed_test_and_user_rejection_preserved(setup_feedback):
    runtime, context = setup_feedback
    row = BrainPlanner(runtime).prepare(context)[0]
    store.transition(row['id'], runtime.scan_id, 'failed', 'synthetic_failure')
    BrainPlanner(runtime).prepare(context)
    assert store.get(row['id'], runtime.scan_id)['status'] == 'failed'
    assert db.get_db().execute('SELECT count(*) FROM plan_reconsiderations').fetchone()[0] == 0
    store.decide(row['id'], runtime.scan_id, approve=False, reason='user_choice')
    context.prerequisites['new_evidence'] = True
    BrainPlanner(runtime).prepare(context)
    assert store.get(row['id'], runtime.scan_id)['status'] == 'rejected'


def test_new_evidence_never_overrides_fresh_authorization(setup_feedback):
    runtime, context = setup_feedback
    rows = BrainPlanner(runtime).prepare(context)
    plan_id = next(r['id'] for r in rows if r['vuln_class'] == 'idor')
    runtime._auth().rules.forbidden.add('idor')
    context.prerequisites['new_evidence'] = True
    BrainPlanner(runtime).prepare(context)
    assert store.get(plan_id, runtime.scan_id)['status'] == 'skipped'
    assert store.get(plan_id, runtime.scan_id)['reason'].startswith('authorization:')


@pytest.mark.parametrize('value', [-1, True, 101, '3'])
def test_invalid_reconsideration_limit(load_config, value):
    from qbh.config import ConfigError
    with pytest.raises(ConfigError):
        load_config([{'domain': '127.0.0.1', 'in_scope': ['127.0.0.1']}],
                    extra={'max_reconsideration_rounds': value})


def test_reconsideration_event_persists_without_runtime_ledger(setup_feedback):
    runtime, context = setup_feedback
    BrainPlanner(runtime).prepare(context)
    context.prerequisites['new_evidence'] = True
    BrainPlanner(runtime).prepare(context)
    events = db.load_event_state(runtime.scan_id)
    assert events
    count = len(events)
    BrainPlanner(runtime).prepare(context)
    assert len(db.load_event_state(runtime.scan_id)) == count


async def test_har_cli_feedback_is_offline(setup_feedback, tmp_path, monkeypatch):
    import json
    from main import run, build_parser
    runtime, _ = setup_feedback
    path = tmp_path / 'offline.har'
    path.write_text(json.dumps({'log': {'entries': [
        {'request': {'method': 'GET', 'url': 'http://127.0.0.1/private/7'},
         'response': {'status': 200, 'content': {'text': '{"id":7}'}}}]}}))
    from qbh.antiblock.guardian import Guardian
    async def deny(*args, **kwargs):
        raise AssertionError('HAR import must never access network')
    monkeypatch.setattr(Guardian, 'request', deny)
    args = build_parser().parse_args(['--config', runtime.cfg.path, '--import-har', str(path),
                                      '--scan-id', str(runtime.scan_id)])
    assert await run(args) == 0
    assert len(store.list_plans(runtime.scan_id)) == 15


def test_unrelated_finding_does_not_change_prerequisites(setup_feedback):
    runtime, context = setup_feedback
    host = db.upsert_host('127.0.0.1', scan_id=runtime.scan_id)
    original = context.prerequisite_hash
    db.insert_finding(host, 'sqli', 'low', 'unrelated',
                      evidence='http://127.0.0.1/other/8', scan_id=runtime.scan_id)
    fresh = ContextBuilder(runtime).from_request(context.request)
    # Fingerprint now exists; compare two contexts with the same host record.
    baseline = fresh.prerequisite_hash
    db.insert_finding(host, 'xss', 'low', 'also unrelated',
                      evidence='http://127.0.0.1/another/9', scan_id=runtime.scan_id)
    assert ContextBuilder(runtime).from_request(context.request).prerequisite_hash == baseline
    db.insert_finding(host, 'sqli', 'low', 'related',
                      evidence=context.request['url'], scan_id=runtime.scan_id)
    assert ContextBuilder(runtime).from_request(context.request).prerequisite_hash != baseline
    assert original


def test_evidence_event_dedup_survives_new_runtime_ledger(setup_feedback):
    from qbh.adaptive import note_evidence
    runtime, _ = setup_feedback
    assert note_evidence(runtime, 'har_import_completed', 'import:synthetic').accept
    runtime.event_ledger = None
    assert not note_evidence(runtime, 'har_import_completed', 'import:synthetic').accept
