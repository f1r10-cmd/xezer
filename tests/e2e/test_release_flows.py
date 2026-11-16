"""Product flows against synthetic loopback targets; no external scan traffic."""
import json
import sys
import subprocess
from pathlib import Path

from qbh import db
from main import run, build_parser
from tests.test_auth_state import spec, policy
from tests.test_durable_recovery import TestCrashRecovery as _Crash
from tests.test_smoke import TestFullPipelineSmoke as _Smoke


class TestCrashAndFailure:
    test_e2e2_real_crash_resume = _Crash.test_kill_then_resume_recovers_state
    test_e2e9_partial_full_pipeline_and_report = _Smoke.test_full_pipeline_records_scan_and_writes_report


async def test_e2e3_4_5_7_offline_import_to_approved_auth_tests(tmp_db, write_config, idor_app, monkeypatch, tmp_path, capsys):
    from qbh.antiblock.guardian import Guardian
    monkeypatch.setenv('QBH_VAULT_KEY', 'synthetic-release-vault')
    for suffix, name, password in [('A', 'alice', 'synthetic-a-password'), ('B', 'bob', 'synthetic-b-password')]:
        monkeypatch.setenv('TARGET_USER_' + suffix, name)
        monkeypatch.setenv('TARGET_USER_' + suffix + '_PASS', password)
    cfg = write_config([{'domain': '127.0.0.1', 'in_scope': ['127.0.0.1']}], extra={
        'auth_contexts': [spec(idor_app.base), spec(idor_app.base, 'B')],
        'auth_resource_policies': policy(idor_app.base)})
    path = tmp_path / 'traffic.har'
    # Capture actual loopback responses into HAR, then verify the import phase
    # emits no additional target traffic and retains graph provenance.
    import aiohttp
    entries = []
    async with aiohttp.ClientSession() as client:
        for kind in ('vulnerable', 'secure'):
            url = idor_app.base + '/' + kind + '/7'
            async with client.get(url, cookies={'session': 'alice'}) as response:
                entries.append({'request': {'method': 'GET', 'url': url,
                    'cookies': [{'name': 'session', 'value': 'alice'}]},
                    'response': {'status': response.status,
                        'content': {'mimeType': 'application/json', 'text': await response.text()}}})
    path.write_text(json.dumps({'log': {'entries': entries}}))
    idor_app.hits.clear()
    async def no_request(*args, **kwargs):
        raise AssertionError('offline import emitted target traffic')
    with monkeypatch.context() as offline:
        offline.setattr(Guardian, 'request', no_request)
        assert await run(build_parser().parse_args(['--config', cfg, '--import-har', str(path)])) == 0
    imported = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    sid = imported['scan_id']
    assert imported['imported'] == 2 and not idor_app.hits
    assert imported['feedback_plans'] == 30
    from qbh.ingest.request_graph import RequestGraph
    edges = RequestGraph(sid).edges()
    assert edges and all(e['provenance'] and 0 <= e['confidence'] <= 1 for e in edges)
    assert await run(build_parser().parse_args(['--config', cfg, '--test-plan', '--scan-id', str(sid), '--approve'])) == 0
    plans = db.get_db().execute('SELECT vuln_class,status,reason FROM test_plans WHERE scan_id=?', (sid,)).fetchall()
    assert len({r['vuln_class'] for r in plans}) == 15
    assert all(r['reason'] for r in plans)
    assert [r['status'] for r in plans if r['vuln_class'] == 'idor'].count('confirmed') == 1
    findings = db.findings_all(sid)
    assert len(findings) == 1 and findings[0]['status'] == 'confirmed'
    assert 'synthetic-a-password' not in capsys.readouterr().out
    assert db.get_db().execute('SELECT count(*) FROM plan_reconsiderations').fetchone()[0] > 0


async def test_e2e1_stored_benchmark_coverage_is_preserved():
    from tests.benchmarks.run_baseline import _amain, compare, BASELINE_PATH
    result = await _amain(write=False)
    assert not compare(json.loads(BASELINE_PATH.read_text()), result)['regressions']


def test_e2e6_diff_preserves_semantics():
    from qbh.brain.diff_engine import DiffEngine, ResponseSnapshot
    result = DiffEngine().compare(ResponseSnapshot(200, body='{"owner_id":"alice","timestamp":1}'),
                                  ResponseSnapshot(200, body='{"owner_id":"bob","timestamp":2}'))
    assert result.total_differences >= 2
    assert result.possible_interpretations and result.false_positive_considerations
    assert any(e.kind == 'ownership' for e in result.relevant_evidence)


def test_e2e8_harmless_simulation_respects_roe(load_config):
    from qbh.authorization import from_config, RuleForbidden
    import pytest
    cfg = load_config([{'domain': '127.0.0.1', 'in_scope': ['127.0.0.1']}])
    auth = from_config(cfg)
    # This records permission only; no destructive target operation exists here.
    auth.authorize_request('POST', 'http://127.0.0.1/synthetic-fixture')
    with pytest.raises(RuleForbidden):
        auth.authorize_request('POST', 'http://127.0.0.1/synthetic-fixture', destructive=True)
    auth.rules.forbidden.add('state_changing')
    with pytest.raises(RuleForbidden):
        auth.authorize_request('POST', 'http://127.0.0.1/synthetic-fixture')


def test_e2e10_real_install_detection_reports_missing_honestly(tmp_path):
    root = Path(__file__).resolve().parents[2]
    proc = subprocess.run([sys.executable, str(root / 'main.py'), '--config',
                           str(root / 'config/examples/example_local.yaml'), '--mode', 'install', '--dry-run'],
                          cwd=tmp_path, capture_output=True, text=True, timeout=90)
    assert proc.returncode in (0, 1)
    assert 'subfinder' in proc.stdout and 'nuclei' in proc.stdout
    # The separately recorded isolated --auto-install run establishes installation,
    # this offline dry-run only establishes real detection/reporting.
