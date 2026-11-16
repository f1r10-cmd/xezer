import json
from qbh import db
from main import main


def test_findings_and_compare_are_offline_and_scan_scoped(tmp_db, capsys):
    a = db.start_scan('a', 'full')
    b = db.start_scan('b', 'full')
    for sid in (a, b):
        host = db.upsert_host('127.0.0.1', scan_id=sid)
        db.insert_finding(host, 'sqli', 'high', 'synthetic finding', evidence='token=synthetic-secret',
                          scan_id=sid)
    assert main(['--findings', '--scan-id', str(a), '--severity', 'high']) == 0
    output = capsys.readouterr().out
    assert 'synthetic-secret' not in output
    assert len(json.loads(output.strip().splitlines()[-1])) == 1
    assert main(['--compare-scans', str(a), str(b)]) == 0
    result = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert result['unchanged'] == 1 and result['added'] == result['removed'] == 0
    assert main(['--findings', '--scan-id', '999']) != 0
