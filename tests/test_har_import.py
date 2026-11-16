import json
import socket

import pytest

from qbh.ingest.har_importer import HarImporter, list_imported
from qbh.ingest.request_graph import RequestGraph
from qbh.vault import SecretVault


@pytest.fixture
def vault(monkeypatch):
    monkeypatch.setenv('QBH_VAULT_KEY', 'synthetic-har-test-key')
    return SecretVault()


def entry(url='https://outside.invalid/api/1', secret='synthetic-cookie'):
    return {'request': {'method': 'POST', 'url': url,
                        'headers': [{'name': 'Cookie', 'value': secret}],
                        'postData': {'mimeType': 'application/json', 'text': '{"password":"short"}'}},
            'response': {'status': 200, 'headers': [], 'content': {'mimeType': 'application/json', 'text': '{"id":1}'}},
            'time': 10, 'timings': {'wait': 8}}


def write_har(tmp_path, entries):
    path = tmp_path / 'sample.har'
    path.write_text(json.dumps({'log': {'entries': entries}}))
    return path


def test_offline_dedup_and_encryption(tmp_db, tmp_path, vault, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('Importer attempted network access')
    monkeypatch.setattr(socket, 'socket', forbidden)
    importer = HarImporter(vault)
    second = entry()
    second['response']['content']['text'] = '{"id":2}'
    report = importer.import_file(write_har(tmp_path, [entry(), second, {}, entry('/invalid')]))
    assert [report[k] for k in ('imported', 'duplicate', 'invalid')] == [1, 1, 2]
    rid = report['entries'][0]['request_id']
    req, resp = importer.evidence(rid)
    assert req['body']['fields']['password'] == 'short'
    assert resp['content']['text'] == '{"id":1}'
    raw = str([tuple(r) for r in tmp_db.get_db().execute('SELECT * FROM imported_requests')])
    assert 'synthetic-cookie' not in raw and 'short' not in raw
    assert 'synthetic-cookie' not in json.dumps(list_imported())
    occurrences = tmp_db.get_db().execute('SELECT evidence_enc FROM import_entries WHERE status="duplicate"').fetchone()
    assert json.loads(vault.decrypt(occurrences[0]))['response']['content']['text'] == '{"id":2}'


def test_vault_unavailable_retryable(tmp_db, tmp_path):
    path = write_har(tmp_path, [entry()])
    report = HarImporter(SecretVault(enabled=False)).import_file(path)
    assert report['blocked'] == 1
    assert not list_imported()
    assert tmp_db.get_db().execute('SELECT reason FROM import_entries').fetchone()[0] == 'vault_unavailable_retryable'


def test_graph_explains_and_separates_scans(tmp_db, tmp_path, vault):
    report = HarImporter(vault).import_file(write_har(tmp_path, [entry(), entry('https://outside.invalid/api/2'), entry('https://other.invalid/api/3')]))
    graph = RequestGraph(report['scan_id'], vault)
    edges = graph.infer()
    assert len(edges) == 2
    assert all(e['provenance'] and 0 <= e['confidence'] <= 1 for e in edges)
    assert len(graph.get_auth_context_chains()) == 1
    ids = [e['request_id'] for e in report['entries']]
    assert [n.request_id for n in graph.get_related(ids[0])] == [ids[1]]
    with pytest.raises(ValueError):
        graph.add_inferred_edge(ids[0], ids[2], 'unknown', float('nan'), 'invalid')
    with pytest.raises(ValueError):
        RequestGraph(999, vault).add_request(ids[0])


def test_identity_preserves_distinct_credentials(tmp_db, tmp_path, vault):
    report = HarImporter(vault).import_file(write_har(tmp_path, [entry(secret='user-a'), entry(secret='user-b')]))
    assert report['imported'] == 2


def test_multipart_and_binary_reference(tmp_db, tmp_path, vault):
    first = entry()
    first['request']['postData'] = {'mimeType': 'multipart/form-data; boundary=x', 'text': '--x\r\nContent-Disposition: form-data; name="name"\r\n\r\nAlice\r\n--x--\r\n'}
    first['response']['content'] = {'mimeType': 'image/png', 'encoding': 'base64', 'text': 'aGVsbG8='}
    importer = HarImporter(vault)
    report = importer.import_file(write_har(tmp_path, [first]))
    req, resp = importer.evidence(report['entries'][0]['request_id'])
    assert req['body']['fields'][0]['value'] == 'Alice'
    assert resp['content']['reference_only'] and 'text' not in resp['content']


def test_cli_import_and_views(tmp_db, tmp_path, vault, capsys):
    from main import main
    path = write_har(tmp_path, [entry()])
    assert main(['--config', 'config/examples/example_local.yaml', '--import-har', str(path)]) == 0
    assert 'synthetic-cookie' not in capsys.readouterr().out
    assert main(['--list-imported']) == 0
    assert 'request_body' not in capsys.readouterr().out
    assert main(['--request-graph']) == 0
    assert 'edges' in capsys.readouterr().out


def test_migration_preserves_existing_scan(tmp_db):
    sid = tmp_db.start_scan('existing', 'full')
    conn = tmp_db.get_db()
    with conn:
        conn.execute("UPDATE schema_meta SET value='7' WHERE key='schema_version'")
    tmp_db.init_db()
    assert tmp_db.get_scan(sid)['program'] == 'existing'
    assert conn.execute('PRAGMA foreign_key_check').fetchall() == []
    assert conn.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'


def test_malformed_payload_preserved_and_base64_text_decoded(tmp_db, tmp_path, vault):
    row = entry()
    row['request']['postData']['text'] = '{broken'
    row['response']['content'] = {'mimeType': 'text/plain', 'encoding': 'base64', 'text': 'aGVsbG8='}
    importer = HarImporter(vault)
    report = importer.import_file(write_har(tmp_path, [row]))
    req, resp = importer.evidence(report['entries'][0]['request_id'])
    assert req['body']['text'] == '{broken'
    assert req['body']['parse_error'] == 'invalid_json_body'
    assert resp['content']['text'] == 'hello'
