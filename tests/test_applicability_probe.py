from qbh import db
from qbh.urlintel import probe_applicability


async def test_all_categories_are_probed_and_budgeted_rows_preserved(tmp_db, make_ctx, local_server):
    runtime = make_ctx()
    runtime.scan_id = db.start_scan('probe', 'full')
    runtime.cfg.chain.max_tasks = 2
    host = db.upsert_host('127.0.0.1', scan_id=runtime.scan_id)
    for path in ('/style.css', '/logo.png', '/unknown'):
        db.insert_url(host, local_server['base'] + path, 'test', scan_id=runtime.scan_id)
    result = await probe_applicability(runtime)
    assert result.data['admitted'] == 2 and len(result.data['deferred_url_ids']) == 1
    rows = db.load_task_state(runtime.scan_id)
    assert len(rows) == 2
    assert all('bounded_applicability_probe_completed' in row['result_data'] for row in rows)
    again = await probe_applicability(runtime)
    assert again.data['admitted'] == 1
    assert len(db.load_task_state(runtime.scan_id)) == 3
    assert (await probe_applicability(runtime)).data['admitted'] == 0
