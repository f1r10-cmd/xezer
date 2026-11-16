from qbh.brain.js_intelligence import analyze, source_map_sources


def test_ast_routes_permissions_flags_and_services():
    result = analyze("""
        fetch('/api/items');
        axios.post('/api/save', {});
        const route = {path: '/account', permissions: ['read'], featureEnabled: true};
        if (user.role === 'admin') { fetch(dynamicUrl); }
        const internal = 'https://service.invalid/internal';
        //# sourceMappingURL=app.js.map
    """, 'http://127.0.0.1:8123/assets/app.js')
    assert result.parser == 'esprima'
    kinds = {o['kind'] for o in result.observations}
    assert {'endpoint', 'route', 'frontend_permission', 'feature_flag', 'service_reference',
            'source_map', 'dynamic_endpoint'} <= kinds
    assert any(o['value'] == 'http://127.0.0.1:8123/api/items' for o in result.observations)
    assert 'service.invalid' not in repr(result)


def test_unsupported_syntax_keeps_legacy_extraction_with_reason():
    result = analyze("const x = user?.profile; const api = '/api/items';", 'http://127.0.0.1/app.js')
    assert result.parser == 'regex_fallback' and result.limitations
    assert any(o['value'].endswith('/api/items') for o in result.observations)


def test_sourcemap_missing_sources_are_visible():
    rows = source_map_sources('{"version":3,"sources":["one.js","two.js"],"sourcesContent":["fetch(123)"]}')
    assert rows[0]['content'] == 'fetch(123)'
    assert rows[1]['content'] is None and rows[1]['reason'] == 'source_content_unavailable'


def test_persist_correlates_har_keeps_external_reference_and_secrets_encrypted(tmp_db, make_ctx, monkeypatch, tmp_path):
    import json
    from qbh import db
    from qbh.brain.js_intelligence import persist
    from qbh.ingest.har_importer import HarImporter
    monkeypatch.setenv('QBH_VAULT_KEY', 'synthetic-js-vault')
    runtime = make_ctx()
    runtime.scan_id = db.start_scan('js', 'full')
    path = tmp_path / 'js.har'
    path.write_text(json.dumps({'log': {'entries': [{'request': {'url': 'http://127.0.0.1:8123/api/items', 'method': 'GET'},
                                                 'response': {'status': 200}}]}}))
    imported = HarImporter(runtime.vault).import_file(path, runtime.scan_id)
    source = """fetch('/api/items'); fetch('/api/private?token=synthetic-private-value');
                fetch('https://outside.invalid/api/private');"""
    result = analyze(source, 'http://127.0.0.1:8123/app.js')
    assert persist(runtime, 'http://127.0.0.1:8123/app.js', source, result) == 'recorded'
    row = db.get_db().execute('SELECT * FROM js_observations').fetchone()
    observations = json.loads(runtime.vault.decrypt(row['payload_enc']))['observations']
    assert any(imported['entries'][0]['request_id'] in o.get('har_refs', []) for o in observations)
    assert any(o.get('decision') == 'out_of_scope_or_forbidden' for o in observations)
    assert any(o.get('decision') == 'credential_or_parameter_review_required' for o in observations)
    assert 'synthetic-private-value' not in '\n'.join(db.get_db().iterdump())


async def test_engine_reads_inline_sourcemap_without_fetching_external_sources(tmp_db, make_ctx, monkeypatch):
    import base64
    import json
    from qbh import db
    from qbh.engines.jsanalysis import JSAnalysisEngine
    from qbh.results import EngineResult
    monkeypatch.setenv('QBH_VAULT_KEY', 'synthetic-map-vault')
    runtime = make_ctx()
    runtime.scan_id = db.start_scan('maps', 'full')
    host = db.upsert_host('127.0.0.1', scan_id=runtime.scan_id)
    source_map = {'version': 3, 'sources': ['https://outside.invalid/source.js', 'missing.js'],
                  'sourcesContent': ["fetch('/api/from-map')"]}
    inline = base64.b64encode(json.dumps(source_map).encode()).decode()
    code = '//# sourceMappingURL=data:application/json;base64,' + inline
    result = analyze(code, 'http://127.0.0.1/app.js')
    engine = JSAnalysisEngine(runtime)
    async def forbidden(*args, **kwargs):
        raise AssertionError('embedded sources must not be fetched')
    monkeypatch.setattr(runtime.guardian, 'get', forbidden)
    await engine._source_maps(None, {'url': 'http://127.0.0.1/app.js', 'host_id': host,
                                    'subdomain': '127.0.0.1'}, result, EngineResult(stage='js'))
    assert any(o['value'].endswith('/api/from-map') for o in result.observations)
    item = next(o for o in result.observations if o['kind'] == 'source_map')
    assert item['map_status'] == 'analyzed'
    assert item['embedded_sources'][1]['reason'] == 'source_content_unavailable'


async def test_real_js_engine_fetches_scoped_map_and_keeps_external_reference(tmp_db, make_ctx, monkeypatch):
    from aiohttp import web
    from qbh import db
    from qbh.engines.jsanalysis import JSAnalysisEngine
    monkeypatch.setenv('QBH_VAULT_KEY', 'synthetic-js-engine-vault')
    hits = []
    async def script(request):
        hits.append('script')
        return web.Response(text="fetch('/api/live'); const r={path:'/profile'}; "
                                 "const s='https://outside.invalid/internal';\n//# sourceMappingURL=app.js.map",
                            content_type='application/javascript')
    async def mapping(request):
        hits.append('map')
        return web.json_response({'version': 3, 'sources': ['original.js'],
                                  'sourcesContent': ["fetch('/api/from-source-map')"]})
    app = web.Application()
    app.router.add_get('/app.js', script)
    app.router.add_get('/app.js.map', mapping)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 0)
    await site.start()
    runtime = make_ctx()
    try:
        runtime.scan_id = db.start_scan('js-engine', 'full')
        base = f'http://127.0.0.1:{runner.addresses[0][1]}'
        host = db.upsert_host('127.0.0.1', scan_id=runtime.scan_id)
        db.insert_url(host, base + '/app.js', 'fixture', is_js=True, scan_id=runtime.scan_id)
        result = await JSAnalysisEngine(runtime).run()
        assert result.ok and hits == ['script', 'map']
        urls = {r['url'] for r in db.get_db().execute('SELECT url FROM urls WHERE scan_id=?', (runtime.scan_id,))}
        assert {base + '/api/live', base + '/profile', base + '/api/from-source-map'} <= urls
        assert not any('outside.invalid' in url for url in urls)
        assert db.get_db().execute('SELECT count(*) FROM js_observations').fetchone()[0] == 1
    finally:
        await runtime.aclose()
        await runner.cleanup()
