from datetime import datetime, timezone, timedelta
import json
from types import SimpleNamespace

import pytest
import pytest_asyncio

from qbh import db
from qbh.brain.auth_config import validate_contexts
from qbh.brain.auth_state import AuthStateMachine
from qbh.ingest.har_importer import HarImporter


@pytest_asyncio.fixture
async def auth_app():
    from aiohttp import web
    state = {'logins': 0, 'verified': 0}
    users = {'alice': 'synthetic-a-password', 'bob': 'synthetic-b-password'}

    async def login(request):
        state['logins'] += 1
        data = await request.json()
        if users.get(data.get('username')) != data.get('password'):
            return web.json_response({'error': 'bad credentials'}, status=401)
        result = web.json_response({'user': {'id': data['username']}})
        result.set_cookie('session', data['username'] + '-synthetic-session', path='/')
        result.set_cookie('extra', 'synthetic-extra-cookie', path='/private')
        return result

    async def identity(request):
        state['verified'] += 1
        cookie = request.cookies.get('session', '')
        name = cookie.removesuffix('-synthetic-session')
        if name not in users:
            return web.json_response({'error': 'unauthorized'}, status=401)
        return web.json_response({'user': {'id': name}})

    async def public_identity(request):
        return web.json_response({'user': {'id': 'alice'}})

    app = web.Application()
    app.router.add_post('/login', login)
    app.router.add_get('/me', identity)
    app.router.add_get('/public-me', public_identity)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 0)
    await site.start()
    try:
        yield SimpleNamespace(base=f'http://127.0.0.1:{runner.addresses[0][1]}', state=state)
    finally:
        await runner.cleanup()


@pytest.fixture
def auth_runtime(tmp_db, make_ctx, monkeypatch):
    monkeypatch.setenv('QBH_VAULT_KEY', 'synthetic-auth-vault-key')
    monkeypatch.setenv('TARGET_USER_A', 'alice')
    monkeypatch.setenv('TARGET_USER_A_PASS', 'synthetic-a-password')
    monkeypatch.setenv('TARGET_USER_B', 'bob')
    monkeypatch.setenv('TARGET_USER_B_PASS', 'synthetic-b-password')
    runtime = make_ctx()
    runtime.scan_id = db.start_scan('auth-fixture', 'full')
    return runtime


def spec(base, suffix='A'):
    return {'name': 'user_' + suffix.lower(), 'role': 'user', 'login_url': base + '/login',
            'login_method': 'POST', 'verify_url': base + '/me',
            'login_fields': {'username_env': 'TARGET_USER_' + suffix,
                             'password_env': 'TARGET_USER_' + suffix + '_PASS'}}


async def test_two_identities_encrypted_isolated_and_reloadable(auth_runtime, auth_app):
    state = AuthStateMachine(auth_runtime)
    a = state.register_context('user_a', 'user', spec(auth_app.base))
    b = state.register_context('user_b', 'user', spec(auth_app.base, 'B'))
    assert not state.is_valid(a)
    assert await state.authenticate(a)
    assert await state.authenticate(b)
    assert state.subject(a) == 'alice' and state.subject(b) == 'bob'
    assert a.session_id != b.session_id and state.is_valid(a) and state.is_valid(b)
    assert 'alice-synthetic-session' in state.headers_for(a, auth_app.base + '/')['Cookie']
    assert 'bob-synthetic-session' in state.headers_for(b, auth_app.base + '/')['Cookie']
    assert 'extra=' not in state.headers_for(a, auth_app.base + '/private-other')['Cookie']
    assert 'extra=' in state.headers_for(a, auth_app.base + '/private/resource')['Cookie']
    assert 'synthetic-session' not in repr(a)
    dump = '\n'.join(db.get_db().iterdump())
    assert 'synthetic-a-password' not in dump and 'alice-synthetic-session' not in dump
    reloaded = AuthStateMachine(auth_runtime)
    restored = reloaded.register_context('user_a', 'user', spec(auth_app.base))
    assert restored.session_id == a.session_id
    assert reloaded.is_valid(restored) and reloaded.subject(restored) == 'alice'
    assert auth_app.state['logins'] == 2


async def test_expiry_origin_and_mutated_context_cannot_export_credentials(auth_runtime, auth_app):
    state = AuthStateMachine(auth_runtime)
    a = state.register_context('user_a', 'user', spec(auth_app.base))
    assert await state.authenticate(a)
    alternate = 'http://127.0.0.1:1/private'
    with pytest.raises(ValueError):
        state.headers_for(a, alternate)
    a.origin = 'http://127.0.0.1:1'
    with pytest.raises(ValueError, match='origin_mismatch'):
        state.headers_for(a, alternate)
    a.valid_until = datetime.now(timezone.utc) - timedelta(seconds=1)
    assert not state.is_valid(a)


async def test_missing_vault_or_credentials_is_recorded_without_network(auth_runtime, auth_app, monkeypatch):
    from qbh.vault import SecretVault
    auth_runtime._vault = SecretVault(enabled=False)
    state = AuthStateMachine(auth_runtime)
    a = state.register_context('user_a', 'user', spec(auth_app.base))
    assert not await state.authenticate(a)
    assert a.status == 'blocked' and auth_app.state['logins'] == 0
    auth_runtime._vault = SecretVault()
    monkeypatch.delenv('TARGET_USER_A_PASS')
    assert not await state.authenticate(a)
    assert auth_app.state['logins'] == 0
    assert db.get_db().execute('SELECT count(*) FROM auth_context_events').fetchone()[0] == 3


async def test_public_identity_is_not_verified(auth_runtime, auth_app):
    source = {**spec(auth_app.base), 'verify_url': auth_app.base + '/public-me'}
    state = AuthStateMachine(auth_runtime)
    a = state.register_context('user_a', 'user', source)
    assert not await state.authenticate(a)
    assert not a.identity_verified and not state.is_valid(a)


async def test_login_without_identity_proof_is_not_verified(auth_runtime, auth_app):
    source = spec(auth_app.base)
    source.pop('verify_url')
    state = AuthStateMachine(auth_runtime)
    a = state.register_context('user_a', 'user', source)
    assert await state.authenticate(a)
    assert state.is_valid(a) and not a.identity_verified and state.subject(a) is None


async def test_scope_and_authentication_roe_are_rechecked(auth_runtime, auth_app):
    state = AuthStateMachine(auth_runtime)
    a = state.register_context('user_a', 'user', spec(auth_app.base))
    auth_runtime._auth().rules.forbidden.add('authentication')
    assert not await state.authenticate(a)
    assert auth_app.state['logins'] == 0


async def test_compatible_requests_do_not_cross_origins_or_scans(auth_runtime, auth_app, tmp_path):
    path = tmp_path / 'requests.har'
    path.write_text(json.dumps({'log': {'entries': [
        {'request': {'method': 'GET', 'url': url}, 'response': {'status': 200}}
        for url in (auth_app.base + '/private/1', 'http://127.0.0.1:1/private/1')
    ]}}))
    HarImporter(auth_runtime.vault).import_file(path, auth_runtime.scan_id)
    state = AuthStateMachine(auth_runtime)
    a = state.register_context('user_a', 'user', spec(auth_app.base))
    assert await state.authenticate(a)
    compatible = state.get_compatible_requests(a)
    assert len(compatible) == 1
    state.invalidate(a)
    assert state.get_compatible_requests(a) == []


@pytest.mark.parametrize('change', [
    {'login_fields': {'password': 'inline-secret'}},
    {'login_fields': {'password_env': 'invalid env name'}},
    {'login_url': 'https://user:password@example.invalid/login'},
    {'verify_url': 'https://other.invalid/me'},
    {'session_ttl_seconds': True},
    {'login_method': 'DELETE'},
    {'unknown_option': True},
])
def test_invalid_or_inline_credentials_rejected(change):
    with pytest.raises(ValueError):
        validate_contexts([{**spec('http://127.0.0.1'), **change}])


def test_config_accepts_auth_contexts_without_loading_credentials(load_config):
    cfg = load_config([{'domain': '127.0.0.1', 'in_scope': ['127.0.0.1']}],
                      extra={'auth_contexts': [spec('http://127.0.0.1')]})
    assert cfg.auth_contexts[0]['name'] == 'user_a'
    assert not any('auth_contexts' in warning for warning in cfg.warnings)


async def test_changed_credential_source_invalidates_reuse_but_preserves_history(auth_runtime, auth_app, monkeypatch):
    state = AuthStateMachine(auth_runtime)
    a = state.register_context('user_a', 'user', spec(auth_app.base))
    assert await state.authenticate(a)
    original = a.session_id
    monkeypatch.setenv('TARGET_USER_A', 'bob')
    monkeypatch.setenv('TARGET_USER_A_PASS', 'synthetic-b-password')
    reloaded = AuthStateMachine(auth_runtime)
    updated = reloaded.register_context('user_a', 'user', spec(auth_app.base))
    assert not reloaded.is_valid(updated)
    assert await reloaded.authenticate(updated)
    assert updated.session_id != original and reloaded.subject(updated) == 'bob'
    assert db.get_db().execute('SELECT count(*) FROM auth_sessions').fetchone()[0] == 2


async def test_existing_vault_credential_references_are_scan_and_host_bound(auth_runtime, auth_app):
    conn = db.get_db()
    host_id = db.upsert_host('127.0.0.1', scan_id=auth_runtime.scan_id)
    refs = []
    with conn:
        for value in ('alice', 'synthetic-a-password'):
            refs.append(conn.execute('INSERT INTO secrets(host_id,kind,value_preview,value_enc) VALUES(?,?,?,?)',
                                     (host_id, 'credential', '<redacted>', auth_runtime.vault.encrypt(value))).lastrowid)
    source = {**spec(auth_app.base), 'login_fields': {'username_vault_ref': refs[0], 'password_vault_ref': refs[1]}}
    state = AuthStateMachine(auth_runtime)
    a = state.register_context('user_a', 'user', source)
    assert await state.authenticate(a)
    assert state.subject(a) == 'alice'
    auth_runtime.scan_id = db.start_scan('another', 'full')
    other = AuthStateMachine(auth_runtime)
    b = other.register_context('user_b', 'user', source)
    assert not await other.authenticate(b)
    assert auth_app.state['logins'] == 1


async def test_forbidden_auth_use_and_forged_context_do_not_send_requests(auth_runtime, auth_app):
    from qbh.authorization import RuleForbidden
    from qbh.brain.auth_state import AuthContext
    state = AuthStateMachine(auth_runtime)
    a = state.register_context('user_a', 'user', spec(auth_app.base))
    assert await state.authenticate(a)
    auth_runtime._auth().rules.forbidden.add('authentication')
    with pytest.raises(RuleForbidden):
        state.headers_for(a, auth_app.base + '/private')
    with pytest.raises(ValueError, match='unregistered'):
        await state.authenticate(AuthContext('user_a', 'user'))
    assert auth_app.state['logins'] == 1


@pytest_asyncio.fixture
async def idor_app(auth_app):
    # Separate loopback origin deliberately hosts its own login and identity proof.
    from aiohttp import web
    hits = []

    async def login(request):
        data = await request.json()
        if (data.get('username'), data.get('password')) not in {
                ('alice', 'synthetic-a-password'), ('bob', 'synthetic-b-password')}:
            return web.Response(status=401)
        response = web.json_response({'user': {'id': data['username']}})
        response.set_cookie('session', data['username'])
        return response

    async def me(request):
        name = request.cookies.get('session')
        return web.json_response({'user': {'id': name}}) if name in {'alice', 'bob'} else web.Response(status=401)

    async def resource(request):
        name = request.cookies.get('session')
        mode = request.match_info['mode']
        hits.append((mode, name))
        if mode != 'public' and name not in {'alice', 'bob'}:
            return web.Response(status=401)
        if mode == 'secure' and name != 'alice':
            return web.Response(status=403)
        return web.json_response({'id': 7, 'owner_id': 'alice', 'private_data': 'synthetic-private-object'})

    app = web.Application()
    app.router.add_post('/login', login)
    app.router.add_get('/me', me)
    app.router.add_get('/{mode}/7', resource)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 0)
    await site.start()
    try:
        yield SimpleNamespace(base=f'http://127.0.0.1:{runner.addresses[0][1]}', hits=hits)
    finally:
        await runner.cleanup()


def policy(base):
    from qbh.brain.resource_policy import validate_policies
    return validate_policies([{'id': 'private-objects', 'origin': base, 'path_pattern': '/*/7',
        'owner_field': 'owner_id', 'object_id_field': 'id', 'protected_fields': ['private_data'],
        'roles': ['user'], 'access_policy': 'owner_only'}])


@pytest.mark.parametrize('mode,expected', [('vulnerable', 'confirmed'), ('secure', 'inconclusive'),
                                         ('public', 'inconclusive')])
async def test_idor_full_planner_proof_and_negative_controls(auth_runtime, idor_app, mode, expected):
    from qbh.brain.planner import BrainPlanner
    from qbh.brain import store
    auth_runtime.cfg.auth_contexts = validate_contexts([spec(idor_app.base), spec(idor_app.base, 'B')])
    auth_runtime.cfg.auth_resource_policies = policy(idor_app.base)
    host = db.upsert_host('127.0.0.1', scan_id=auth_runtime.scan_id)
    db.insert_url(host, idor_app.base + '/' + mode + '/7', 'test', scan_id=auth_runtime.scan_id)
    planner = BrainPlanner(auth_runtime)
    # A plan view must not trigger login or object access.
    planner.prepare_scan()
    assert auth_runtime.auth_state is None and not idor_app.hits
    await planner.run()
    row = next(r for r in store.list_plans(auth_runtime.scan_id) if r['vuln_class'] == 'idor')
    assert row['status'] == expected
    stored = store.get(row['id'], auth_runtime.scan_id)
    result = json.loads(auth_runtime.vault.decrypt(stored['result_enc']))
    assert result['confirmed'] == (expected == 'confirmed')
    findings = db.findings_all(auth_runtime.scan_id)
    assert len(findings) == (1 if expected == 'confirmed' else 0)
    if findings:
        assert findings[0]['status'] == 'confirmed'
        assert len(idor_app.hits) == 5
    assert 'synthetic-private-object' not in '\n'.join(db.get_db().iterdump())


async def test_unknown_ownership_still_probes_without_confirmation(auth_runtime, idor_app):
    from qbh.brain.context import ContextBuilder
    from qbh.brain.strategies.idor import Strategy
    auth_runtime.cfg.auth_contexts = validate_contexts([spec(idor_app.base), spec(idor_app.base, 'B')])
    await auth_runtime.initialize_auth()
    context = ContextBuilder(auth_runtime, auth_states=auth_runtime.auth_state.contexts.values()).from_request(
        {'url': idor_app.base + '/vulnerable/7', 'method': 'GET'})
    strategy = Strategy()
    result = await strategy.execute_test(context, strategy.plan_test(context))
    assert len(idor_app.hits) == 2
    assert result.status == 'inconclusive' and not result.confirmed
    assert 'synthetic-private-object' not in repr(result)


@pytest.mark.parametrize('scenario', ['same_subject', 'overlapping_policy', 'role_mismatch', 'expired'])
async def test_idor_confirmation_requires_unambiguous_valid_distinct_actors(auth_runtime, idor_app, monkeypatch, scenario):
    from qbh.brain.context import ContextBuilder
    from qbh.brain.strategies.idor import Strategy
    if scenario == 'same_subject':
        monkeypatch.setenv('TARGET_USER_B', 'alice')
        monkeypatch.setenv('TARGET_USER_B_PASS', 'synthetic-a-password')
    auth_runtime.cfg.auth_contexts = validate_contexts([spec(idor_app.base), spec(idor_app.base, 'B')])
    if scenario == 'role_mismatch':
        auth_runtime.cfg.auth_contexts[1]['role'] = 'admin'
    auth_runtime.cfg.auth_resource_policies = policy(idor_app.base)
    if scenario == 'overlapping_policy':
        auth_runtime.cfg.auth_resource_policies += [{**auth_runtime.cfg.auth_resource_policies[0], 'id': 'overlap'}]
    await auth_runtime.initialize_auth()
    if scenario == 'expired':
        auth_runtime.auth_state.invalidate(auth_runtime.auth_state.contexts['user_b'], 'expired')
    context = ContextBuilder(auth_runtime, auth_states=auth_runtime.auth_state.contexts.values()).from_request(
        {'url': idor_app.base + '/vulnerable/7', 'method': 'GET'})
    strategy = Strategy()
    result = await strategy.execute_test(context, strategy.plan_test(context))
    assert not result.confirmed and result.status in {'deferred', 'inconclusive'}


def test_confirmation_flag_alone_is_insufficient():
    from qbh.brain.strategies.idor import has_confirmation
    from qbh.brain.strategy import TestResult
    assert not has_confirmation(TestResult('confirmed', 'http_200', confirmed=True))


async def test_plan_result_history_preserves_encrypted_evidence(auth_runtime, idor_app):
    from qbh.brain import store
    from qbh.brain.context import ContextBuilder
    from qbh.brain.planner import BrainPlanner
    planner = BrainPlanner(auth_runtime)
    context = ContextBuilder(auth_runtime).from_request({'url': idor_app.base + '/vulnerable/7'})
    row = planner.prepare(context)[0]
    for body in ('synthetic-first-proof', 'synthetic-second-proof'):
        store.transition(row['id'], auth_runtime.scan_id, 'inconclusive', 'test',
                         result_enc=auth_runtime.vault.encrypt(body))
    db.init_db()
    rows = db.get_db().execute('SELECT result_enc FROM test_plan_results WHERE plan_id=? ORDER BY id', (row['id'],)).fetchall()
    assert [auth_runtime.vault.decrypt(r[0]) for r in rows] == ['synthetic-first-proof', 'synthetic-second-proof']
    assert 'synthetic-first-proof' not in '\n'.join(db.get_db().iterdump())


async def test_rejection_during_execution_preserves_received_evidence(auth_runtime, idor_app):
    from qbh.brain import store
    from qbh.brain.context import ContextBuilder
    from qbh.brain.planner import BrainPlanner
    context = ContextBuilder(auth_runtime).from_request({'url': idor_app.base + '/vulnerable/7'})
    row = BrainPlanner(auth_runtime).prepare(context)[0]
    store.decide(row['id'], auth_runtime.scan_id, approve=False, reason='cancelled_by_user')
    store.transition(row['id'], auth_runtime.scan_id, 'inconclusive', 'response_received',
                     result_enc=auth_runtime.vault.encrypt('synthetic-late-response'))
    assert store.get(row['id'], auth_runtime.scan_id)['status'] == 'rejected'
    result = db.get_db().execute('SELECT result_enc FROM test_plan_results WHERE plan_id=?', (row['id'],)).fetchone()
    assert auth_runtime.vault.decrypt(result[0]) == 'synthetic-late-response'
