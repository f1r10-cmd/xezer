"""Explainable planning and bounded execution through TaskLedger and Scheduler."""
from __future__ import annotations

import asyncio
from dataclasses import asdict, replace
from urllib.parse import urlsplit

from qbh import db
from qbh.authorization import AuthorizationError
from qbh.ingest.har_importer import canonical, digest
from qbh.results import EngineResult
from qbh.scheduler import Scheduler, SchedTask, submit_with_backpressure
from qbh.tasks import TaskLedger, task_identity, STATE_SKIPPED
from . import store
from .context import ContextBuilder, TestContext
from .knowledge_base import load_knowledge
from .strategy import TestPlan, discover


class BrainPlanner:
    def __init__(self, runtime):
        self.runtime = runtime
        self.knowledge = load_knowledge()
        self.plugins = discover()
        self.ledger = getattr(runtime, 'task_ledger', None) or TaskLedger()
        self.scan_id = db.effective_scan_id(runtime.scan_id)
        self._prepared = {}

    def _authorize(self, context, name):
        auth = self.runtime._auth()
        auth.ensure_active()
        auth.authorize_request(context.request.get('method', 'GET'), context.request['url'], name)
        for action in self.knowledge.get(name, {}).get('required_authorization', [name, 'active_fuzz']):
            auth.require(action)

    def prepare(self, context):
        records = []
        for name in sorted(self.knowledge.keys() | self.plugins.keys()):
            plugin = self.plugins.get(name)
            if plugin:
                applicable, applicability_reason = plugin.is_applicable(context)
                plan = plugin.plan_test(context)
                if not applicable and not plan.missing_prerequisites:
                    plan = replace(plan, reason=applicability_reason, missing_prerequisites=("strategy_applicability",))
            else:
                missing = tuple(p['name'] for p in self.knowledge[name]['preconditions']
                                if p['required'] and not context.prerequisites.get(p['name']))
                plan = TestPlan(name, context.request_id, context.prerequisite_hash,
                                'existing_engines_preserved;strategy_plugin_unavailable',
                                missing + ('strategy_plugin',), tuple(context.evidence_refs))
            source = (f'import:{context.request_id}' if context.request_id is not None else
                      f'url:{context.url_id}' if context.url_id is not None else digest(context.request))
            identity = task_identity(context.scan_id, 'brain_plan', source, test_type=name)
            status, reason = ('deferred', plan.reason) if plan.missing_prerequisites else ('ready', plan.reason)
            try:
                self._authorize(context, name)
            except AuthorizationError as exc:
                status, reason = 'skipped', 'authorization:' + type(exc).__name__
            if context.prerequisites.get('vault_evidence_unavailable') and status != 'skipped':
                status, reason = 'deferred', 'vault_evidence_unavailable_retryable'
            if status == 'ready' and not self.runtime.vault.available:
                status, reason = 'deferred', 'vault_unavailable_retryable'
            row = store.save(identity, context, plan, status, reason)
            self._prepared[identity] = (context, plan)
            records.append(row)
        return records

    def prepare_scan(self):
        auth_state = getattr(self.runtime, 'auth_state', None)
        identities = list(auth_state.contexts.values()) if auth_state is not None else []
        builder = ContextBuilder(self.runtime, auth_states=identities)
        conn = db.get_db()
        for row in conn.execute('SELECT id,method,url FROM imported_requests WHERE scan_id=? ORDER BY id', (self.scan_id,)):
            try:
                context = builder.from_import(row['id'])
            except ValueError:
                # Preserve all classifications as deferred even when encrypted evidence is unavailable.
                context = TestContext(self.scan_id, row['id'], {'url': row['url'], 'method': row['method']}, runtime=self.runtime,
                                      evidence_refs=[f'imported_request:{row["id"]}'])
                context.prerequisites['vault_evidence_unavailable'] = True
            self.prepare(context)
        for row in conn.execute('SELECT id,url FROM urls WHERE scan_id=? ORDER BY id', (self.scan_id,)):
            try:
                context = builder.from_request({'url': row['url'], 'method': 'GET'}, url_id=row['id'])
            except ValueError:
                context = TestContext(self.scan_id, None, {'url': row['url'], 'method': 'GET'},
                                      runtime=self.runtime, url_id=row['id'])
                context.prerequisites['vault_evidence_unavailable'] = True
            context.evidence_refs.append(f'url:{row["id"]}')
            self.prepare(context)
        return store.list_plans(self.scan_id)

    async def _execute(self, plan_id, context, plan):
        # Rejection and authorization are read again after queueing, at the actual execution boundary.
        row = store.get(plan_id, context.scan_id)
        if row['user_decision'] == 'rejected':
            return {'status': 'rejected'}
        try:
            self._authorize(context, plan.vuln_class)
        except AuthorizationError as exc:
            store.transition(plan_id, context.scan_id, 'skipped', 'authorization:' + type(exc).__name__)
            return {'status': 'skipped'}
        plugin = self.plugins[plan.vuln_class]
        current = plugin.plan_test(context)
        applicable, _ = plugin.is_applicable(context)
        if not applicable or current.missing_prerequisites:
            store.transition(plan_id, context.scan_id, 'deferred', current.reason)
            return {'status': 'deferred'}
        if not self.runtime.vault.available:
            store.transition(plan_id, context.scan_id, 'deferred', 'vault_unavailable_retryable')
            return {'status': 'deferred'}
        store.transition(plan_id, context.scan_id, 'running', 'authorized_at_execution')
        try:
            result = await plugin.execute_test(context, current)
        except asyncio.CancelledError:
            store.transition(plan_id, context.scan_id, 'pending', 'cancelled_retryable')
            raise
        except Exception as exc:
            # Raw exception strings may contain URLs, cookies, or provider credentials.
            store.transition(plan_id, context.scan_id, 'failed', 'strategy_error:' + type(exc).__name__)
            return {'status': 'failed'}
        from .strategies.idor import has_confirmation
        confirmed = plan.vuln_class == 'idor' and has_confirmation(result)
        if result.status == 'confirmed' and not confirmed:
            result.status, result.reason, result.confirmed = 'inconclusive', 'confirmation_evidence_incomplete', False
        encrypted = self.runtime.vault.encrypt(canonical(asdict(result)))
        if encrypted is None:
            store.transition(plan_id, context.scan_id, 'failed', 'vault_write_failed_retryable')
            return {'status': 'failed'}
        finding_id = None
        if result.status == 'candidate' or confirmed:
            host_id = db.upsert_host(urlsplit(context.request['url']).hostname, scan_id=context.scan_id)
            finding_id = db.insert_finding(host_id, 'brain:' + plan.vuln_class, 'high' if confirmed else 'low',
                                          ('Verified: ' if confirmed else 'Verification required: ') + plan.vuln_class,
                                          evidence='test_plan:' + plan_id, status='confirmed' if confirmed else 'candidate',
                                          confidence=.95 if confirmed else .4,
                                          source='brain_strategy', scan_id=context.scan_id)
            db.add_evidence(finding_id, 'brain_plan', canonical({'plan_id': plan_id, 'evidence_refs': current.evidence_refs}),
                            context.scan_id)
        store.transition(plan_id, context.scan_id, result.status, result.reason, result_enc=encrypted, finding_id=finding_id)
        return {'status': result.status, 'finding_id': finding_id}

    async def execute_ready(self, *, budget=None):
        maximum = int(self.runtime.cfg.chain.max_tasks) if budget is None else max(0, int(budget))
        cap = max(1, int(self.runtime.cfg.effective_concurrency))
        sched = Scheduler(workers=cap, global_limit=cap, per_host_limit=cap, ledger=self.ledger,
                          metrics=getattr(self.runtime, 'orchestration', None), guardian=self.runtime.guardian)
        admitted = 0
        async with sched:
            for plan_id, (context, plan) in self._prepared.items():
                row = store.get(plan_id, context.scan_id)
                if row['status'] != 'ready':
                    continue
                if admitted >= maximum:
                    store.transition(plan_id, context.scan_id, 'deferred', 'bounded_scheduling_budget_exhausted')
                    continue
                ident = task_identity(context.scan_id, 'brain:' + plan.vuln_class, plan_id,
                                      profile=plan.prerequisite_hash)
                decision = self.ledger.consider(ident, engine='brain:' + plan.vuln_class,
                                                endpoint=plan_id, test_type=plan.vuln_class)
                if not decision.create:
                    store.transition(plan_id, context.scan_id, 'deferred', 'task_ledger:' + decision.reason)
                    continue
                task = SchedTask(identity=ident, engine='brain:' + plan.vuln_class,
                                 host=urlsplit(context.request['url']).hostname or '', family=plan.vuln_class,
                                 run=lambda pid=plan_id, ctx=context, p=plan: self._execute(pid, ctx, p))
                if await submit_with_backpressure(sched, task):
                    admitted += 1
                else:
                    self.ledger.mark(ident, STATE_SKIPPED, 'bounded_backpressure')
                    store.transition(plan_id, context.scan_id, 'deferred', 'bounded_backpressure')
            await sched.drain()
        return sched.snapshot()

    async def run(self, *, budget=None):
        result = EngineResult(stage='brain')
        if db.get_scan(self.scan_id) is None:
            return result.skip('brain: scan_id yoxdur')
        initialize = getattr(self.runtime, 'initialize_auth', None)
        if initialize is not None:
            await initialize()
        self.prepare_scan()
        snapshot = await self.execute_ready(budget=budget)
        rows = store.list_plans(self.scan_id)
        result.findings = len({r['finding_id'] for r in rows if r['finding_id'] is not None})
        result.data = {'plans': rows, 'scheduler': snapshot}
        if any(r['status'] in {'failed', 'deferred'} for r in rows):
            result.mark_partial('Brain: ilkin şərtlər və nəticəsiz cəhdlər test-plan auditindədir')
        return result
