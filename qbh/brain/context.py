"""Evidence assembly from the single SQLite database and existing URL intelligence."""
from __future__ import annotations

from dataclasses import dataclass, field
import json
from urllib.parse import urlsplit
from typing import Any

from qbh import db, urlintel
from qbh.ingest.har_importer import HarImporter, digest
from qbh.ingest.request_graph import RequestGraph
from .classifier import classify


@dataclass
class TestContext:
    __test__ = False
    scan_id: int
    request_id: int | None
    request: dict = field(repr=False)
    response: dict = field(default_factory=dict, repr=False)
    runtime: Any = field(default=None, repr=False)
    related_requests: list = field(default_factory=list, repr=False)
    auth_states: list = field(default_factory=list, repr=False)
    previous_findings: list = field(default_factory=list, repr=False)
    previous_tests: list = field(default_factory=list, repr=False)
    api_schemas: list = field(default_factory=list, repr=False)
    fingerprint: dict = field(default_factory=dict, repr=False)
    endpoint: Any = field(default=None, repr=False)
    prerequisites: dict = field(default_factory=dict)
    evidence_refs: list[str] = field(default_factory=list)
    classifications: list = field(default_factory=list)
    url_id: int | None = None
    resource_policies: list = field(default_factory=list, repr=False)

    @property
    def prerequisite_hash(self):
        # Include actual state versions, never raw credentials in any view.
        return digest({'prerequisites': self.prerequisites,
                       'auth': [(getattr(a, 'name', ''), getattr(a, 'session_id', '')) for a in self.auth_states],
                       'request': self.request, 'response': self.response,
                       'schemas': self.api_schemas, 'fingerprint': self.fingerprint,
                       'resource_policies': self.resource_policies,
                       'related_requests': [getattr(n, 'request_id', None) for n in self.related_requests],
                       'findings': [(f['id'], f['status']) for f in self.previous_findings
                                    if not f['module'].startswith('brain:')
                                    and any(self.request['url'] in str(f.get(key, ''))
                                            for key in ('evidence', 'description', 'curl_repro'))]})

    def explanation(self):
        return {'request_id': self.request_id, 'evidence_refs': self.evidence_refs,
                'categories': [c.category for c in self.classifications],
                'available_prerequisites': sorted(k for k, v in self.prerequisites.items() if v),
                'prerequisite_hash': self.prerequisite_hash}


class ContextBuilder:
    def __init__(self, runtime, *, auth_states=()):
        self.runtime = runtime
        self.scan_id = db.effective_scan_id(runtime.scan_id)
        self.auth_states = list(auth_states)
        self._schema_cache = {}

    def from_import(self, request_id):
        row = db.get_db().execute('SELECT id FROM imported_requests WHERE id=? AND scan_id=?',
                                  (request_id, self.scan_id)).fetchone()
        if row is None:
            raise ValueError('imported_request_not_in_scan')
        request, response = HarImporter(self.runtime.vault).evidence(request_id)
        graph = RequestGraph(self.scan_id, self.runtime.vault)
        context = self.from_request(request, response=response, request_id=request_id)
        context.related_requests = graph.get_related(request_id)
        context.evidence_refs += [f'imported_request:{n.request_id}' for n in context.related_requests]
        return context

    def from_request(self, request, *, response=None, request_id=None, url_id=None):
        conn = db.get_db()
        host = urlsplit(request['url']).hostname
        context = TestContext(self.scan_id, request_id, request, response or {}, self.runtime,
                              auth_states=list(self.auth_states))
        context.url_id = url_id
        from qbh.scope import ScopeError
        from .resource_policy import matching_policies
        context.resource_policies = matching_policies(
            getattr(getattr(self.runtime, 'cfg', None), 'auth_resource_policies', []), request['url'])
        context.evidence_refs += [f'config:auth_resource_policies:{p["id"]}' for p in context.resource_policies]
        provider = getattr(self.runtime, 'auth_state', None)
        if provider is not None:
            compatible = []
            for identity in context.auth_states:
                try:
                    provider.headers_for(identity, request['url'])
                    compatible.append(identity)
                except (ValueError, ScopeError) as exc:
                    context.prerequisites['auth_unavailable:' + identity.name] = type(exc).__name__
            context.auth_states = compatible
        context.endpoint = urlintel.analyze_row({'url': request['url'], 'source': 'brain_context'})
        host_row = conn.execute('SELECT * FROM hosts WHERE scan_id=? AND subdomain=?',
                                (self.scan_id, host)).fetchone()
        if host_row:
            context.fingerprint = {k: host_row[k] for k in ('tech_raw', 'strategy', 'status_code')}
            context.previous_findings = [dict(r) for r in conn.execute(
                'SELECT * FROM findings WHERE scan_id=? AND host_id=?', (self.scan_id, host_row['id']))]
        context.previous_tests = [dict(r) for r in conn.execute(
            'SELECT * FROM task_state WHERE scan_id=? AND endpoint IN (?,?)',
            (self.scan_id, request['url'], host))]
        plans = [dict(r) for r in conn.execute(
            'SELECT id,status,reason,prerequisite_hash,vuln_class FROM test_plans WHERE scan_id=? '
            'AND ((request_id IS NOT NULL AND request_id=?) OR (url_id IS NOT NULL AND url_id=?))',
            (self.scan_id, request_id, url_id))]
        context.previous_tests.extend(plans)
        context.evidence_refs += [f'test_plan:{p["id"]}' for p in plans]
        # Decode each host's observed API schemas once per builder, without fetching anything.
        if host not in self._schema_cache:
            schemas, refs = [], []
            for row in conn.execute('SELECT id FROM imported_requests WHERE scan_id=? AND host=?', (self.scan_id, host)):
                _, observed = HarImporter(self.runtime.vault).evidence(row['id'])
                try:
                    body = json.loads(observed.get('content', {}).get('text', ''))
                except (TypeError, ValueError):
                    continue
                if isinstance(body, dict) and ('openapi' in body or 'swagger' in body):
                    schemas.append(body)
                    refs.append(f'imported_schema:{row["id"]}')
            self._schema_cache[host] = schemas, refs
        schemas, refs = self._schema_cache[host]
        context.api_schemas = list(schemas)
        context.evidence_refs.extend(refs)
        js_refs = [r['url'] for r in conn.execute(
            "SELECT url FROM urls WHERE scan_id=? AND source LIKE '%js%'", (self.scan_id,))
                   if urlsplit(r['url']).hostname == host]
        response_structure = context.response
        try:
            response_structure = json.loads(context.response.get('content', {}).get('text', ''))
        except (TypeError, ValueError):
            pass
        from .knowledge_base import load_knowledge
        knowledge = load_knowledge()
        finding_labels = [
            {'id': finding['id'], 'endpoint_category': category}
            for finding in context.previous_findings
            for category in knowledge.get(finding['module'].removeprefix('brain:'), {}).get('relevant_endpoint_types', [])
        ]
        context.classifications = classify({**request, 'response': response_structure,
                                           'findings': finding_labels,
                                           'api_schema': context.api_schemas, 'js_references': js_refs,
                                           'auth_context': bool(self.auth_states)})
        context.evidence_refs += [f'finding:{f["id"]}' for f in context.previous_findings]
        context.evidence_refs += [f'task:{t["task_id"]}' for t in context.previous_tests if 'task_id' in t]
        if request_id is not None:
            context.evidence_refs.append(f'imported_request:{request_id}')
        context.prerequisites['observed_request'] = True
        return context
