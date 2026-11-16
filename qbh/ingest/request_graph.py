"""Inspectable inferred relationships; chronology alone is never a dependency."""
from __future__ import annotations

from dataclasses import dataclass
import math
from urllib.parse import urlsplit

from qbh import db
from qbh.ingest.har_importer import HarImporter

RELATIONS = {'session_continuation', 'auth_flow', 'same_endpoint_family', 'parameter_progression', 'unknown'}


@dataclass(frozen=True)
class RequestNode:
    request_id: int
    scan_id: int
    method: str
    url: str


class RequestGraph:
    def __init__(self, scan_id, vault=None):
        self.scan_id = scan_id
        self.importer = HarImporter(vault)

    def add_request(self, request_id: int) -> RequestNode:
        row = db.get_db().execute('SELECT * FROM imported_requests WHERE id=? AND scan_id=?',
                                  (request_id, self.scan_id)).fetchone()
        if row is None:
            raise ValueError('request_not_in_scan')
        return RequestNode(request_id, self.scan_id, row['method'], row['url'])

    def add_inferred_edge(self, from_id, to_id, relation, confidence, provenance):
        self.add_request(from_id)
        self.add_request(to_id)
        if relation not in RELATIONS or not math.isfinite(confidence) or not 0 <= confidence <= 1:
            raise ValueError('invalid_relation_or_confidence')
        if from_id == to_id or not provenance.strip():
            raise ValueError('invalid_edge')
        # Provenance is caller-authored explanation, never raw traffic.
        from qbh.redact import redact
        conn = db.get_db()
        with conn:
            conn.execute('INSERT INTO request_graph_edges VALUES (?,?,?,?,?,?) '
                         'ON CONFLICT(from_request_id,to_request_id,relation_type) DO UPDATE SET '
                         'confidence=excluded.confidence,provenance=excluded.provenance',
                         (from_id, to_id, relation, confidence, redact(provenance), db._now()))

    def edges(self):
        return [dict(r) for r in db.get_db().execute(
            'SELECT e.* FROM request_graph_edges e JOIN imported_requests r ON r.id=e.from_request_id '
            'WHERE r.scan_id=? ORDER BY e.from_request_id,e.to_request_id,e.relation_type', (self.scan_id,))]

    def get_related(self, request_id):
        self.add_request(request_id)
        ids = set()
        for edge in self.edges():
            if edge['from_request_id'] == request_id:
                ids.add(edge['to_request_id'])
            if edge['to_request_id'] == request_id:
                ids.add(edge['from_request_id'])
        return [self.add_request(i) for i in sorted(ids)]

    def get_auth_context_chains(self):
        adjacency = {}
        for edge in self.edges():
            if edge['relation_type'] not in {'session_continuation', 'auth_flow'}:
                continue
            a, b = edge['from_request_id'], edge['to_request_id']
            adjacency.setdefault(a, set()).add(b)
            adjacency.setdefault(b, set()).add(a)
        seen, groups = set(), []
        for root in sorted(adjacency):
            if root in seen:
                continue
            stack, group = [root], []
            while stack:
                node = stack.pop()
                if node in seen:
                    continue
                seen.add(node)
                group.append(self.add_request(node))
                stack.extend(sorted(adjacency[node] - seen, reverse=True))
            groups.append(group)
        return groups

    def infer(self):
        """Bounded edges to the previous matching session/family, never all pairs."""
        sessions, families = {}, {}
        rows = db.get_db().execute('SELECT id FROM imported_requests WHERE scan_id=? ORDER BY id', (self.scan_id,))
        for row in rows:
            rid = row['id']
            req, _ = self.importer.evidence(rid)
            parts = urlsplit(req['url'])
            family = (parts.scheme, parts.netloc, parts.path.rsplit('/', 1)[0])
            if family in families:
                self.add_inferred_edge(families[family], rid, 'same_endpoint_family', .5,
                                       'Same origin and parent path; dependency unverified')
            families[family] = rid
            credentials = [(h['name'].lower(), h['value']) for h in req['headers']
                           if h['name'].lower() in {'authorization', 'cookie'} and h['value']]
            credentials += [('cookie:' + str(c.get('name', '')), str(c.get('value', '')))
                            for c in req['cookies'] if isinstance(c, dict) and c.get('value')]
            for credential in credentials:
                key = (parts.scheme, parts.netloc, credential)
                if key in sessions and sessions[key] != rid:
                    self.add_inferred_edge(sessions[key], rid, 'session_continuation', .8,
                                           'Same origin and identical credential; identity unverified')
                sessions[key] = rid
        return self.edges()
