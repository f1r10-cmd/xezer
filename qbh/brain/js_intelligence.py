"""Offline AST observations; code is never executed and credentials never replayed."""
from dataclasses import dataclass, field
import json
import re
from urllib.parse import urljoin

from qbh.ingest.har_importer import digest

MAX_AST_SIZE = 500_000


@dataclass
class JSObservations:
    parser: str = 'esprima'
    observations: list = field(default_factory=list, repr=False)
    limitations: list = field(default_factory=list)

    def summary(self):
        counts = {}
        for item in self.observations:
            counts[item['kind']] = counts.get(item['kind'], 0) + 1
        return {'parser': self.parser, 'counts': counts, 'limitations': self.limitations}


def _name(node):
    if not isinstance(node, dict):
        return ''
    if node.get('type') == 'Identifier':
        return node.get('name', '')
    if node.get('type') == 'MemberExpression':
        return _name(node.get('object')) + '.' + _name(node.get('property'))
    return str(node.get('value', '')) if node.get('type') == 'Literal' else ''


def analyze(source, source_url):
    result = JSObservations()
    seen = set()

    def add(kind, value, node=None, **metadata):
        if not isinstance(value, str) or not value:
            return
        line = (node or {}).get('loc', {}).get('start', {}).get('line')
        identity = digest([kind, value, line, metadata])
        if identity in seen:
            return
        seen.add(identity)
        result.observations.append({'kind': kind, 'value': value, 'line': line,
                                    'source_digest': digest(source_url), **metadata})

    try:
        if len(source) > MAX_AST_SIZE:
            raise ValueError('ast_size_limit')
        import esprima
        tree = esprima.parseModule(source, loc=True, jsx=True).toDict()
        stack = [tree]
        while stack:
            node = stack.pop()
            if not isinstance(node, dict):
                continue
            kind = node.get('type')
            if kind == 'CallExpression':
                callee = _name(node.get('callee'))
                args = node.get('arguments', [])
                if args and (callee == 'fetch' or callee.startswith(('axios.', 'router.', 'app.'))):
                    value = args[0].get('value')
                    if isinstance(value, str):
                        add('endpoint', urljoin(source_url, value), node, call=callee)
                    else:
                        add('dynamic_endpoint', callee, node, reason='runtime_expression_not_executed')
            if kind == 'Property':
                key = _name(node.get('key'))
                value = node.get('value', {}).get('value')
                if key in {'path', 'route', 'url', 'baseURL'} and isinstance(value, str):
                    add('route' if key in {'path', 'route'} else 'endpoint', urljoin(source_url, value), node)
                if re.search(r'role|permission|isAdmin', key, re.I):
                    add('frontend_permission', key, node, value_digest=digest(value))
                if re.search(r'feature|enabled|flag', key, re.I):
                    add('feature_flag', key, node, value_digest=digest(value))
            if kind in {'MemberExpression', 'Identifier'}:
                name = _name(node)
                if re.search(r'role|permission|isAdmin', name, re.I):
                    add('frontend_permission', name, node)
                if re.search(r'feature|flag', name, re.I):
                    add('feature_flag', name, node)
            if kind == 'Literal' and isinstance(node.get('value'), str):
                value = node['value']
                if value.startswith(('http://', 'https://', '//')):
                    add('service_reference', urljoin(source_url, value), node)
            for value in node.values():
                if isinstance(value, dict):
                    stack.append(value)
                elif isinstance(value, list):
                    stack.extend(v for v in value if isinstance(v, dict))
    except (ImportError, ValueError, RecursionError, RuntimeError) as exc:
        result.parser = 'regex_fallback'
        result.limitations.append('ast_unavailable_or_unsupported:' + type(exc).__name__)
    except Exception as exc:
        # Parser-specific syntax exceptions may embed source, so retain only the type.
        result.parser = 'regex_fallback'
        result.limitations.append('ast_parse_failed:' + type(exc).__name__)
    # Existing extraction stays active even when the AST parser succeeds.
    for match in re.finditer(r"""['"]((?:/api|/v[0-9]|/admin|/graphql|/rest)/[A-Za-z0-9_\-/]{2,60})['"]""", source):
        add('endpoint', urljoin(source_url, match.group(1)), extraction='legacy_regex')
    for match in re.finditer(r'[#@]\s*sourceMappingURL=([^\s*]+)', source):
        value = match.group(1)
        add('source_map', value if value.startswith('data:') else urljoin(source_url, value))
    return result


def source_map_sources(content):
    """Read embedded sources without fetching arbitrary sources/sourceRoot URLs."""
    value = json.loads(content)
    if not isinstance(value, dict) or value.get('version') != 3:
        raise ValueError('unsupported_source_map')
    sources, contents = value.get('sources', []), value.get('sourcesContent', [])
    if not isinstance(sources, list) or not isinstance(contents, list):
        raise ValueError('invalid_source_map')
    return [{'name': name, 'content': contents[i] if i < len(contents) else None,
             'reason': 'embedded_source' if i < len(contents) and isinstance(contents[i], str) else 'source_content_unavailable'}
            for i, name in enumerate(sources)]


def persist(runtime, source_url, content, result):
    """Keep observations encrypted; public summaries contain counts and reasons only."""
    from qbh import db
    from qbh.ingest.har_importer import canonical, HarImporter
    from qbh.scope import ScopeError
    from urllib.parse import urlsplit
    from qbh.redact import redact

    imported = []
    for row in db.get_db().execute('SELECT id FROM imported_requests WHERE scan_id=?', (runtime.scan_id,)):
        try:
            request, _ = HarImporter(runtime.vault).evidence(row['id'])
        except ValueError:
            result.limitations.append('har_evidence_unavailable_retryable')
            continue
        imported.append((row['id'], request['url']))
    for item in result.observations:
        if item['kind'] not in {'endpoint', 'route', 'service_reference', 'source_map'}:
            continue
        url = item['value']
        if url.startswith('data:'):
            item['decision'] = 'embedded_source_map'
            continue
        item['har_refs'] = [ref for ref, observed in imported if observed == url]
        try:
            runtime._auth().authorize_request('GET', url, 'jsanalysis')
        except ScopeError:
            item['decision'] = 'out_of_scope_or_forbidden'
            continue
        parts = urlsplit(url)
        if item['kind'] in {'service_reference', 'source_map'}:
            item['decision'] = 'reviewable_reference'
        elif (parts.query or parts.username or parts.password or redact(url) != url
              or any(len(segment) > 64 for segment in parts.path.split('/'))):
            item['decision'] = 'credential_or_parameter_review_required'
        else:
            host = db.upsert_host(parts.hostname, scan_id=runtime.scan_id)
            db.insert_url(host, url, 'jsanalysis_ast', scan_id=runtime.scan_id)
            item['decision'] = 'queued_endpoint'
    payload = runtime.vault.encrypt(canonical({'source_url': source_url, 'observations': result.observations}))
    status = 'recorded' if payload else 'blocked_vault_retryable'
    conn = db.get_db()
    with conn:
        conn.execute('INSERT INTO js_observations(scan_id,source_digest,content_digest,payload_enc,summary,status,created_at) '
                     'VALUES(?,?,?,?,?,?,?)', (runtime.scan_id, digest(source_url), digest(content), payload,
                                               canonical(result.summary()), status, db._now()))
    return status
