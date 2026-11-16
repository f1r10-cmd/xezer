"""Bounded, evidence-preserving response comparisons; differences are not findings."""
from __future__ import annotations

from dataclasses import dataclass, field
from difflib import SequenceMatcher
import hashlib
import json
import math
import statistics
from typing import Any

from qbh.redact import redact

VOLATILE_FIELDS = frozenset({'timestamp', 'request_id', 'requestid', 'csrf_token', 'csrftoken', 'nonce'})
VOLATILE_HEADERS = frozenset({'date', 'x-request-id', 'x-correlation-id'})
OWNERSHIP_FIELDS = frozenset({'owner', 'owner_id', 'ownerid', 'user_id', 'userid', 'tenant_id', 'tenantid', 'account_id'})
SENSITIVE_FIELDS = frozenset({'password', 'passwd', 'secret', 'token', 'access_token', 'refresh_token',
                              'api_key', 'email', 'phone', 'ssn', 'credit_card', 'private_key'})
SEMANTIC_FIELDS = OWNERSHIP_FIELDS | SENSITIVE_FIELDS | frozenset({
    'id', 'role', 'roles', 'permissions', 'admin', 'is_admin', 'authenticated', 'authorized',
    'status', 'error', 'message', 'balance', 'amount', 'price', 'currency', 'data', 'items',
})
ERROR_MARKERS = ('traceback', 'sqlstate', 'stack trace', 'unhandled exception', 'access denied', 'unauthorized')
_MISSING = object()


def _hash(value):
    return hashlib.sha256(value.encode('utf-8', 'surrogatepass')).hexdigest()


def _fingerprint(value):
    if value is _MISSING:
        return 'absent'
    return _hash(json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':')))


@dataclass(frozen=True)
class Evidence:
    kind: str
    field: str
    baseline_digest: str
    test_digest: str
    details: dict = field(default_factory=dict)


@dataclass
class DiffResult:
    difference_summary: str
    relevant_evidence: list[Evidence]
    confidence: float
    possible_interpretations: list[str]
    false_positive_considerations: list[str]
    recommended_next_verification: str | None
    # Explicit accounting makes evidence limits visible rather than silently discarding differences.
    total_differences: int = 0
    omitted_evidence_count: int = 0
    limitations: list[str] = field(default_factory=list)


@dataclass
class ResponseSnapshot:
    status: int
    headers: Any = field(default_factory=dict, repr=False)
    body: str = field(default='', repr=False)
    truncated: bool = False
    timing_samples: tuple[float, ...] = ()
    timing_context: str = ''

    def __post_init__(self):
        if type(self.status) is not int or not 0 <= self.status <= 599 or not isinstance(self.body, str):
            raise ValueError('invalid_response_snapshot')


def _snapshot(response):
    if isinstance(response, ResponseSnapshot):
        return response
    if isinstance(response, dict):
        content = response.get('content', {})
        body = response.get('body', response.get('text', content.get('text', '')))
        if not isinstance(body, str):
            body = json.dumps(body, ensure_ascii=True)
        if content.get('reference_only'):
            body = json.dumps({'reference_sha256': content.get('sha256'), 'reference_size': content.get('size')})
        headers = response.get('headers', {})
        if not headers and content.get('mimeType'):
            headers = {'content-type': content['mimeType']}
        return ResponseSnapshot(response['status'], headers, body, response.get('truncated', False) or bool(content.get('reference_only')),
                                tuple(response.get('timing_samples', ())), response.get('timing_context', ''))
    return ResponseSnapshot(response.status, response.headers, response.text, getattr(response, 'truncated', False),
                            tuple(getattr(response, 'timing_samples', ())), getattr(response, 'timing_context', ''))


def _headers(headers):
    items = ((h['name'], h['value']) for h in headers) if isinstance(headers, list) else headers.items()
    result = {}
    for name, value in items:
        result.setdefault(str(name).lower(), []).append(str(value))
    return result


def _safe_component(value):
    # JSON object keys may themselves contain emails, passwords, or tokens.
    if str(value).lower() in SEMANTIC_FIELDS | VOLATILE_FIELDS:
        return redact(str(value).lower())
    if isinstance(value, int):
        return str(value)
    return 'key-' + _hash(str(value))[:16]


def _flatten(value, *, maximum, depth_limit):
    flat, limited = {}, False
    stack = [((), value)]
    while stack:
        path, node = stack.pop()
        if len(flat) >= maximum or len(path) > depth_limit:
            limited = True
            continue
        if isinstance(node, dict):
            flat[path] = ('object', len(node))
            remaining = max(0, maximum - len(flat) - len(stack))
            keys = sorted(node)
            if len(keys) > remaining:
                limited = True
            for key in reversed(keys[:remaining]):
                stack.append((path + (key,), node[key]))
        elif isinstance(node, list):
            flat[path] = ('array', len(node))
            remaining = max(0, maximum - len(flat) - len(stack))
            if len(node) > remaining:
                limited = True
            for index in reversed(range(min(len(node), remaining))):
                stack.append((path + (index,), node[index]))
        else:
            flat[path] = (type(node).__name__, node)
    return flat, limited


def _strict_json(body):
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate_json_key')
            result[key] = value
        return result

    def invalid_constant(value):
        raise ValueError('nonstandard_json_constant')

    return json.loads(body, object_pairs_hook=unique_object, parse_constant=invalid_constant)


class DiffEngine:
    def __init__(self, *, volatile_fields=VOLATILE_FIELDS, randomized_paths=(), max_evidence=200,
                 max_json_chars=2_000_000, max_nodes=10_000, max_depth=32, similarity_chars=2048):
        self.volatile_fields = frozenset(volatile_fields)
        # Only explicitly supplied JSON paths qualify as randomized; never guess from numeric IDs.
        self.randomized_paths = frozenset(tuple(p) for p in randomized_paths)
        self.max_evidence = max(1, int(max_evidence))
        self.max_json_chars = max(1, int(max_json_chars))
        self.max_nodes = max(1, int(max_nodes))
        self.max_depth = max(1, int(max_depth))
        self.similarity_chars = max(1, min(8192, int(similarity_chars)))

    def compare(self, baseline_response, test_response) -> DiffResult:
        baseline, test = _snapshot(baseline_response), _snapshot(test_response)
        evidence, limitations, interpretations = [], [], []
        considerations = ['Different responses can reflect legitimate permissions, public content, caching, or application state.',
                          'A matching status or body does not establish unauthorized access.']
        total = substantive = observations = 0

        def add(kind, path, before, after, *, meaningful=True, difference=True, **details):
            nonlocal total, substantive, observations
            observations += 1
            total += int(difference)
            substantive += int(meaningful and difference)
            if len(evidence) < self.max_evidence:
                evidence.append(Evidence(kind, path, _fingerprint(before), _fingerprint(after), details))

        if baseline.status != test.status:
            add('status', 'status', baseline.status, test.status, baseline=baseline.status, test=test.status)
            interpretations.append('Access-control behavior, redirects, or application error handling may differ.')
        left, right = _headers(baseline.headers), _headers(test.headers)
        for name in sorted(left.keys() | right.keys()):
            a, b = left.get(name, _MISSING), right.get(name, _MISSING)
            if a == b:
                continue
            volatile = name in VOLATILE_HEADERS
            kind = ('redirect' if name == 'location' else 'content_type' if name == 'content-type'
                    else 'volatile_header' if volatile else 'header')
            # Header values (including Location query credentials and cookies) are never emitted.
            safe_name = name if name in {'location', 'content-type', 'set-cookie', 'www-authenticate',
                                         'cache-control', 'vary', 'access-control-allow-origin'} | VOLATILE_HEADERS else 'header-' + _hash(name)[:16]
            add(kind, safe_name, a, b, meaningful=not volatile)
        if baseline.truncated or test.truncated:
            limitations.append('truncated_response: comparison cannot establish full-body equality')
        json_values = []
        for body in (baseline.body, test.body):
            if len(body) > self.max_json_chars:
                json_values.append(_MISSING)
                limitations.append('json_size_limit: raw body fingerprint is preserved')
                continue
            try:
                json_values.append(_strict_json(body))
            except (ValueError, RecursionError):
                json_values.append(_MISSING)
        both_json = all(v is not _MISSING for v in json_values)
        normalized_equal = False
        if both_json:
            before, limited_before = _flatten(json_values[0], maximum=self.max_nodes, depth_limit=self.max_depth)
            after, limited_after = _flatten(json_values[1], maximum=self.max_nodes, depth_limit=self.max_depth)
            if limited_before or limited_after:
                limitations.append('json_structure_limit: some fields were not individually compared')
            changed = False
            for path in sorted(before.keys() | after.keys(), key=repr):
                a, b = before.get(path, _MISSING), after.get(path, _MISSING)
                name = str(path[-1]).lower() if path else ''
                if _fingerprint(a) == _fingerprint(b):
                    if name in OWNERSHIP_FIELDS | SENSITIVE_FIELDS:
                        add('ownership_indicator' if name in OWNERSHIP_FIELDS else 'sensitive_indicator',
                            '/' + '/'.join(_safe_component(p) for p in path), a, b,
                            meaningful=False, difference=False, matching=True)
                    continue
                scalar_pair = (a is not _MISSING and b is not _MISSING and
                               a[0] not in {'object', 'array'} and b[0] not in {'object', 'array'})
                # Never normalize addition/removal/type changes, or ownership/security semantics.
                volatile = (scalar_pair and a[0] == b[0] and name not in SEMANTIC_FIELDS and
                            (name in self.volatile_fields or path in self.randomized_paths))
                changed |= not volatile
                kind = ('volatile_field' if volatile else 'ownership' if name in OWNERSHIP_FIELDS
                        else 'sensitive_field' if name in SENSITIVE_FIELDS else 'json_field')
                safe_path = '/' + '/'.join(_safe_component(p) for p in path)
                add(kind, safe_path, a, b, meaningful=not volatile,
                    baseline_present=a is not _MISSING, test_present=b is not _MISSING,
                    normalized=volatile)
            normalized_equal = not changed and not (limited_before or limited_after)
        elif (json_values[0] is _MISSING) != (json_values[1] is _MISSING):
            add('json_parse_behavior', 'body', json_values[0] is not _MISSING, json_values[1] is not _MISSING)
        if baseline.body != test.body:
            def sample(body):
                if len(body) <= self.similarity_chars:
                    return body
                width = max(1, self.similarity_chars // 3)
                middle = len(body) // 2
                return body[:width] + body[middle:middle + width] + body[-width:]
            similarity = SequenceMatcher(None, sample(baseline.body), sample(test.body), autojunk=True).ratio()
            add('body', 'body', baseline.body, test.body, meaningful=not normalized_equal,
                similarity=round(similarity, 6), sampled=max(len(baseline.body), len(test.body)) > self.similarity_chars,
                normalized_json_equal=normalized_equal)
            interpretations.append('Content differs; determine whether the change exposes protected information or is expected variation.')
        else:
            interpretations.append('Bodies match; public content, shared errors, or unauthorized disclosure are all possible.')
        for marker in ERROR_MARKERS:
            a, b = marker in baseline.body.lower(), marker in test.body.lower()
            if a != b:
                add('error_behavior', 'error_signature', a, b, signature=marker)
        if baseline.status >= 400 or test.status >= 400:
            considerations.append('Error pages can share content and status patterns across unrelated causes.')
        if any(e.kind.startswith('sensitive_') for e in evidence):
            considerations.append('Sensitive field names are indicators only; public or synthetic data requires policy verification.')
        if any(e.kind.startswith('volatile_') for e in evidence):
            considerations.append('Volatile-field normalization is provisional: timestamps, CSRF tokens and nonces can carry security meaning; their changes remain recorded.')
        samples = (baseline.timing_samples, test.timing_samples)
        reliable = (bool(baseline.timing_context) and baseline.timing_context == test.timing_context and
                    all(len(s) >= 3 and all(type(t) in (float, int) and math.isfinite(t) and t >= 0 for t in s)
                        for s in samples))
        if reliable:
            medians = [statistics.median(s) for s in samples]
            if medians[0] != medians[1]:
                add('timing', 'elapsed_samples', medians[0], medians[1], median_delta=medians[1] - medians[0],
                    baseline_samples=len(samples[0]), test_samples=len(samples[1]),
                    ranges_overlap=max(min(s) for s in samples) <= min(max(s) for s in samples))
                considerations.append('Timing differences need repeated interleaved controls; network jitter, load and caching can explain them.')
        else:
            limitations.append('timing_unverified: requires at least three finite samples per response and a shared measurement context')
        if total == 0:
            summary = 'No observed differences; this is not proof of equivalent authorization.'
        elif substantive == 0:
            summary = 'Only provisional volatile/formatting differences observed; raw changes are preserved.'
        else:
            summary = f'{total} observed differences; {substantive} require semantic verification.'
        confidence = 0.9 if substantive else 0.4 if total else 0.0
        if any(not limitation.startswith('timing_unverified') for limitation in limitations):
            confidence = min(confidence, .4)
        return DiffResult(summary, evidence, confidence, interpretations, considerations,
                          'Repeat with known ownership, distinct valid identities and a negative control before confirming a vulnerability.',
                          total, max(0, observations - len(evidence)), list(dict.fromkeys(limitations)))
