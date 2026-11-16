"""Multi-label request classification. Categories never exclude a test."""
from __future__ import annotations

from dataclasses import dataclass
import re
from urllib.parse import parse_qsl, urlsplit


@dataclass(frozen=True)
class Classification:
    category: str
    confidence: float
    evidence_refs: tuple[str, ...]


# Evidence references deliberately contain neither credentials nor raw values.
PATTERNS = {
    'authentication': r'login|logout|signin|oauth|authenticate|password|mfa|otp',
    'account_management': r'account|profile|register|signup|password|settings',
    'user_resources': r'users?|members?|profiles?|customers?',
    'administrative_resources': r'admin|manage|dashboard|permissions?|roles?',
    'file_upload_download': r'upload|download|files?|attachments?|documents?',
    'search': r'search|query|filter|lookup',
    'payment_checkout': r'payments?|checkout|billing|invoices?|transactions?|cart',
    'api_operations': r'api|graphql|openapi|swagger|v[0-9]+',
    'object_access': r'id|uuid|object|owner|resource',
    'configuration': r'config|settings|preferences|feature|flags?',
    'business_workflow': r'orders?|approve|workflow|submit|redeem|transfer|confirm',
}


def _keys(value, depth=0):
    if depth > 12:
        return []
    if isinstance(value, dict):
        return [str(k) for k in value] + [key for v in value.values() for key in _keys(v, depth + 1)]
    if isinstance(value, list):
        return [key for v in value for key in _keys(v, depth + 1)]
    return []


def classify(request: dict) -> list[Classification]:
    """Accept request data plus optional observed response/schema/JS evidence."""
    parts = urlsplit(request.get('url', ''))
    sources = {
        'request.path': re.sub(r'[^a-zA-Z0-9]+', ' ', parts.path),
        'request.parameters': ' '.join(k for k, _ in parse_qsl(parts.query)),
        'request.structure': ' '.join(_keys(request.get('body', {}))),
        'response.structure': ' '.join(_keys(request.get('response', {}))),
        'api.schema': ' '.join(_keys(request.get('api_schema', {}))),
        'javascript.references': ' '.join(str(v) for v in request.get('js_references', [])),
    }
    found = {}
    for category, pattern in PATTERNS.items():
        refs = tuple(ref for ref, value in sources.items()
                     if re.search(r'\b(?:' + pattern + r')\b', value, re.I))
        if refs:
            found[category] = Classification(category, min(.9, .55 + .1 * len(refs)), refs)
    if request.get('method', 'GET').upper() in {'POST', 'PUT', 'PATCH', 'DELETE'}:
        found.setdefault('business_workflow', Classification('business_workflow', .4, ('request.method',)))
    if re.search(r'/(?:[0-9]+|[0-9a-f]{8}-[0-9a-f-]{27,})(?:/|$)', parts.path, re.I):
        found.setdefault('object_access', Classification('object_access', .6, ('request.path.object_identifier',)))
    if request.get('auth_context'):
        found.setdefault('user_resources', Classification('user_resources', .4, ('auth_context.reference',)))
    for previous in request.get('findings', []):
        category = previous.get('endpoint_category')
        if category in PATTERNS:
            found.setdefault(category, Classification(category, .6, (f'finding:{previous["id"]}' if 'id' in previous else 'previous_finding.reference',)))
    return list(found.values()) or [Classification('unknown', 0.0, ('no_classification_evidence',))]
