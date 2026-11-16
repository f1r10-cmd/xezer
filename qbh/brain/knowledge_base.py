"""Validated, data-only vulnerability knowledge (no executable expressions)."""
from __future__ import annotations

import json
from pathlib import Path

DIRECTORY = Path(__file__).with_name('knowledge')
REQUIRED = {'vuln_class', 'preconditions', 'relevant_endpoint_types', 'required_auth_states',
            'required_evidence', 'safe_test_strategy', 'expected_behavior',
            'potential_false_positives', 'confirmation_criteria', 'impact',
            'safe_poc_constraints', 'dependencies', 'required_authorization'}


def load_knowledge(directory=None):
    result = {}
    for path in sorted(Path(directory or DIRECTORY).glob('*.json')):
        item = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(item, dict) or not REQUIRED <= item.keys() or item['vuln_class'] != path.stem:
            raise ValueError(f'invalid_knowledge_schema:{path.name}')
        if not isinstance(item['preconditions'], list) or any(
            not isinstance(p, dict) or not isinstance(p.get('name'), str) or type(p.get('required')) is not bool
            for p in item['preconditions']
        ):
            raise ValueError(f'invalid_preconditions:{path.name}')
        for key in ('required_evidence', 'confirmation_criteria', 'required_authorization', 'safe_test_strategy'):
            if not isinstance(item[key], list) or not item[key] or any(not isinstance(v, str) or not v for v in item[key]):
                raise ValueError(f'invalid_{key}:{path.name}')
        constraints = item['safe_poc_constraints']
        if not isinstance(constraints, dict) or type(constraints.get('data_modification')) is not bool:
            raise ValueError(f'invalid_safety_constraints:{path.name}')
        if not isinstance(constraints.get('methods_allowed'), list) or not constraints['methods_allowed']:
            raise ValueError(f'invalid_methods:{path.name}')
        result[path.stem] = item
    if not result:
        raise ValueError('empty_knowledge_base')
    return result
