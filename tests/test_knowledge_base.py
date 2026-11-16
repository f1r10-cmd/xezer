import json
import pytest
from qbh.brain.knowledge_base import load_knowledge, REQUIRED


def test_all_fifteen_classes_have_verification_and_safety_contracts():
    knowledge = load_knowledge()
    assert len(knowledge) == 15
    for name, item in knowledge.items():
        assert REQUIRED <= item.keys()
        assert item['vuln_class'] == name
        assert item['confirmation_criteria'] and item['potential_false_positives']
        assert item['safe_poc_constraints']['destructive'] is False
        if name in {'idor', 'bola'}:
            assert item['safe_poc_constraints']['data_modification'] is False
        assert all(type(p['required']) is bool for p in item['preconditions'])


def test_invalid_data_fails_visibly(tmp_path):
    (tmp_path / 'idor.json').write_text(json.dumps({'vuln_class': 'idor'}))
    with pytest.raises(ValueError, match='invalid_knowledge_schema'):
        load_knowledge(tmp_path)
