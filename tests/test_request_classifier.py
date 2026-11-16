from qbh.brain.classifier import classify


def test_multilabel_and_evidence_without_secret_values():
    result = classify({'url': 'https://example.invalid/api/users/123?token=private-value', 'method': 'GET',
                       'body': {'owner': 'alice'}, 'response': {'profile': {'name': 'Alice'}}})
    assert {'api_operations', 'user_resources', 'object_access'} <= {c.category for c in result}
    assert all(0 <= c.confidence <= 1 and c.evidence_refs for c in result)
    assert 'private-value' not in repr(result)


def test_unknown_is_a_label_not_exclusion():
    assert classify({'url': 'https://example.invalid/'})[0].category == 'unknown'


def test_structure_and_additional_sources():
    values = classify({'url': 'https://example.invalid/', 'method': 'POST',
                       'api_schema': {'payment': {}}, 'js_references': ['/admin/upload'],
                       'auth_context': 'user-a'})
    assert {'payment_checkout', 'administrative_resources', 'file_upload_download',
            'business_workflow', 'user_resources'} <= {v.category for v in values}


def test_previous_finding_keeps_its_evidence_reference():
    result = classify({'url': 'https://example.invalid/',
                       'findings': [{'id': 5, 'endpoint_category': 'search'}]})
    assert result[0].category == 'search'
    assert result[0].evidence_refs == ('finding:5',)
