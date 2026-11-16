from dataclasses import asdict
import json

import pytest

from qbh.brain.diff_engine import DiffEngine, ResponseSnapshot
from qbh.http_policy import HttpResponse


def response(body, *, status=200, headers=None, **kwargs):
    return ResponseSnapshot(status, headers or {'Content-Type': 'application/json'},
                            json.dumps(body) if not isinstance(body, str) else body, **kwargs)


def kinds(result):
    return {e.kind for e in result.relevant_evidence}


def test_status_headers_redirect_errors_have_separate_evidence():
    result = DiffEngine().compare(response({'error': 'unauthorized'}, status=401),
                                  response('SQLSTATE error', status=302, headers={
                                      'Content-Type': 'text/html', 'Location': '/private?token=do-not-export',
                                      'Set-Cookie': 'sid=do-not-export'}))
    assert {'status', 'content_type', 'redirect', 'header', 'error_behavior', 'json_parse_behavior'} <= kinds(result)
    assert 'do-not-export' not in json.dumps(asdict(result))
    assert result.possible_interpretations and result.false_positive_considerations
    assert result.recommended_next_verification
    assert not hasattr(result, 'confirmed')


def test_normalization_keeps_raw_changes_and_real_ownership_difference():
    result = DiffEngine().compare(response({'timestamp': 'old', 'csrf_token': 'old-secret', 'owner_id': 1}),
                                  response({'timestamp': 'new', 'csrf_token': 'new-secret', 'owner_id': 2}))
    assert {'volatile_field', 'ownership', 'body'} <= kinds(result)
    assert not next(e for e in result.relevant_evidence if e.kind == 'body').details['normalized_json_equal']
    assert 'old-secret' not in repr(result) and 'new-secret' not in repr(result)


def test_only_volatile_fields_still_appear_in_evidence():
    result = DiffEngine().compare(response({'request_id': 'a'}), response({'request_id': 'b'}))
    assert result.total_differences == 2
    assert 'volatile_field' in kinds(result)
    assert next(e for e in result.relevant_evidence if e.kind == 'body').details['normalized_json_equal']
    assert result.confidence < .5


@pytest.mark.parametrize('before,after', [({'timestamp': 1}, {'timestamp': '1'}),
                                         ({'timestamp': 1}, {}),
                                         ({}, {'timestamp': 1})])
def test_normalization_never_hides_types_or_presence(before, after):
    result = DiffEngine().compare(response(before), response(after))
    assert 'json_field' in kinds(result)
    assert not next(e for e in result.relevant_evidence if e.kind == 'body').details['normalized_json_equal']


def test_selected_semantics_and_list_order_are_preserved():
    result = DiffEngine().compare(response({'role': 'user', 'items': [1, 2]}),
                                  response({'role': 'admin', 'items': [2, 1]}))
    assert any(e.field == '/role' for e in result.relevant_evidence)
    assert any(e.field == '/items/0' for e in result.relevant_evidence)


def test_sensitive_presence_and_ownership_still_visible_when_bodies_match():
    result = DiffEngine().compare(response({'owner_id': 1, 'email': 'secret@example.invalid'}),
                                  response({'owner_id': 1, 'email': 'secret@example.invalid'}))
    assert {'ownership_indicator', 'sensitive_indicator'} <= kinds(result)
    assert result.total_differences == 0
    assert result.confidence == 0
    assert 'secret@example.invalid' not in repr(result)


def test_randomized_paths_must_be_explicit_and_cannot_hide_ownership():
    result = DiffEngine(randomized_paths=[('noise',), ('owner_id',)]).compare(
        response({'noise': 'a', 'owner_id': 'a'}), response({'noise': 'b', 'owner_id': 'b'}))
    assert {'volatile_field', 'ownership'} <= kinds(result)
    assert next(e for e in result.relevant_evidence if e.kind == 'ownership').details['normalized'] is False


def test_unknown_json_keys_are_not_exported():
    result = DiffEngine().compare(response({'customer-secret-key': 1}), response({'customer-secret-key': 2}))
    assert 'customer-secret-key' not in repr(result)


def test_timing_needs_repeated_comparable_finite_samples():
    raw_a = HttpResponse(200, {}, 'same', 'http://127.0.0.1', .1)
    raw_b = HttpResponse(200, {}, 'same', 'http://127.0.0.1', 5)
    assert 'timing' not in kinds(DiffEngine().compare(raw_a, raw_b))
    result = DiffEngine().compare(response('same', timing_samples=(.1, .11, .12), timing_context='loopback-control'),
                                  response('same', timing_samples=(1., 1.1, 1.2), timing_context='loopback-control'))
    assert 'timing' in kinds(result)
    assert any('jitter' in reason for reason in result.false_positive_considerations)
    for samples, context in [((float('nan'), 1., 2.), 'loopback-control'), ((1., 2.), 'loopback-control'),
                             ((1., 2., 3.), 'other-context')]:
        result = DiffEngine().compare(response('same', timing_samples=(.1, .11, .12), timing_context='loopback-control'),
                                      response('same', timing_samples=samples, timing_context=context))
        assert 'timing' not in kinds(result)


def test_limits_never_claim_full_equality_or_silently_drop_evidence():
    engine = DiffEngine(max_evidence=2, max_nodes=3, similarity_chars=32)
    result = engine.compare(response({str(i): i for i in range(20)}), response({str(i): i + 1 for i in range(20)}))
    assert result.omitted_evidence_count > 0
    assert any('structure_limit' in note for note in result.limitations)
    assert result.confidence <= .4
    result = DiffEngine(max_json_chars=10).compare(response('a' * 100), response('a' * 99 + 'b'))
    assert 'body' in kinds(result)
    assert any('size_limit' in note for note in result.limitations)


def test_header_case_and_json_object_order_do_not_create_semantic_difference():
    result = DiffEngine().compare(response('{"a":1,"b":2}', headers={'Content-Type': 'application/json'}),
                                  response('{"b":2,"a":1}', headers={'content-type': 'application/json'}))
    assert kinds(result) == {'body'}
    assert result.relevant_evidence[0].details['normalized_json_equal']


def test_har_duplicate_headers_and_binary_reference_are_preserved():
    baseline = {'status': 200, 'headers': [{'name': 'Set-Cookie', 'value': 'a'}, {'name': 'Set-Cookie', 'value': 'b'}],
                'content': {'mimeType': 'image/png', 'reference_only': True}}
    changed = {**baseline, 'headers': [{'name': 'Set-Cookie', 'value': 'b'}]}
    result = DiffEngine().compare(baseline, changed)
    assert 'header' in kinds(result)
    assert any('truncated_response' in note for note in result.limitations)


@pytest.mark.parametrize('malformed', ['{"role":"user","role":"admin"}', '{"amount":NaN}'])
def test_ambiguous_json_cannot_be_normalized_into_equality(malformed):
    result = DiffEngine().compare(response(malformed), response('{"role":"admin"}'))
    assert 'json_parse_behavior' in kinds(result)
    assert not next(e for e in result.relevant_evidence if e.kind == 'body').details['normalized_json_equal']


def test_changed_binary_reference_is_visible_without_raw_binary():
    baseline = {'status': 200, 'content': {'reference_only': True, 'sha256': 'a' * 64}}
    changed = {'status': 200, 'content': {'reference_only': True, 'sha256': 'b' * 64}}
    result = DiffEngine().compare(baseline, changed)
    assert 'body' in kinds(result)
    assert result.total_differences > 0
    assert result.limitations


def test_invalid_status_is_rejected_before_it_can_enter_public_evidence():
    with pytest.raises(ValueError, match='invalid_response_snapshot'):
        DiffEngine().compare({'status': 'secret-status', 'body': ''}, {'status': 200, 'body': ''})
