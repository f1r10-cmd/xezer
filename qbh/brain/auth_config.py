"""Credential references only; no raw passwords or session tokens in YAML."""
from copy import deepcopy
import re
from urllib.parse import urlsplit

ALLOWED = {'name', 'role', 'login_url', 'login_method', 'login_fields', 'login_format',
           'verify_url', 'subject_field', 'token_field', 'session_ttl_seconds'}


def origin(url):
    if not isinstance(url, str) or not url:
        raise ValueError("invalid_auth_url")
    parts = urlsplit(url)
    if parts.scheme not in {'http', 'https'} or not parts.hostname or parts.username or parts.password:
        raise ValueError('invalid_auth_url')
    try:
        port = parts.port or (443 if parts.scheme == 'https' else 80)
    except ValueError:
        raise ValueError('invalid_auth_url') from None
    return f'{parts.scheme}://{parts.hostname.lower()}:{port}'


def validate_contexts(value):
    if not isinstance(value, list):
        raise ValueError('auth_contexts_must_be_list')
    result, names = [], set()
    for item in value:
        if not isinstance(item, dict) or item.keys() - ALLOWED:
            raise ValueError('unsupported_auth_context_fields')
        item = deepcopy(item)
        for key in ('name', 'role'):
            if not isinstance(item.get(key), str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,80}', item[key]):
                raise ValueError('invalid_auth_context_name_or_role')
        if item['name'] in names:
            raise ValueError('duplicate_auth_context_name')
        names.add(item['name'])
        login_origin = origin(item.get('login_url', ''))
        item.setdefault('login_method', 'POST')
        if item['login_method'] not in {'GET', 'POST'}:
            raise ValueError('unsupported_login_method')
        fields = item.get('login_fields')
        if not isinstance(fields, dict) or not fields:
            raise ValueError('credential_references_required')
        field_names = set()
        for key, reference in fields.items():
            if not isinstance(key, str):
                raise ValueError('credential_reference_name_required')
            suffix = '_env' if key.endswith('_env') else '_vault_ref' if key.endswith('_vault_ref') else ''
            if not suffix:
                raise ValueError('inline_credentials_forbidden')
            name = key[:-len(suffix)]
            if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,79}', name) or name in field_names:
                raise ValueError('duplicate_or_invalid_login_field')
            field_names.add(name)
            if suffix == '_env' and (not isinstance(reference, str) or not re.fullmatch(r'[A-Z_][A-Z0-9_]*', reference)):
                raise ValueError('invalid_credential_env_reference')
            if suffix == '_vault_ref' and (type(reference) is not int or reference < 1):
                raise ValueError('invalid_credential_vault_reference')
        item.setdefault('login_format', 'json')
        if item['login_format'] not in {'json', 'form', 'basic'}:
            raise ValueError('invalid_login_format')
        if item['login_format'] == 'basic' and field_names != {'username', 'password'}:
            raise ValueError('basic_auth_requires_username_and_password_references')
        if item.get('verify_url') and origin(item['verify_url']) != login_origin:
            raise ValueError('verification_origin_must_match_login')
        item.setdefault('subject_field', 'user.id')
        item.setdefault('token_field', 'access_token')
        for key in ('subject_field', 'token_field'):
            if not isinstance(item[key], str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.]{0,100}', item[key]):
                raise ValueError('invalid_auth_response_field')
        ttl = item.setdefault('session_ttl_seconds', 900)
        if type(ttl) is not int or ttl < 1 or ttl > 86400:
            raise ValueError('invalid_session_ttl')
        result.append(item)
    return result
