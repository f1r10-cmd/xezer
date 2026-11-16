"""Owner-only confirmation metadata; this module never grants test authorization."""
from copy import deepcopy
from fnmatch import fnmatchcase
import re
from urllib.parse import urlsplit

from .auth_config import origin


def validate_policies(value):
    if not isinstance(value, list):
        raise ValueError('auth_resource_policies_must_be_list')
    result, names = [], set()
    keys = {'id', 'origin', 'path_pattern', 'owner_field', 'object_id_field',
            'protected_fields', 'roles', 'access_policy'}
    for item in value:
        if not isinstance(item, dict) or set(item) != keys:
            raise ValueError('auth_resource_policy_fields_required')
        item = deepcopy(item)
        if not isinstance(item['id'], str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,80}', item['id']) or item['id'] in names:
            raise ValueError('invalid_or_duplicate_resource_policy_id')
        names.add(item['id'])
        parts = urlsplit(item['origin'])
        if parts.path not in ('', '/') or parts.query or parts.fragment:
            raise ValueError('resource_policy_origin_required')
        item['origin'] = origin(item['origin'])
        if not isinstance(item['path_pattern'], str) or not item['path_pattern'].startswith('/') or len(item['path_pattern']) > 512:
            raise ValueError('invalid_resource_path_pattern')
        if item['access_policy'] != 'owner_only':
            raise ValueError('unsupported_resource_access_policy')
        if not isinstance(item['roles'], list) or not item['roles'] or any(
                not isinstance(role, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,80}', role) for role in item['roles']):
            raise ValueError('resource_policy_roles_required')
        fields = item['protected_fields']
        if not isinstance(fields, list) or not fields or len(fields) > 32:
            raise ValueError('protected_fields_required')
        for name in [item['owner_field'], item['object_id_field'], *fields]:
            if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.]{0,100}', name):
                raise ValueError('invalid_resource_field')
        if len(set(fields)) != len(fields) or set(fields) & {item['owner_field'], item['object_id_field']}:
            raise ValueError('protected_fields_must_be_distinct_from_identifiers')
        result.append(item)
    return result


def matching_policies(policies, url):
    return [policy for policy in policies if origin(policy['origin']) == origin(url)
            and fnmatchcase(urlsplit(url).path or '/', policy['path_pattern'])]
