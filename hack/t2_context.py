"""Required case coordinates, planned before installing any database."""
from __future__ import annotations
import uuid
import re
from candidate_fixture import installation as product_installation


def coordinate(run_id, value):
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f'rss-mdm/t2/{run_id}/{value}'))


def contexts(run_id, jobs):
    result = {}
    for job in jobs:
        scope = job.module.scope
        observation = job.id + '/' + str(job.invocation)
        tenant = coordinate(run_id, 'objects' if scope == 'objects' else observation)
        peer = coordinate(run_id, observation + '/peer' if scope == 'pair' else 'foreign')
        namespace = coordinate(run_id, job.id + '/' + str(job.invocation)).replace('-', '')
        result[job.key] = dict(caseId=job.id, invocationId=job.key, namespace=namespace,
                               tenant=tenant, peer=peer, adminLogin='admin-' + namespace, otherLogin='other-' + namespace,
                               identityTenants=[tenant, peer] if scope == 'pair' else [tenant],
                               fixtures=list(job.module.fixtures), admins={})
        validate(result[job.key])
    return result


def installation(values):
    config = product_installation()
    config['tenants'] = sorted({value[key] for value in values for key in ('tenant', 'peer')})
    if not 0 < len(config['tenants']) <= 128:
        raise ValueError('T2 installation requires between 1 and 128 planned tenants')
    return config


def validate(value, *, ready=False):
    """Same wire contract as tests/support/context.rs; preparation may have partial admins."""
    strings = ('caseId', 'invocationId', 'namespace', 'tenant', 'peer', 'adminLogin', 'otherLogin')
    fields = {*strings, 'identityTenants', 'fixtures', 'admins'}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError('invalid case context fields')
    for field in strings:
        if not isinstance(value[field], str) or not value[field]:
            raise ValueError('invalid case context: ' + field)
    if not re.fullmatch('[0-9a-fA-F]{32}', value['namespace']):
        raise ValueError('invalid case context: namespace')
    for field in ('tenant', 'peer'):
        try:
            uuid.UUID(value[field])
        except ValueError:
            raise ValueError('invalid case context: ' + field) from None
    if value['tenant'] == value['peer']:
        raise ValueError('invalid case context: peer')
    if value['identityTenants'] not in ([value['tenant']], [value['tenant'], value['peer']]):
        raise ValueError('invalid case context: identityTenants')
    fixtures = value['fixtures']
    if (not isinstance(fixtures, list) or any(not isinstance(item, str) or not item for item in fixtures)
            or len(set(fixtures)) != len(fixtures) or {'shared_worker', 'local_worker'} <= set(fixtures)):
        raise ValueError('invalid case context: fixtures')
    admins = value['admins']
    if not isinstance(admins, dict) or not set(admins) <= set(value['identityTenants']):
        raise ValueError('invalid case context: admins')
    for principal in admins.values():
        try:
            if not isinstance(principal, str):
                raise ValueError()
            uuid.UUID(principal)
        except ValueError:
            raise ValueError('invalid case context: admins') from None
    if ready and 'identity' in fixtures and set(admins) != set(value['identityTenants']):
        raise ValueError('invalid case context: admins not prepared')
    return value
