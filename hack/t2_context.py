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
                               tenant=tenant, peer=peer,
                               actors=[dict(tenant=tenant if side == 'tenant' else peer, role=role,
                                            login=role + '-' + (coordinate(run_id, (tenant if side == 'tenant' else peer) + '/' + role).replace('-', '')
                                                if role == 'admin' and 'stable_admin' in job.module.fixtures else namespace), principal=None)
                                       for side, role in job.module.actors],
                               fixtures=list(job.module.fixtures))
        validate(result[job.key])
    return result


def installation():
    return product_installation()


def registration_tenants(values):
    tenants = sorted({value[key] for value in values for key in ('tenant', 'peer')})
    if not 0 < len(tenants) <= 1024:
        raise ValueError('T2 registration requires between 1 and 1024 planned tenants')
    return tenants


def validate(value, *, ready=False):
    """Same wire contract as tests/support/context.rs; preparation may have partial admins."""
    strings = ('caseId', 'invocationId', 'namespace', 'tenant', 'peer')
    fields = {*strings, 'fixtures', 'actors'}
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
    fixtures = value['fixtures']
    if (not isinstance(fixtures, list) or any(not isinstance(item, str) or not item for item in fixtures)
            or len(set(fixtures)) != len(fixtures) or {'shared_worker', 'local_worker'} <= set(fixtures)):
        raise ValueError('invalid case context: fixtures')
    actors = value['actors']
    if not isinstance(actors, list):
        raise ValueError('invalid case context: actors')
    seen = set()
    for actor in actors:
        if (not isinstance(actor, dict) or set(actor) != {'tenant', 'role', 'login', 'principal'}
                or actor['tenant'] not in (value['tenant'], value['peer'])
                or actor['role'] not in ('admin', 'other')
                or not isinstance(actor['login'], str) or not actor['login']):
            raise ValueError('invalid case context: actor')
        key = (actor['tenant'], actor['role'])
        if key in seen:
            raise ValueError('duplicate case actor')
        seen.add(key)
        principal = actor['principal']
        if principal is None and not ready:
            continue
        try:
            if not isinstance(principal, str):
                raise ValueError()
            uuid.UUID(principal)
        except ValueError:
            raise ValueError('invalid case context: actor principal') from None
    if bool(actors) != ('identity' in fixtures):
        raise ValueError('invalid case context: identity actors')
    return value
