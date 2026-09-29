"""Required case coordinates, planned before installing any database."""
from __future__ import annotations
import uuid
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
                               fixtures=list(job.module.fixtures))
    return result


def installation(values):
    config = product_installation()
    config['tenants'] = sorted({value[key] for value in values for key in ('tenant', 'peer')})
    if not 0 < len(config['tenants']) <= 128:
        raise ValueError('T2 installation requires between 1 and 128 planned tenants')
    return config
