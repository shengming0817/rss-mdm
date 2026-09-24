"""Shared disposable installation coordinates; no product or filesystem state."""
INSTANCE = '33333333-3333-4333-8333-333333333333'
ADMIN = '44444444-4444-4444-8444-444444444444'
TENANTS = ['11111111-1111-4111-8111-111111111111','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb']

def installation():
    return dict(instance_id=INSTANCE,target=[1]*16,lineage=[2]*16,epoch=1,tenants=TENANTS)

