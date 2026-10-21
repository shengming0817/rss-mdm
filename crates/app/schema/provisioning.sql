-- Product provisioning extends the existing operation authority, not a second workflow store.
BEGIN;

GRANT UPDATE(receipt) ON public.mdm_tenant_operations TO mdm_tenant_registry;
COMMIT;
