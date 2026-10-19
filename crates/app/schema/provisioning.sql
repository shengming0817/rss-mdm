-- Product provisioning extends the existing operation authority, not a second workflow store.
BEGIN;
ALTER TABLE public.mdm_tenant_operations DROP CONSTRAINT mdm_tenant_operations_action_check;
ALTER TABLE public.mdm_tenant_operations ADD CONSTRAINT mdm_tenant_operations_action_check
 CHECK(action IN ('create','update','delete','administrator_create','provision'));
GRANT UPDATE(receipt) ON public.mdm_tenant_operations TO mdm_tenant_registry;
COMMIT;
