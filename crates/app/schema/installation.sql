-- Stable installation identity and product-owned mutable tenant registration.
BEGIN;
CREATE TABLE public.mdm_installation (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 instance_id uuid NOT NULL CHECK(instance_id<>'00000000-0000-0000-0000-000000000000'),
 target bytea NOT NULL CHECK(octet_length(target)=16),
 lineage bytea NOT NULL CHECK(octet_length(lineage)=16),
 audit_mode text NOT NULL CHECK(audit_mode IN ('plain','ledger'))
);
CREATE TABLE public.mdm_tenants (
 tenant_id uuid PRIMARY KEY CHECK(tenant_id<>'00000000-0000-0000-0000-000000000000'),
 initial_epoch bigint NOT NULL CHECK(initial_epoch>0)
);
CREATE TABLE public.mdm_tenant_registrations (
 operation_id uuid PRIMARY KEY CHECK(operation_id<>'00000000-0000-0000-0000-000000000000'),
 tenant_id uuid NOT NULL UNIQUE REFERENCES public.mdm_tenants(tenant_id),
 initial_epoch bigint NOT NULL CHECK(initial_epoch>0),
 request jsonb NOT NULL CHECK(jsonb_typeof(request)='object'),
 registered_by name NOT NULL DEFAULT session_user,
 registered_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE public.mdm_tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.mdm_tenants FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON public.mdm_tenants USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY operator ON public.mdm_tenants TO mdm_owner USING(true) WITH CHECK(true);
REVOKE ALL ON public.mdm_installation,public.mdm_tenants,public.mdm_tenant_registrations FROM PUBLIC;
GRANT SELECT ON public.mdm_installation,public.mdm_tenants TO mdm_access,mdm_identity_runtime,mdm_identity_maintenance;
GRANT SELECT ON rss_transactional_messaging.tenant_epoch TO mdm_access;
COMMIT;
