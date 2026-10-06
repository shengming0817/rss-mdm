-- Stable installation identity and product-owned tenant CRUD.
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
 initial_epoch bigint NOT NULL CHECK(initial_epoch>0),
 name text CHECK(name IS NULL OR (char_length(name)<=128 AND btrim(name,E' \t\n\r\v\f' || U&'\0085\00a0\1680\2000\2001\2002\2003\2004\2005\2006\2007\2008\2009\200a\2028\2029\202f\205f\3000')<>'')),
 notes text CHECK(notes IS NULL OR char_length(notes)<=2048),
 revision bigint NOT NULL DEFAULT 1 CHECK(revision>0),
 used boolean NOT NULL DEFAULT false,
 deleted boolean NOT NULL DEFAULT false,
 CHECK(NOT(used AND deleted))
);
CREATE TABLE public.mdm_tenant_operations (
 operation_id uuid PRIMARY KEY CHECK(operation_id<>'00000000-0000-0000-0000-000000000000'),
 tenant_id uuid NOT NULL REFERENCES public.mdm_tenants(tenant_id),
 action text NOT NULL CHECK(action IN ('create','update','delete')),
 request jsonb NOT NULL CHECK(jsonb_typeof(request)='object'),
 receipt jsonb NOT NULL CHECK(jsonb_typeof(receipt)='object'),
 performed_by name NOT NULL DEFAULT session_user,
 performed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE public.mdm_tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.mdm_tenants FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON public.mdm_tenants USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY operator ON public.mdm_tenants TO mdm_owner USING(true) WITH CHECK(true);
REVOKE ALL ON public.mdm_installation,public.mdm_tenants,public.mdm_tenant_operations FROM PUBLIC;
GRANT SELECT ON public.mdm_installation,public.mdm_tenants TO mdm_access,mdm_identity_runtime,mdm_identity_maintenance;
GRANT USAGE ON SCHEMA rss_transactional_messaging TO mdm_access,mdm_identity_runtime,mdm_identity_maintenance;
GRANT SELECT ON rss_transactional_messaging.tenant_epoch TO mdm_access,mdm_identity_runtime,mdm_identity_maintenance;
COMMIT;
