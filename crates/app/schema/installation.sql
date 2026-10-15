-- Stable installation identity and product-owned tenant CRUD.
BEGIN;
CREATE TABLE public.mdm_installation (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 instance_id uuid NOT NULL CHECK(instance_id<>'00000000-0000-0000-0000-000000000000'),
 management_tenant_id uuid NOT NULL UNIQUE CHECK(management_tenant_id<>'00000000-0000-0000-0000-000000000000'),
 target bytea NOT NULL CHECK(octet_length(target)=16),
 lineage bytea NOT NULL CHECK(octet_length(lineage)=16),
 audit_mode text NOT NULL CHECK(audit_mode IN ('plain','ledger'))
);
CREATE TABLE public.mdm_tenants (
 tenant_id uuid PRIMARY KEY CHECK(tenant_id<>'00000000-0000-0000-0000-000000000000'),
 initial_epoch bigint NOT NULL CHECK(initial_epoch>0),
 name text CHECK(name IS NULL OR (char_length(name)<=128 AND btrim(name,E' \t\n\r\013\f' || U&'\0085\00a0\1680\2000\2001\2002\2003\2004\2005\2006\2007\2008\2009\200a\2028\2029\202f\205f\3000')<>'')),
 notes text CHECK(notes IS NULL OR char_length(notes)<=2048),
 revision bigint NOT NULL DEFAULT 1 CHECK(revision>0),
 used boolean NOT NULL DEFAULT false,
 deleted boolean NOT NULL DEFAULT false,
 CHECK(NOT(used AND deleted))
);
CREATE TABLE public.mdm_tenant_operations (
 operation_id uuid PRIMARY KEY CHECK(operation_id<>'00000000-0000-0000-0000-000000000000'),
 tenant_id uuid NOT NULL REFERENCES public.mdm_tenants(tenant_id),
 action text NOT NULL CHECK(action IN ('create','update','delete','administrator_create')),
 request jsonb NOT NULL CHECK(jsonb_typeof(request)='object'),
 receipt jsonb NOT NULL CHECK(jsonb_typeof(receipt)='object'),
 operator jsonb NOT NULL CHECK(jsonb_typeof(operator)='object'),
 performed_by name NOT NULL DEFAULT session_user,
 performed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE public.mdm_tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.mdm_tenants FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON public.mdm_tenants USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY operator ON public.mdm_tenants TO mdm_owner USING(true) WITH CHECK(true);
ALTER TABLE public.mdm_installation ADD CONSTRAINT management_tenant
 FOREIGN KEY(management_tenant_id) REFERENCES public.mdm_tenants(tenant_id);
REVOKE ALL ON public.mdm_installation,public.mdm_tenants,public.mdm_tenant_operations FROM PUBLIC;
-- Transaction-bound authorization reads only the two immutable purpose coordinates.
GRANT SELECT(instance_id,management_tenant_id) ON public.mdm_installation TO mdm_flow_runtime,mdm_command_runtime;
GRANT SELECT ON public.mdm_installation,public.mdm_tenants TO mdm_access,mdm_identity_runtime,mdm_identity_maintenance;
GRANT USAGE ON SCHEMA rss_transactional_messaging TO mdm_access,mdm_identity_runtime,mdm_identity_maintenance;
GRANT SELECT ON rss_transactional_messaging.tenant_epoch TO mdm_access,mdm_identity_runtime,mdm_identity_maintenance;
-- Narrow capability: marking use never changes metadata, revisions, or epochs.
CREATE FUNCTION public.claim_tenant_use(tenant uuid, expected_epoch bigint, instance uuid, expected_target bytea, expected_lineage bytea, expected_audit_mode text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $tenant_use$
BEGIN
 IF current_setting('transaction_isolation') <> 'read committed' THEN
  RAISE EXCEPTION 'tenant use requires read committed';
 END IF;
 PERFORM pg_catalog.pg_advisory_xact_lock(2346);
 PERFORM pg_catalog.set_config('rss.tenant_id', tenant::text, true);
 IF NOT EXISTS(SELECT 1 FROM public.mdm_installation i WHERE i.singleton AND i.instance_id=instance AND i.target=expected_target AND i.lineage=expected_lineage AND i.audit_mode=expected_audit_mode)
 OR NOT EXISTS(SELECT 1 FROM public.mdm_tenants t JOIN rss_transactional_messaging.tenant_epoch e USING(tenant_id) WHERE t.tenant_id=tenant AND NOT t.deleted AND e.epoch=expected_epoch) THEN
  RETURN false;
 END IF;
 UPDATE public.mdm_tenants SET used=true WHERE tenant_id=tenant AND NOT used;
 RETURN true;
END
$tenant_use$;
ALTER FUNCTION public.claim_tenant_use(uuid,bigint,uuid,bytea,bytea,text) OWNER TO mdm_owner;
REVOKE ALL ON FUNCTION public.claim_tenant_use(uuid,bigint,uuid,bytea,bytea,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.claim_tenant_use(uuid,bigint,uuid,bytea,bytea,text) TO mdm_access,mdm_identity_runtime,mdm_identity_maintenance;
COMMIT;
