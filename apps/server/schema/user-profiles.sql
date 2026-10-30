-- Product-owned mappings only. Identity remains the sole profile value owner.
BEGIN;
CREATE SCHEMA mdm_user_profiles;
CREATE TABLE mdm_user_profiles.definitions (
 tenant_id uuid NOT NULL REFERENCES public.mdm_tenants(tenant_id),
 field_id uuid NOT NULL CHECK(field_id<>'00000000-0000-0000-0000-000000000000'),
 revision bigint NOT NULL CHECK(revision>0),
 collected_after_micros bigint NOT NULL CHECK(collected_after_micros>=0),
 value jsonb CHECK(value IS NULL OR (jsonb_typeof(value)='object' AND octet_length(value::text)<=8192)),
 PRIMARY KEY(tenant_id,field_id)
);
CREATE UNIQUE INDEX definition_key ON mdm_user_profiles.definitions(tenant_id,(value->>'key')) WHERE value IS NOT NULL;
CREATE TABLE mdm_user_profiles.operations (
 tenant_id uuid NOT NULL REFERENCES public.mdm_tenants(tenant_id),
 actor text NOT NULL,
 instance_id uuid NOT NULL,
 operation_id uuid NOT NULL CHECK(operation_id<>'00000000-0000-0000-0000-000000000000'),
 fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),
 receipt jsonb NOT NULL CHECK(jsonb_typeof(receipt)='object'),
 PRIMARY KEY(tenant_id,actor,operation_id)
);
ALTER TABLE mdm_user_profiles.definitions ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_user_profiles.definitions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_user_profiles.definitions USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
ALTER TABLE mdm_user_profiles.operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_user_profiles.operations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_user_profiles.operations USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON SCHEMA mdm_user_profiles FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA mdm_user_profiles FROM PUBLIC;
GRANT USAGE ON SCHEMA mdm_user_profiles TO mdm_access;
GRANT SELECT,INSERT ON mdm_user_profiles.definitions,mdm_user_profiles.operations TO mdm_access;
GRANT UPDATE(revision,collected_after_micros,value) ON mdm_user_profiles.definitions TO mdm_access;
COMMIT;
