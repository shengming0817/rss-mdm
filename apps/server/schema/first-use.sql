-- Product setup intent only; domain configuration remains with its existing owner.
BEGIN;
CREATE SCHEMA mdm_first_use;
CREATE TABLE mdm_first_use.intents (
 tenant_id uuid PRIMARY KEY REFERENCES public.mdm_tenants(tenant_id),
 revision bigint NOT NULL CHECK(revision>0),
 intent jsonb NOT NULL CHECK(jsonb_typeof(intent)='object')
);
CREATE TABLE mdm_first_use.operations (
 tenant_id uuid NOT NULL REFERENCES public.mdm_tenants(tenant_id),
 actor text NOT NULL,
 operation_id uuid NOT NULL CHECK(operation_id<>'00000000-0000-0000-0000-000000000000'),
 instance_id uuid NOT NULL,
 fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),
 receipt jsonb NOT NULL CHECK(jsonb_typeof(receipt)='object'),
 PRIMARY KEY(tenant_id,actor,operation_id)
);
ALTER TABLE mdm_first_use.intents ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_first_use.intents FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_first_use.intents USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
ALTER TABLE mdm_first_use.operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_first_use.operations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_first_use.operations USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON SCHEMA mdm_first_use FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA mdm_first_use FROM PUBLIC;
GRANT USAGE ON SCHEMA mdm_first_use TO mdm_access;
GRANT SELECT,INSERT ON mdm_first_use.intents,mdm_first_use.operations TO mdm_access;
GRANT UPDATE(revision,intent) ON mdm_first_use.intents TO mdm_access;
COMMIT;
