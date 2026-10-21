-- App owns initialization intent/progress; domain owners retain their operation receipts.
CREATE SCHEMA mdm_initialization;
REVOKE ALL ON SCHEMA mdm_initialization FROM PUBLIC;
CREATE TABLE mdm_initialization.baselines (
 tenant_id uuid PRIMARY KEY,
 authority jsonb NOT NULL CHECK(octet_length(authority::text)<=131072),
 manifest jsonb NOT NULL CHECK(octet_length(manifest::text)<=4194304),
 completed jsonb NOT NULL DEFAULT '{}' CHECK(jsonb_typeof(completed)='object' AND octet_length(completed::text)<=131072),
 phase text NOT NULL DEFAULT 'pending' CHECK(phase IN('pending','blocked','configured')),
 blocked text CHECK(blocked IN('authorization','content','conflict','storage','outcome_unknown','telemetry_backend'))
);
ALTER TABLE mdm_initialization.baselines ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_initialization.baselines FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_initialization.baselines USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT USAGE ON SCHEMA mdm_initialization TO mdm_access,mdm_identity_provisioning;
GRANT SELECT,INSERT ON mdm_initialization.baselines TO mdm_access,mdm_identity_provisioning;
GRANT UPDATE(completed,phase,blocked) ON mdm_initialization.baselines TO mdm_access;
