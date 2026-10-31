CREATE SCHEMA IF NOT EXISTS mdm_flow;
CREATE TABLE mdm_flow.native_protection (
    tenant_id uuid PRIMARY KEY,
    key_id text NOT NULL CHECK (key_id ~ '^[0-9a-f]{64}$')
);

ALTER TABLE mdm_flow.native_protection ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_flow.native_protection FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant ON mdm_flow.native_protection USING (tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK (tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON mdm_flow.native_protection TO mdm_command_runtime,mdm_policy_runtime;

GRANT USAGE ON SCHEMA mdm_flow TO mdm_command_runtime,mdm_policy_runtime;
