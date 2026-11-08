BEGIN;
CREATE TABLE mdm_access.agent_native_enrollments (
    tenant_id uuid NOT NULL
  , task uuid NOT NULL
  , attempt uuid NOT NULL
  , operation uuid NOT NULL
  , source_device text NOT NULL
  , request uuid NOT NULL
  , request_digest text NOT NULL
  , authority jsonb NOT NULL
  , PRIMARY KEY (tenant_id, task)
  , UNIQUE (tenant_id, request)
  , UNIQUE (tenant_id, operation)
  , FOREIGN KEY (tenant_id, request) REFERENCES mdm_access.requests (tenant_id, id)
  , FOREIGN KEY (tenant_id, source_device) REFERENCES mdm_access.devices (tenant_id, id)
);
ALTER TABLE mdm_access.agent_native_enrollments ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_access.agent_native_enrollments FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_access.agent_native_enrollments USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON mdm_access.agent_native_enrollments TO mdm_command_runtime;
GRANT SELECT ON mdm_access.agent_native_enrollments TO mdm_access;
GRANT SELECT,INSERT ON mdm_access.requests,mdm_access.grants TO mdm_command_runtime;

COMMIT;

GRANT USAGE ON SCHEMA mdm_agent_packages TO mdm_access,mdm_command_runtime,mdm_policy_runtime;
GRANT SELECT ON mdm_agent_packages.releases TO mdm_access,mdm_command_runtime,mdm_policy_runtime;
GRANT SELECT ON mdm_pki.certificates,mdm_pki.revocations TO mdm_access,mdm_command_runtime,mdm_policy_runtime;
