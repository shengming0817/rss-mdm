-- Fresh installation: agent-channel owns these objects.
BEGIN;
SET LOCAL check_function_bodies = false;

ALTER TABLE ONLY mdm_agent.bindings
    ADD CONSTRAINT agent_bindings_tenant_id_registration_fkey FOREIGN KEY (tenant_id, registration) REFERENCES mdm_access.registrations(tenant_id, id);

GRANT USAGE ON SCHEMA mdm_agent TO mdm_access;
GRANT USAGE ON SCHEMA mdm_agent TO mdm_flow_runtime;
GRANT USAGE ON SCHEMA mdm_agent TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_agent.bindings TO mdm_access;
GRANT SELECT ON TABLE mdm_agent.bindings TO mdm_flow_runtime;
GRANT SELECT ON TABLE mdm_agent.bindings TO mdm_command_runtime;
GRANT UPDATE(execution_context) ON TABLE mdm_agent.bindings TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_agent.operations TO mdm_access;
COMMIT;
