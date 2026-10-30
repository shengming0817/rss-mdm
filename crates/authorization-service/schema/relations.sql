-- Fresh installation: authorization-service owns these objects.
BEGIN;
SET LOCAL check_function_bodies = false;

GRANT SELECT,INSERT ON TABLE mdm_access.authorization_initializations TO mdm_access;

GRANT SELECT,INSERT ON TABLE mdm_access.authorization_operations TO mdm_access;

GRANT SELECT,INSERT ON TABLE mdm_access.authorization_rules TO mdm_access;
GRANT SELECT ON TABLE mdm_access.authorization_rules TO mdm_command_runtime;
GRANT SELECT ON TABLE mdm_access.authorization_rules TO mdm_inventory_runtime,mdm_scope_runtime,mdm_policy_runtime,mdm_resource_runtime,mdm_software_runtime,mdm_content_runtime,mdm_telemetry_runtime,mdm_software_driver;

GRANT UPDATE(revision) ON TABLE mdm_access.authorization_rules TO mdm_access;

GRANT UPDATE(document) ON TABLE mdm_access.authorization_rules TO mdm_access;

GRANT SELECT,INSERT ON TABLE mdm_access.user_groups TO mdm_access;
GRANT SELECT ON TABLE mdm_access.user_groups TO mdm_command_runtime;
GRANT SELECT ON TABLE mdm_access.user_groups TO mdm_inventory_runtime,mdm_scope_runtime,mdm_policy_runtime,mdm_resource_runtime,mdm_software_runtime,mdm_content_runtime,mdm_telemetry_runtime,mdm_software_driver;

GRANT UPDATE(revision) ON TABLE mdm_access.user_groups TO mdm_access;

GRANT UPDATE(document) ON TABLE mdm_access.user_groups TO mdm_access;
GRANT USAGE ON SCHEMA mdm_access TO mdm_identity_runtime;
GRANT SELECT ON mdm_access.authorization_rules,mdm_access.user_groups,mdm_access.authorization_initializations TO mdm_identity_runtime;
GRANT SELECT,INSERT ON mdm_access.api_keys,mdm_access.api_network_policy TO mdm_access;
GRANT UPDATE(revision,authority_revision,credential_revision,metadata,secret_digest,revoked) ON mdm_access.api_keys TO mdm_access;
GRANT UPDATE(revision,networks) ON mdm_access.api_network_policy TO mdm_access;
GRANT SELECT ON mdm_access.api_keys TO mdm_command_runtime,mdm_inventory_runtime,mdm_scope_runtime,mdm_policy_runtime,mdm_resource_runtime,mdm_software_runtime,mdm_content_runtime,mdm_telemetry_runtime,mdm_software_driver,mdm_identity_runtime;
ALTER TABLE mdm_access.api_network_policy ADD CONSTRAINT api_network_policy_installation_fk FOREIGN KEY (tenant_id) REFERENCES public.mdm_installation(management_tenant_id);
COMMIT;

GRANT USAGE ON SCHEMA mdm_access TO mdm_resource_runtime,mdm_software_runtime,mdm_content_runtime;
