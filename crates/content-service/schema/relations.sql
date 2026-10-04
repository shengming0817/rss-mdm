-- Fresh installation: content-service owns these objects.
BEGIN;
SET LOCAL check_function_bodies = false;

GRANT USAGE ON SCHEMA mdm_content TO mdm_flow_runtime;

GRANT SELECT,INSERT ON TABLE mdm_content.bindings TO mdm_flow_runtime;
GRANT USAGE ON SCHEMA mdm_content TO mdm_command_runtime;
GRANT SELECT,INSERT ON mdm_content.diagnostic_artifacts TO mdm_command_runtime;
GRANT SELECT ON mdm_content.diagnostic_artifacts TO mdm_flow_runtime;
COMMIT;
