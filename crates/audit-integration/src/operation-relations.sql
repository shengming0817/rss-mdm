-- Fresh installation: audit owns these objects.
BEGIN;
SET LOCAL check_function_bodies = false;

GRANT SELECT,INSERT ON TABLE mdm_planning.operations TO mdm_scope_runtime,mdm_policy_runtime,mdm_command_runtime;

COMMIT;
