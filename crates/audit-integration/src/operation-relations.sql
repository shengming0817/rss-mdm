-- Fresh installation: audit owns these objects.
BEGIN;
SET LOCAL check_function_bodies = false;

GRANT SELECT,INSERT ON TABLE mdm_planning.operations TO mdm_flow_runtime;

COMMIT;
