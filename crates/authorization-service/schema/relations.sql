-- Fresh installation: authorization-service owns these objects.
BEGIN;
SET LOCAL check_function_bodies = false;

GRANT SELECT,INSERT ON TABLE mdm_access.authorization_initializations TO mdm_access;

GRANT SELECT,INSERT ON TABLE mdm_access.authorization_operations TO mdm_access;

GRANT SELECT,INSERT ON TABLE mdm_access.authorization_rules TO mdm_access;
GRANT SELECT ON TABLE mdm_access.authorization_rules TO mdm_command_runtime;
GRANT SELECT ON TABLE mdm_access.authorization_rules TO mdm_flow_runtime;

GRANT UPDATE(revision) ON TABLE mdm_access.authorization_rules TO mdm_access;

GRANT UPDATE(document) ON TABLE mdm_access.authorization_rules TO mdm_access;

GRANT SELECT,INSERT ON TABLE mdm_access.user_groups TO mdm_access;
GRANT SELECT ON TABLE mdm_access.user_groups TO mdm_command_runtime;
GRANT SELECT ON TABLE mdm_access.user_groups TO mdm_flow_runtime;

GRANT UPDATE(revision) ON TABLE mdm_access.user_groups TO mdm_access;

GRANT UPDATE(document) ON TABLE mdm_access.user_groups TO mdm_access;
COMMIT;
