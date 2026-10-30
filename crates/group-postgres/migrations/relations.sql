BEGIN;
GRANT USAGE ON SCHEMA mdm_group TO mdm_access;
GRANT EXECUTE ON FUNCTION mdm_group.group_current(uuid) TO mdm_access;
GRANT USAGE ON SCHEMA mdm_group TO mdm_command_runtime;
GRANT SELECT ON mdm_group.groups,mdm_group.member_runs,mdm_group.member_changes TO mdm_command_runtime;
COMMIT;
