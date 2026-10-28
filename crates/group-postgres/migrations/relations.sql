BEGIN;
GRANT USAGE ON SCHEMA mdm_group TO mdm_access;
GRANT EXECUTE ON FUNCTION mdm_group.group_current(uuid) TO mdm_access;
COMMIT;
