-- External administrator bootstrap for N12. Run once after backend roles exist.
CREATE ROLE mdm_group_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
CREATE ROLE mdm_management_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
GRANT mdm_group_runtime,mdm_policy_runtime,mdm_resource_runtime TO mdm_management_runtime;
-- The asset universe and missing fields must share one database snapshot.
-- Runtime admission rejects a session that overrides this isolation level.
ALTER ROLE mdm_management_runtime SET default_transaction_isolation='serializable';
