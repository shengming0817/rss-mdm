-- External administrator bootstrap for N12. Run once after backend roles exist.
CREATE ROLE mdm_group_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
CREATE ROLE mdm_planning_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
GRANT mdm_group_runtime,mdm_policy_runtime,mdm_resource_runtime TO mdm_planning_runtime;
-- Asset pages read immutable history at their persisted watermark; aggregate writes
-- retain their domain locks. Audit recovery needs a fresh statement snapshot after
-- the Audit/Ledger heads have serialized the previous transaction.
ALTER ROLE mdm_planning_runtime SET default_transaction_isolation='read committed';
