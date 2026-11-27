-- Product runtime identities; no role aggregates all business writers.
CREATE ROLE mdm_group_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
ALTER ROLE mdm_group_runtime SET default_transaction_isolation='read committed';
CREATE ROLE mdm_observation_maintenance NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
CREATE ROLE mdm_inventory_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
ALTER ROLE mdm_inventory_runtime SET default_transaction_isolation='read committed';
CREATE ROLE mdm_scope_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
ALTER ROLE mdm_scope_runtime SET default_transaction_isolation='read committed';
CREATE ROLE mdm_policy_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
ALTER ROLE mdm_policy_runtime SET default_transaction_isolation='read committed';
CREATE ROLE mdm_resource_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
ALTER ROLE mdm_resource_runtime SET default_transaction_isolation='read committed';
CREATE ROLE mdm_software_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
ALTER ROLE mdm_software_runtime SET default_transaction_isolation='read committed';
CREATE ROLE mdm_content_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
ALTER ROLE mdm_content_runtime SET default_transaction_isolation='read committed';
CREATE ROLE mdm_telemetry_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
ALTER ROLE mdm_telemetry_runtime SET default_transaction_isolation='read committed';
CREATE ROLE mdm_scheduler_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
ALTER ROLE mdm_scheduler_runtime SET default_transaction_isolation='read committed';
CREATE ROLE mdm_scope_group_consumer NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
ALTER ROLE mdm_scope_group_consumer SET default_transaction_isolation='read committed';
GRANT mdm_group_runtime TO mdm_inventory_runtime;
CREATE ROLE mdm_asset_ingress_consumer NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
ALTER ROLE mdm_asset_ingress_consumer SET default_transaction_isolation='read committed';
CREATE ROLE mdm_wns_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
ALTER ROLE mdm_wns_runtime SET default_transaction_isolation='read committed';

DO $dispatch$
DECLARE login text;
BEGIN
 FOREACH login IN ARRAY string_to_array('{command_roles}', ',') LOOP
  EXECUTE format('CREATE ROLE %I NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION',login);
  EXECUTE format('ALTER ROLE %I SET default_transaction_isolation=%L',login,'read committed');
 END LOOP;
END $dispatch$;
