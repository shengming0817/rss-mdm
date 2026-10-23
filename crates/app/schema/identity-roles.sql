-- Administrator bootstrap for the embedded authentication instance, before rss-mdm migrate.
CREATE ROLE mdm_identity_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
CREATE ROLE mdm_identity_maintenance NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
CREATE ROLE mdm_identity_audit NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
CREATE ROLE mdm_audit_worker NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
-- The installer verifies both actual profiles under SET LOCAL ROLE. Neither profile inherits owner.
GRANT mdm_identity_runtime,mdm_identity_maintenance,mdm_identity_audit,mdm_audit_worker TO mdm_owner;

CREATE ROLE mdm_tenant_registry NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
CREATE ROLE mdm_identity_provisioning NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
GRANT mdm_tenant_registry,mdm_identity_provisioning TO mdm_owner;
