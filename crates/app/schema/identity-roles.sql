-- Administrator bootstrap for the embedded authentication instance, before rss-mdm migrate.
CREATE ROLE mdm_identity_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
CREATE ROLE mdm_identity_maintenance NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
-- The installer verifies both actual profiles under SET LOCAL ROLE. Neither profile inherits owner.
GRANT mdm_identity_runtime,mdm_identity_maintenance TO mdm_owner;
