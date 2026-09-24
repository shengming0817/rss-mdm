-- Administrator bootstrap. Neither owner can log in or bypass tenant RLS.
CREATE ROLE mdm_audit_owner NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
CREATE ROLE mdm_ledger_owner NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
GRANT mdm_audit_owner,mdm_ledger_owner TO mdm_owner;
DO $$ BEGIN
 EXECUTE format('GRANT CREATE ON DATABASE %I TO mdm_audit_owner,mdm_ledger_owner',current_database());
END $$;
