BEGIN;
CREATE TABLE mdm_windows.entra_web_flows (
 expected_epoch bigint NOT NULL DEFAULT current_setting('rss.execution_epoch')::bigint CHECK(expected_epoch>0),
 tenant_id uuid NOT NULL,
 id uuid NOT NULL,
 cookie_digest text NOT NULL CHECK(cookie_digest ~ '^[0-9a-f]{64}$'),
 sealed bytea NOT NULL CHECK(octet_length(sealed)<=65536),
 expires_at timestamptz NOT NULL,
 accepted boolean,
 PRIMARY KEY(tenant_id,id)
);
ALTER TABLE mdm_windows.entra_web_flows ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_windows.entra_web_flows FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_windows.entra_web_flows USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY expired_only ON mdm_windows.entra_web_flows AS RESTRICTIVE FOR DELETE USING(expires_at<clock_timestamp());
GRANT SELECT,INSERT,DELETE ON mdm_windows.entra_web_flows TO mdm_access;
GRANT UPDATE(accepted) ON mdm_windows.entra_web_flows TO mdm_access;
COMMIT;

CREATE INDEX ON mdm_windows.entra_web_flows(id);
CREATE POLICY flow_locator ON mdm_windows.entra_web_flows FOR SELECT TO mdm_owner USING(true);
CREATE FUNCTION mdm_windows.entra_flow_scopes(flow uuid) RETURNS TABLE(tenant_id uuid,expected_epoch bigint) LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$ SELECT tenant_id,expected_epoch FROM mdm_windows.entra_web_flows WHERE id=flow ORDER BY tenant_id LIMIT 2 $$;
REVOKE ALL ON FUNCTION mdm_windows.entra_flow_scopes(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mdm_windows.entra_flow_scopes(uuid) TO mdm_access;
