BEGIN;
-- Explicit upgrade; old consent is invalidated before the strict runtime decoder is used.
-- Installation runs as the schema owner; tenant RLS is restored in the same transaction.
ALTER TABLE mdm_windows.entra_policy DISABLE ROW LEVEL SECURITY;
UPDATE mdm_windows.entra_policy
SET document=document || '{"termsText":"","enabled":false}'::jsonb, revision=revision+1;
ALTER TABLE mdm_windows.entra_policy ENABLE ROW LEVEL SECURITY;
CREATE TABLE mdm_windows.entra_web_flows (
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
