-- Registration-owned policy; absent row is disabled.
BEGIN;
CREATE TABLE mdm_windows.entra_policy (
 tenant_id uuid PRIMARY KEY,
 revision bigint NOT NULL CHECK(revision>0),
 document jsonb NOT NULL CHECK(octet_length(document::text)<=131072)
);

ALTER TABLE mdm_windows.entra_policy ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_windows.entra_policy FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant ON mdm_windows.entra_policy USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);

GRANT UPDATE(revision,document) ON mdm_windows.entra_policy TO mdm_access;
GRANT SELECT,INSERT ON mdm_windows.entra_policy TO mdm_access;
COMMIT;
