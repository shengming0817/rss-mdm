BEGIN;
-- Product operation recovery only. Audit schema remains owned by rss-audit.
CREATE SCHEMA mdm_audit;
REVOKE ALL ON SCHEMA mdm_audit FROM PUBLIC;
CREATE TABLE mdm_audit.receipts (
    tenant_id uuid NOT NULL,
    source_id text NOT NULL,
    event_id text NOT NULL,
    fingerprint bytea NOT NULL CHECK (octet_length(fingerprint)=32),
    canonical bytea NOT NULL CHECK (octet_length(canonical) BETWEEN 1 AND 131072),
    PRIMARY KEY (tenant_id, source_id, event_id)
);
ALTER TABLE mdm_audit.receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_audit.receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_audit.receipts
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id',true),'')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON mdm_audit.receipts FROM PUBLIC;

COMMIT;
