BEGIN;
-- Product source recovery and bounded queue accounting. Audit/Ledger remain separate owners.
CREATE SCHEMA mdm_audit;
REVOKE ALL ON SCHEMA mdm_audit FROM PUBLIC;
CREATE TABLE mdm_audit.receipts (
    tenant_id uuid NOT NULL,
    source_id text NOT NULL,
    event_id text NOT NULL,
    fingerprint bytea NOT NULL CHECK (octet_length(fingerprint)=32),
    source_bytes bytea NOT NULL CHECK (octet_length(source_bytes) BETWEEN 1 AND 262144),
    message_id text NOT NULL CHECK (octet_length(message_id) BETWEEN 1 AND 255),
    projected_at bigint CHECK (projected_at IS NULL OR projected_at>=0),
    reserved boolean NOT NULL,
    enqueued_at bigint NOT NULL CHECK (enqueued_at>=0),
    PRIMARY KEY (tenant_id, source_id, event_id)
);
CREATE INDEX receipts_backlog ON mdm_audit.receipts(tenant_id,source_id,enqueued_at) WHERE projected_at IS NULL;
CREATE TABLE mdm_audit.backlog (
    tenant_id uuid NOT NULL,
    source_id text NOT NULL CHECK (source_id IN ('mdm.business','mdm.request')),
    events bigint NOT NULL DEFAULT 0,
    bytes bigint NOT NULL DEFAULT 0,
    reserved_events bigint NOT NULL DEFAULT 0,
    reserved_bytes bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, source_id),
    CHECK (events>=0 AND bytes>=0 AND reserved_events>=0 AND reserved_bytes>=0)
);
ALTER TABLE mdm_audit.receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_audit.receipts FORCE ROW LEVEL SECURITY;
ALTER TABLE mdm_audit.backlog ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_audit.backlog FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_audit.receipts
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id',true),'')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY tenant ON mdm_audit.backlog
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id',true),'')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON ALL TABLES IN SCHEMA mdm_audit FROM PUBLIC;
COMMIT;
