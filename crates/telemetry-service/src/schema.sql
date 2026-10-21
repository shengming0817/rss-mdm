-- Product admission metadata only. Pending content belongs to RSS Outbox.
CREATE SCHEMA mdm_telemetry;
REVOKE ALL ON SCHEMA mdm_telemetry FROM PUBLIC;
CREATE TABLE mdm_telemetry.batches (
 tenant_id uuid NOT NULL, id uuid NOT NULL, device text NOT NULL,
 registration uuid NOT NULL, credential uuid NOT NULL, generation bigint NOT NULL,
 source text NOT NULL CHECK(source IN ('agent.native','agent.script','agent.osquery')), epoch uuid NOT NULL,
 policy uuid NOT NULL, policy_version uuid NOT NULL,
 input_digest bytea NOT NULL CHECK(octet_length(input_digest)=32),
 context_digest bytea NOT NULL CHECK(octet_length(context_digest)=32),
 fields text[] NOT NULL CHECK(cardinality(fields) BETWEEN 1 AND 64),
 received_at bigint NOT NULL CHECK(received_at>=0),
 delivery text NOT NULL CHECK(delivery IN ('pending','published','unknown','blocked')),
 first_observed bigint NOT NULL, last_observed bigint NOT NULL CHECK(last_observed>=first_observed),
 quality jsonb NOT NULL CHECK(jsonb_typeof(quality)='object'),
 observations uuid[] NOT NULL CHECK(cardinality(observations) BETWEEN 1 AND 4096),current_assets boolean NOT NULL,
 PRIMARY KEY(tenant_id,id)
);
CREATE INDEX pending_registration ON mdm_telemetry.batches(tenant_id,registration) WHERE delivery<>'published';
CREATE TABLE mdm_telemetry.rate_windows (
 tenant_id uuid NOT NULL, minute bigint NOT NULL, batches bigint NOT NULL CHECK(batches>0), bytes bigint NOT NULL CHECK(bytes>0),
 PRIMARY KEY(tenant_id)
);
ALTER TABLE mdm_telemetry.batches ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_telemetry.batches FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_telemetry.batches USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
ALTER TABLE mdm_telemetry.rate_windows ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_telemetry.rate_windows FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_telemetry.rate_windows USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON ALL TABLES IN SCHEMA mdm_telemetry FROM PUBLIC;
GRANT USAGE ON SCHEMA mdm_telemetry TO mdm_flow_runtime;
GRANT SELECT,INSERT ON mdm_telemetry.batches TO mdm_flow_runtime;
GRANT UPDATE(delivery) ON mdm_telemetry.batches TO mdm_flow_runtime;
GRANT SELECT,INSERT,UPDATE ON mdm_telemetry.rate_windows TO mdm_flow_runtime;

-- Confirmed progress of the catalog projection; definitions remain owned by Inventory/RSS.
CREATE TABLE mdm_telemetry.definition_progress (
 tenant_id uuid NOT NULL, field text NOT NULL, version bigint NOT NULL CHECK(version>=0), digest bytea CHECK(octet_length(digest)=32), retired_through bigint NOT NULL DEFAULT 0 CHECK(retired_through>=0 AND retired_through<=version),
 PRIMARY KEY(tenant_id,field), CHECK((version=0)=(digest IS NULL))
);
ALTER TABLE mdm_telemetry.definition_progress ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_telemetry.definition_progress FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_telemetry.definition_progress USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON mdm_telemetry.definition_progress FROM PUBLIC;
GRANT SELECT,INSERT ON mdm_telemetry.definition_progress TO mdm_flow_runtime;
GRANT UPDATE(version,digest,retired_through) ON mdm_telemetry.definition_progress TO mdm_flow_runtime;

-- Admission cardinality only: no sampled values and no second series store.
CREATE TABLE mdm_telemetry.resources (
 tenant_id uuid NOT NULL, device text NOT NULL, field text NOT NULL, resource text NOT NULL,
 PRIMARY KEY(tenant_id,device,field,resource)
);
ALTER TABLE mdm_telemetry.resources ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_telemetry.resources FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_telemetry.resources USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON mdm_telemetry.resources FROM PUBLIC;
GRANT SELECT,INSERT ON mdm_telemetry.resources TO mdm_flow_runtime;

-- Idempotent management intent and the last confirmed bounded step, never sampled data.
CREATE TABLE mdm_telemetry.maintenance (
 tenant_id uuid NOT NULL, id uuid NOT NULL, binding bytea NOT NULL CHECK(octet_length(binding)=32),
 result jsonb, PRIMARY KEY(tenant_id,id)
);
ALTER TABLE mdm_telemetry.maintenance ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_telemetry.maintenance FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_telemetry.maintenance USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON mdm_telemetry.maintenance FROM PUBLIC;
GRANT SELECT,INSERT ON mdm_telemetry.maintenance TO mdm_flow_runtime;
GRANT UPDATE(result) ON mdm_telemetry.maintenance TO mdm_flow_runtime;

-- Scheduling coordinates only; immutable field history and RSS remain authoritative.
CREATE TABLE mdm_telemetry.retention_targets (
 tenant_id uuid NOT NULL,id bytea NOT NULL CHECK(octet_length(id)=32),
 device text NOT NULL,field text NOT NULL,version bigint NOT NULL CHECK(version>0),resource text NOT NULL,
 stream jsonb NOT NULL,dimensions jsonb NOT NULL,
 due_at bigint NOT NULL CHECK(due_at>=0),next_check bigint NOT NULL CHECK(next_check>=0),
 phase smallint NOT NULL CHECK(phase IN(0,1,2)),result jsonb,PRIMARY KEY(tenant_id,id)
);
CREATE INDEX retention_due ON mdm_telemetry.retention_targets(tenant_id,next_check,id);
ALTER TABLE mdm_telemetry.retention_targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_telemetry.retention_targets FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_telemetry.retention_targets USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON mdm_telemetry.retention_targets FROM PUBLIC;
GRANT SELECT,INSERT ON mdm_telemetry.retention_targets TO mdm_flow_runtime;
GRANT UPDATE(due_at,next_check,phase,result) ON mdm_telemetry.retention_targets TO mdm_flow_runtime;

-- Reception identity only. Values remain exclusively in the pending Outbox and destination owners.
CREATE TABLE mdm_telemetry.observation_receipts (
 tenant_id uuid NOT NULL,id uuid NOT NULL,digest bytea NOT NULL CHECK(octet_length(digest)=32),
 PRIMARY KEY(tenant_id,id)
);
ALTER TABLE mdm_telemetry.observation_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_telemetry.observation_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_telemetry.observation_receipts USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON mdm_telemetry.observation_receipts FROM PUBLIC;
GRANT SELECT,INSERT ON mdm_telemetry.observation_receipts TO mdm_flow_runtime;

-- App-owned fixed installation/admission identity, shared by every tenant replica.
CREATE TABLE mdm_telemetry.storage_binding (
 tenant_id uuid PRIMARY KEY,binding bytea NOT NULL CHECK(octet_length(binding)=32)
);
ALTER TABLE mdm_telemetry.storage_binding ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_telemetry.storage_binding FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_telemetry.storage_binding USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON mdm_telemetry.storage_binding FROM PUBLIC;
GRANT SELECT,INSERT ON mdm_telemetry.storage_binding TO mdm_flow_runtime;

-- Device-reported bounded diagnostics, not field coverage or sampled values.
CREATE TABLE mdm_telemetry.gap_reports (
 tenant_id uuid NOT NULL,id uuid NOT NULL,device text NOT NULL,
 registration uuid NOT NULL,generation bigint NOT NULL CHECK(generation>0),
 input_digest bytea NOT NULL CHECK(octet_length(input_digest)=32),
 report jsonb NOT NULL CHECK(jsonb_typeof(report)='object'),
 received_at bigint NOT NULL CHECK(received_at>=0),
 expires_at bigint NOT NULL CHECK(expires_at>received_at),
 PRIMARY KEY(tenant_id,id)
);
CREATE INDEX gap_expiry ON mdm_telemetry.gap_reports(tenant_id,expires_at,id);
CREATE INDEX gap_registration ON mdm_telemetry.gap_reports(tenant_id,registration);
CREATE INDEX gap_device_receipt ON mdm_telemetry.gap_reports(tenant_id,device,received_at,id);
ALTER TABLE mdm_telemetry.gap_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_telemetry.gap_reports FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_telemetry.gap_reports USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON mdm_telemetry.gap_reports FROM PUBLIC;
GRANT SELECT,INSERT,DELETE ON mdm_telemetry.gap_reports TO mdm_flow_runtime;
