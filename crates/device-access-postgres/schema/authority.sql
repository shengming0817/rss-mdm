-- DA-exclusive receipts and current optional delivery/evidence authority. Fresh installation only.
CREATE TABLE rss_da.operations (
 tenant_id uuid NOT NULL,instance uuid NOT NULL,actor uuid NOT NULL,operation_id uuid NOT NULL,
 digest text NOT NULL CHECK(length(digest)=64),result text NOT NULL CHECK(octet_length(result)<=1048576),
 PRIMARY KEY(tenant_id,instance,actor,operation_id)
);
CREATE TABLE rss_da.agent_delivery (
 tenant_id uuid NOT NULL,da_device text NOT NULL,da_registration uuid NOT NULL,da_generation bigint NOT NULL CHECK(da_generation>0),
 agent_installation uuid NOT NULL,agent_device text NOT NULL,agent_registration uuid NOT NULL,agent_generation bigint NOT NULL CHECK(agent_generation>0),
 enabled boolean NOT NULL,revision bigint NOT NULL CHECK(revision>0),PRIMARY KEY(tenant_id,da_registration),
 FOREIGN KEY(tenant_id,da_registration) REFERENCES rss_da.registrations(tenant_id,id)
);
CREATE UNIQUE INDEX da_device_delivery_current ON rss_da.agent_delivery(tenant_id,da_device) WHERE enabled;
CREATE UNIQUE INDEX da_agent_delivery_current ON rss_da.agent_delivery(tenant_id,agent_installation,agent_registration) WHERE enabled;
CREATE TABLE rss_da.deployment_evidence (
 tenant_id uuid NOT NULL,registration uuid NOT NULL,generation bigint NOT NULL CHECK(generation>0),authority uuid NOT NULL,
 sequence bigint NOT NULL CHECK(sequence>0),fingerprint text NOT NULL CHECK(length(fingerprint)=64),payload text NOT NULL CHECK(length(payload)<=32768),signature text NOT NULL CHECK(length(signature)<=128),
 mandatory jsonb NOT NULL DEFAULT '{}'::jsonb CHECK(jsonb_typeof(mandatory)='object' AND octet_length(mandatory::text)<=2048),
 document jsonb NOT NULL CHECK(octet_length(document::text)<=32768),received_at bigint NOT NULL CHECK(received_at>=0),
 PRIMARY KEY(tenant_id,registration,generation,authority),FOREIGN KEY(tenant_id,registration) REFERENCES rss_da.registrations(tenant_id,id)
);
ALTER TABLE rss_da.operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_da.operations FORCE ROW LEVEL SECURITY;
ALTER TABLE rss_da.agent_delivery ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_da.agent_delivery FORCE ROW LEVEL SECURITY;
ALTER TABLE rss_da.deployment_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_da.deployment_evidence FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON rss_da.operations USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY tenant ON rss_da.agent_delivery USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY tenant ON rss_da.deployment_evidence USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON rss_da.operations,rss_da.agent_delivery,rss_da.deployment_evidence TO da_access;
GRANT UPDATE(da_generation,agent_installation,agent_device,agent_registration,agent_generation,enabled,revision) ON rss_da.agent_delivery TO da_access;
GRANT UPDATE(sequence,fingerprint,payload,signature,document,received_at,mandatory) ON rss_da.deployment_evidence TO da_access;
GRANT SELECT ON rss_da.agent_delivery,rss_da.deployment_evidence TO da_identity_runtime,da_command_runtime;
-- SELECT FOR SHARE locks require one update column; no evidence payload is writable by readers.
GRANT UPDATE(tenant_id) ON rss_da.agent_delivery TO da_identity_runtime,da_command_runtime;

CREATE TABLE rss_da.report_heads(
 tenant_id uuid NOT NULL,registration uuid NOT NULL,generation bigint NOT NULL CHECK(generation>0),kind text NOT NULL CHECK(kind IN('status','application')),
 integrity text NOT NULL CHECK(octet_length(integrity)<=4096),document jsonb NOT NULL CHECK(octet_length(document::text)<=131072),receipt jsonb NOT NULL,
 PRIMARY KEY(tenant_id,registration,generation,kind)
);
CREATE TABLE rss_da.report_history(
 tenant_id uuid NOT NULL,registration uuid NOT NULL,generation bigint NOT NULL CHECK(generation>0),kind text NOT NULL CHECK(kind IN('status','application')),
 sequence bigint NOT NULL CHECK(sequence>0),operation uuid,received_at bigint NOT NULL,document jsonb NOT NULL CHECK(octet_length(document::text)<=131072),receipt jsonb NOT NULL,
 PRIMARY KEY(tenant_id,registration,generation,kind,sequence),UNIQUE(tenant_id,registration,generation,kind,operation)
);
CREATE INDEX report_history_retention ON rss_da.report_history(tenant_id,received_at);
CREATE TABLE rss_da.report_budget(tenant_id uuid PRIMARY KEY,minute bigint NOT NULL,reports bigint NOT NULL,bytes bigint NOT NULL);
ALTER TABLE rss_da.report_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_da.report_heads FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON rss_da.report_heads USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON rss_da.report_heads FROM PUBLIC;
GRANT SELECT,INSERT ON rss_da.report_heads TO da_access;
GRANT UPDATE(integrity,document,receipt) ON rss_da.report_heads TO da_access;
ALTER TABLE rss_da.report_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_da.report_history FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON rss_da.report_history USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON rss_da.report_history FROM PUBLIC;
GRANT SELECT,INSERT ON rss_da.report_history TO da_access;
ALTER TABLE rss_da.report_budget ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_da.report_budget FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON rss_da.report_budget USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON rss_da.report_budget FROM PUBLIC;
GRANT SELECT,INSERT ON rss_da.report_budget TO da_access;
GRANT UPDATE(minute,reports,bytes) ON rss_da.report_budget TO da_access;
GRANT DELETE ON rss_da.report_history TO da_access;
