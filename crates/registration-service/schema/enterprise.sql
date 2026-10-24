-- RP business configuration and stable subject coordinates. No password or session secret.
BEGIN;
CREATE SCHEMA mdm_enterprise;
CREATE TABLE mdm_enterprise.relying_parties (
 tenant_id uuid NOT NULL,id text NOT NULL CHECK(length(id) BETWEEN 1 AND 64),revision bigint NOT NULL CHECK(revision>0),
 document jsonb NOT NULL CHECK(octet_length(document::text)<=8192),PRIMARY KEY(tenant_id,id)
);
CREATE TABLE mdm_enterprise.subjects (
 tenant_id uuid NOT NULL,provider uuid NOT NULL,principal uuid NOT NULL,revision bigint NOT NULL CHECK(revision>0),
 document jsonb NOT NULL CHECK(octet_length(document::text)<=4096),PRIMARY KEY(tenant_id,provider,principal)
);
CREATE TABLE mdm_enterprise.subject_owners (
 tenant_id uuid NOT NULL,provider uuid NOT NULL,subject text NOT NULL CHECK(length(subject) BETWEEN 1 AND 512),principal uuid NOT NULL,
 PRIMARY KEY(tenant_id,provider,subject)
);
ALTER TABLE mdm_enterprise.subject_owners ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_enterprise.subject_owners FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_enterprise.subject_owners USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE TABLE mdm_enterprise.subject_versions (
 tenant_id uuid NOT NULL,provider uuid NOT NULL,principal uuid NOT NULL,revision bigint NOT NULL CHECK(revision>0),
 document jsonb NOT NULL CHECK(octet_length(document::text)<=4096),PRIMARY KEY(tenant_id,provider,principal,revision)
);
ALTER TABLE mdm_enterprise.subject_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_enterprise.subject_versions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_enterprise.subject_versions USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE UNIQUE INDEX enterprise_stable_subject ON mdm_enterprise.subjects(tenant_id,provider,(document->>'subject'));
ALTER TABLE mdm_enterprise.relying_parties ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_enterprise.relying_parties FORCE ROW LEVEL SECURITY;
ALTER TABLE mdm_enterprise.subjects ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_enterprise.subjects FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_enterprise.relying_parties USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY tenant ON mdm_enterprise.subjects USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT USAGE ON SCHEMA mdm_enterprise TO mdm_access,mdm_identity_runtime;
GRANT SELECT ON mdm_enterprise.relying_parties,mdm_enterprise.subjects,mdm_enterprise.subject_versions,mdm_enterprise.subject_owners TO mdm_access,mdm_identity_runtime;
GRANT INSERT ON mdm_enterprise.relying_parties,mdm_enterprise.subjects,mdm_enterprise.subject_versions,mdm_enterprise.subject_owners TO mdm_identity_runtime;
GRANT UPDATE(revision,document) ON mdm_enterprise.relying_parties,mdm_enterprise.subjects TO mdm_identity_runtime;
CREATE TABLE mdm_enterprise.windows_sources (
 tenant_id uuid NOT NULL,binding uuid NOT NULL,id uuid NOT NULL,version bigint NOT NULL CHECK(version>0),
 document jsonb NOT NULL CHECK(octet_length(document::text)<=4096),PRIMARY KEY(tenant_id,binding),UNIQUE(tenant_id,id),
 FOREIGN KEY(tenant_id,binding) REFERENCES mdm_access.device_access_bindings(tenant_id,id)
);
ALTER TABLE mdm_enterprise.windows_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_enterprise.windows_sources FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_enterprise.windows_sources USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT ON mdm_enterprise.windows_sources TO mdm_access,mdm_identity_runtime;
GRANT INSERT ON mdm_enterprise.windows_sources TO mdm_identity_runtime;
GRANT UPDATE(version,document) ON mdm_enterprise.windows_sources TO mdm_identity_runtime;
CREATE TABLE mdm_enterprise.brokers (
 tenant_id uuid NOT NULL,id uuid NOT NULL,document jsonb NOT NULL CHECK(octet_length(document::text)<=65536),
 sealed bytea CHECK(octet_length(sealed)<=65536),expires_at bigint NOT NULL,
 phase text NOT NULL CHECK(phase IN('preparing','awaiting_proof','completing','unknown','ready','consumed','cancelled','expired','failed')),
 PRIMARY KEY(tenant_id,id)
);
CREATE INDEX enterprise_brokers_active ON mdm_enterprise.brokers(tenant_id,expires_at,phase);
ALTER TABLE mdm_enterprise.brokers ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_enterprise.brokers FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_enterprise.brokers USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON mdm_enterprise.brokers TO mdm_access,mdm_identity_runtime;
GRANT UPDATE(document,sealed,expires_at,phase) ON mdm_enterprise.brokers TO mdm_access,mdm_identity_runtime;
COMMIT;
