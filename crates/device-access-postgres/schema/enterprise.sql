-- RP business configuration and stable subject coordinates. No password or session secret.
BEGIN;

CREATE TABLE rss_da.relying_parties (
 tenant_id uuid NOT NULL,id text NOT NULL CHECK(length(id) BETWEEN 1 AND 64),revision bigint NOT NULL CHECK(revision>0),
 document jsonb NOT NULL CHECK(octet_length(document::text)<=8192),PRIMARY KEY(tenant_id,id)
);
CREATE TABLE rss_da.subjects (
 tenant_id uuid NOT NULL,provider uuid NOT NULL,principal uuid NOT NULL,revision bigint NOT NULL CHECK(revision>0),
 document jsonb NOT NULL CHECK(octet_length(document::text)<=4096),PRIMARY KEY(tenant_id,provider,principal)
);
CREATE TABLE rss_da.subject_owners (
 tenant_id uuid NOT NULL,provider uuid NOT NULL,subject text NOT NULL CHECK(length(subject) BETWEEN 1 AND 512),principal uuid NOT NULL,
 PRIMARY KEY(tenant_id,provider,subject)
);
ALTER TABLE rss_da.subject_owners ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_da.subject_owners FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON rss_da.subject_owners USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE TABLE rss_da.subject_versions (
 tenant_id uuid NOT NULL,provider uuid NOT NULL,principal uuid NOT NULL,revision bigint NOT NULL CHECK(revision>0),
 document jsonb NOT NULL CHECK(octet_length(document::text)<=4096),PRIMARY KEY(tenant_id,provider,principal,revision)
);
ALTER TABLE rss_da.subject_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_da.subject_versions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON rss_da.subject_versions USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE UNIQUE INDEX enterprise_stable_subject ON rss_da.subjects(tenant_id,provider,(document->>'subject'));
ALTER TABLE rss_da.relying_parties ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_da.relying_parties FORCE ROW LEVEL SECURITY;
ALTER TABLE rss_da.subjects ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_da.subjects FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON rss_da.relying_parties USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY tenant ON rss_da.subjects USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT USAGE ON SCHEMA rss_da TO da_access,da_identity_runtime;
GRANT SELECT ON rss_da.relying_parties,rss_da.subjects,rss_da.subject_versions,rss_da.subject_owners TO da_access,da_identity_runtime;
GRANT INSERT ON rss_da.relying_parties,rss_da.subjects,rss_da.subject_versions,rss_da.subject_owners TO da_identity_runtime;
GRANT UPDATE(revision,document) ON rss_da.relying_parties,rss_da.subjects TO da_identity_runtime;
CREATE TABLE rss_da.windows_sources (
    tenant_id uuid NOT NULL
  , binding uuid NOT NULL
  , id uuid NOT NULL
  , version bigint NOT NULL CHECK (version > 0)
  , document jsonb NOT NULL CHECK (octet_length(CAST(document AS text)) <= 4096)
  , PRIMARY KEY (tenant_id, binding)
  , UNIQUE (tenant_id, id)
  , FOREIGN KEY (tenant_id, binding) REFERENCES rss_da.bindings (tenant_id, id)
);
ALTER TABLE rss_da.windows_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_da.windows_sources FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON rss_da.windows_sources USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT ON rss_da.windows_sources TO da_access,da_identity_runtime;
GRANT INSERT ON rss_da.windows_sources TO da_identity_runtime;
GRANT UPDATE(version,document) ON rss_da.windows_sources TO da_identity_runtime;
CREATE TABLE rss_da.brokers (
 tenant_id uuid NOT NULL,id uuid NOT NULL,document jsonb NOT NULL CHECK(octet_length(document::text)<=65536),
 sealed bytea CHECK(octet_length(sealed)<=65536),expires_at bigint NOT NULL,
 phase text NOT NULL CHECK(phase IN('preparing','awaiting_proof','completing','unknown','ready','consumed','cancelled','expired','failed')),
 PRIMARY KEY(tenant_id,id)
);
CREATE INDEX enterprise_brokers_active ON rss_da.brokers(tenant_id,expires_at,phase);
ALTER TABLE rss_da.brokers ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_da.brokers FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON rss_da.brokers USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON rss_da.brokers TO da_access,da_identity_runtime;
GRANT UPDATE(document,sealed,expires_at,phase) ON rss_da.brokers TO da_access,da_identity_runtime;
COMMIT;
