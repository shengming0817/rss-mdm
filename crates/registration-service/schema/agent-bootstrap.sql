BEGIN;
CREATE TABLE mdm_access.agent_bootstraps (
 tenant_id uuid NOT NULL,id uuid NOT NULL,installation uuid NOT NULL,delivery uuid NOT NULL,
 cleanup uuid,cleanup_complete boolean NOT NULL DEFAULT false,cleanup_retry_at bigint NOT NULL DEFAULT 0,source jsonb NOT NULL,release uuid NOT NULL,issuer text NOT NULL,provisioner text NOT NULL,
 download_origin text NOT NULL CHECK(octet_length(download_origin) BETWEEN 1 AND 2048),
 active boolean NOT NULL DEFAULT true,challenge bytea NOT NULL CHECK(octet_length(challenge)=32),deadline bigint NOT NULL,
 state text NOT NULL CHECK(state IN ('prepared','signing','issued','consumed','revoked')),
 transaction_id text,csr_digest bytea,spki bytea,fingerprint bytea,certificate bytea,
 PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,delivery),
 CHECK((csr_digest IS NULL)=(spki IS NULL)),
 CHECK(csr_digest IS NULL OR octet_length(csr_digest)=32),
 CHECK(spki IS NULL OR octet_length(spki)=32),
 CHECK(fingerprint IS NULL OR octet_length(fingerprint)=32)
);
CREATE UNIQUE INDEX agent_bootstrap_current ON mdm_access.agent_bootstraps(tenant_id,installation) WHERE active;
ALTER TABLE mdm_access.agent_bootstraps ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_access.agent_bootstraps FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_access.agent_bootstraps USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON mdm_access.agent_bootstraps TO mdm_command_runtime;
GRANT UPDATE(active,cleanup,cleanup_complete,cleanup_retry_at) ON mdm_access.agent_bootstraps TO mdm_command_runtime;
GRANT SELECT ON mdm_access.agent_bootstraps TO mdm_access;
GRANT UPDATE(state,deadline,transaction_id,csr_digest,spki,fingerprint,certificate) ON mdm_access.agent_bootstraps TO mdm_access;
GRANT USAGE ON SCHEMA mdm_agent_packages TO mdm_command_runtime;
GRANT SELECT ON mdm_agent_packages.releases TO mdm_command_runtime;
GRANT SELECT ON mdm_pki.certificates,mdm_pki.revocations TO mdm_command_runtime;
COMMIT;
