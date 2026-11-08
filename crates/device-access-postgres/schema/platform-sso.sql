-- Apple PSSO protocol state only. Personnel and browser sessions retain their existing owners.
BEGIN;
CREATE TABLE rss_da.psso_sources (
    tenant_id uuid NOT NULL
  , id uuid NOT NULL
  , kind text NOT NULL CHECK (kind IN ('device', 'user'))
  , device text NOT NULL
  , binding uuid
  , parent uuid
  , version bigint NOT NULL CHECK (version > 0)
  , revoked boolean NOT NULL
  , signing_kid text CHECK (signing_kid IS NULL
                         OR octet_length(signing_kid) = 44)
  , document jsonb NOT NULL CHECK (octet_length(CAST(document AS text)) <= 16384)
  , PRIMARY KEY (tenant_id, id)
  , FOREIGN KEY (tenant_id, device) REFERENCES rss_da.devices (tenant_id, id)
  , FOREIGN KEY (tenant_id, binding) REFERENCES rss_da.bindings (tenant_id, id)
  , FOREIGN KEY (tenant_id, parent) REFERENCES rss_da.psso_sources (tenant_id, id)
  , CHECK ((kind = 'device'
        AND binding IS NULL
        AND parent IS NULL)
        OR (kind = 'user'
        AND binding IS NOT NULL
        AND parent IS NOT NULL))
);
CREATE UNIQUE INDEX psso_device
  ON rss_da.psso_sources (tenant_id
                        , device)
  WHERE kind = 'device';
CREATE UNIQUE INDEX psso_user ON rss_da.psso_sources(tenant_id,binding) WHERE kind='user';
CREATE UNIQUE INDEX psso_key ON rss_da.psso_sources(tenant_id,signing_kid) WHERE NOT revoked;
CREATE TABLE rss_da.psso_challenges (
 tenant_id uuid NOT NULL,
 id uuid NOT NULL,
 purpose text NOT NULL CHECK(purpose IN('device','user','login')),
 nonce_digest bytea NOT NULL CHECK(octet_length(nonce_digest)=32),
 expires_at bigint NOT NULL,
 context jsonb NOT NULL CHECK(octet_length(context::text)<=16384),
 consumed boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,id)
);
CREATE INDEX psso_challenge_expiry ON rss_da.psso_challenges(tenant_id,expires_at);
CREATE TABLE rss_da.psso_tokens (
    tenant_id uuid NOT NULL
  , digest bytea NOT NULL CHECK (octet_length(digest) = 32)
  , source uuid NOT NULL
  , version bigint NOT NULL CHECK (version > 0)
  , expires_at bigint NOT NULL
  , PRIMARY KEY (tenant_id, digest)
  , FOREIGN KEY (tenant_id, source) REFERENCES rss_da.psso_sources (tenant_id, id)
);
CREATE INDEX psso_token_expiry ON rss_da.psso_tokens(tenant_id,expires_at);
ALTER TABLE rss_da.psso_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_da.psso_sources FORCE ROW LEVEL SECURITY;
ALTER TABLE rss_da.psso_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_da.psso_challenges FORCE ROW LEVEL SECURITY;
ALTER TABLE rss_da.psso_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_da.psso_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON rss_da.psso_sources USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY tenant ON rss_da.psso_challenges USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY tenant ON rss_da.psso_tokens USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON rss_da.psso_sources,rss_da.psso_challenges,rss_da.psso_tokens TO da_access;
GRANT UPDATE (parent, version, revoked, signing_kid, document)
  ON TABLE rss_da.psso_sources
  TO da_access;
GRANT UPDATE(consumed) ON rss_da.psso_challenges TO da_access;
GRANT DELETE ON rss_da.psso_challenges,rss_da.psso_tokens TO da_access;
-- Registration consumes the same current paired-device and application evidence as login.
GRANT SELECT ON rss_da.psso_sources,rss_da.psso_tokens TO da_identity_runtime;
GRANT UPDATE(tenant_id) ON rss_da.psso_sources TO da_identity_runtime;
CREATE TABLE rss_da.psso_password_providers (
 tenant_id uuid NOT NULL, id uuid NOT NULL, revision bigint NOT NULL CHECK(revision>0),
 fingerprint text NOT NULL CHECK(length(fingerprint)=43), PRIMARY KEY(tenant_id,id)
);
CREATE TABLE rss_da.psso_password_attempts (
    tenant_id uuid NOT NULL
  , id uuid NOT NULL
  , source uuid NOT NULL
  , version bigint NOT NULL CHECK (version > 0)
  , provider uuid NOT NULL
  , provider_fingerprint text NOT NULL CHECK (length(provider_fingerprint) = 43)
  , context jsonb NOT NULL
  , expires_at bigint NOT NULL
  , state text NOT NULL CHECK (state IN ('verifying', 'succeeded', 'rejected', 'unavailable'))
  , PRIMARY KEY (tenant_id, id)
  , FOREIGN KEY (tenant_id, source) REFERENCES rss_da.psso_sources (tenant_id, id)
  , FOREIGN KEY (tenant_id, provider) REFERENCES rss_da.psso_password_providers (tenant_id, id)
  , CHECK (octet_length(CAST(context AS text)) <= 16384)
);
ALTER TABLE rss_da.psso_password_providers ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_da.psso_password_providers FORCE ROW LEVEL SECURITY;
ALTER TABLE rss_da.psso_password_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_da.psso_password_attempts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON rss_da.psso_password_providers USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY tenant ON rss_da.psso_password_attempts USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON rss_da.psso_password_providers,rss_da.psso_password_attempts TO da_access;
GRANT UPDATE(revision,fingerprint) ON rss_da.psso_password_providers TO da_access;
GRANT UPDATE(state) ON rss_da.psso_password_attempts TO da_access;
CREATE POLICY expired_only ON rss_da.psso_password_attempts AS RESTRICTIVE FOR DELETE USING(expires_at < floor(extract(epoch FROM clock_timestamp()))::bigint-86400);
GRANT DELETE ON rss_da.psso_password_attempts TO da_access;
GRANT SELECT ON rss_da.psso_password_providers TO da_identity_runtime;
COMMIT;
