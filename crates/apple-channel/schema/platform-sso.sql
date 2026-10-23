-- Apple PSSO protocol state only. Personnel and browser sessions retain their existing owners.
BEGIN;
CREATE TABLE mdm_apple.psso_sources (
 tenant_id uuid NOT NULL,
 id uuid NOT NULL,
 kind text NOT NULL CHECK(kind IN('device','user')),
 registration uuid NOT NULL,
 binding uuid,
 parent uuid,
 version bigint NOT NULL CHECK(version>0),
 revoked boolean NOT NULL,
 signing_kid text NOT NULL CHECK(octet_length(signing_kid)=44),
 document jsonb NOT NULL CHECK(octet_length(document::text)<=16384),
 PRIMARY KEY(tenant_id,id),
 FOREIGN KEY(tenant_id,registration) REFERENCES mdm_access.registrations(tenant_id,id),
 FOREIGN KEY(tenant_id,binding) REFERENCES mdm_access.device_access_bindings(tenant_id,id),
 FOREIGN KEY(tenant_id,parent) REFERENCES mdm_apple.psso_sources(tenant_id,id),
 CHECK((kind='device' AND binding IS NULL AND parent IS NULL) OR (kind='user' AND binding IS NOT NULL AND parent IS NOT NULL))
);
CREATE UNIQUE INDEX psso_device ON mdm_apple.psso_sources(tenant_id,registration) WHERE kind='device';
CREATE UNIQUE INDEX psso_user ON mdm_apple.psso_sources(tenant_id,binding) WHERE kind='user';
CREATE UNIQUE INDEX psso_key ON mdm_apple.psso_sources(tenant_id,signing_kid) WHERE NOT revoked;
CREATE TABLE mdm_apple.psso_challenges (
 tenant_id uuid NOT NULL,
 id uuid NOT NULL,
 purpose text NOT NULL CHECK(purpose IN('device','user','login')),
 nonce_digest bytea NOT NULL CHECK(octet_length(nonce_digest)=32),
 expires_at bigint NOT NULL,
 context jsonb NOT NULL CHECK(octet_length(context::text)<=16384),
 consumed boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,id)
);
CREATE INDEX psso_challenge_expiry ON mdm_apple.psso_challenges(tenant_id,expires_at);
CREATE TABLE mdm_apple.psso_tokens (
 tenant_id uuid NOT NULL,
 digest bytea NOT NULL CHECK(octet_length(digest)=32),
 source uuid NOT NULL,
 version bigint NOT NULL CHECK(version>0),
 expires_at bigint NOT NULL,
 PRIMARY KEY(tenant_id,digest),
 FOREIGN KEY(tenant_id,source) REFERENCES mdm_apple.psso_sources(tenant_id,id)
);
CREATE INDEX psso_token_expiry ON mdm_apple.psso_tokens(tenant_id,expires_at);
ALTER TABLE mdm_apple.psso_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_apple.psso_sources FORCE ROW LEVEL SECURITY;
ALTER TABLE mdm_apple.psso_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_apple.psso_challenges FORCE ROW LEVEL SECURITY;
ALTER TABLE mdm_apple.psso_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_apple.psso_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_apple.psso_sources USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY tenant ON mdm_apple.psso_challenges USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY tenant ON mdm_apple.psso_tokens USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON mdm_apple.psso_sources,mdm_apple.psso_challenges,mdm_apple.psso_tokens TO mdm_access;
GRANT UPDATE(registration,parent,version,revoked,signing_kid,document) ON mdm_apple.psso_sources TO mdm_access;
GRANT UPDATE(consumed) ON mdm_apple.psso_challenges TO mdm_access;
GRANT DELETE ON mdm_apple.psso_challenges,mdm_apple.psso_tokens TO mdm_access;
-- Registration consumes the same current paired-device and application evidence as login.
GRANT SELECT ON mdm_devices.input_snapshots,mdm_devices.input_objects,mdm.inventory TO mdm_access;
GRANT USAGE ON SCHEMA mdm_apple TO mdm_identity_runtime;
GRANT SELECT ON mdm_apple.psso_sources,mdm_apple.psso_tokens TO mdm_identity_runtime;
GRANT UPDATE(tenant_id) ON mdm_apple.psso_sources TO mdm_identity_runtime;
COMMIT;
