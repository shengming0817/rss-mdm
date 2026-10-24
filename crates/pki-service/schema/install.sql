-- Product device PKI and cross-owner trust relationships.
BEGIN;
CREATE SCHEMA mdm_pki;
GRANT USAGE ON SCHEMA mdm_pki TO mdm_access;
CREATE TABLE mdm_pki.issuers (tenant_id uuid NOT NULL, purpose text NOT NULL CHECK(purpose IN ('windows','apple','agent','agent_bootstrap')), digest text NOT NULL CHECK(digest ~ '^[0-9a-f]{64}$'), revision bigint NOT NULL CHECK(revision>0), state text NOT NULL CHECK(state IN ('prepared','active','verify_only','retired')), chain bytea NOT NULL CHECK(octet_length(chain) BETWEEN 1 AND 67108864), provider text NOT NULL CHECK(provider IN ('step_ca','legacy')), not_after bigint NOT NULL, PRIMARY KEY(tenant_id,purpose,digest));
ALTER TABLE mdm_pki.issuers ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_pki.issuers FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_pki.issuers USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON mdm_pki.issuers TO mdm_access;
GRANT UPDATE(state) ON mdm_pki.issuers TO mdm_access;
CREATE TABLE mdm_pki.signing (tenant_id uuid NOT NULL, attempt uuid NOT NULL, purpose text NOT NULL CHECK(purpose IN ('windows','apple','agent','agent_bootstrap')), issuer text NOT NULL CHECK(issuer ~ '^[0-9a-f]{64}$'), binding bytea NOT NULL CHECK(octet_length(binding) BETWEEN 1 AND 131072), deadline bigint NOT NULL, digest bytea NOT NULL CHECK(octet_length(digest)=32), state text NOT NULL CHECK(state IN ('prepared','signing','unknown','issued')), chain bytea CHECK(octet_length(chain) BETWEEN 1 AND 524288), created_at timestamptz NOT NULL DEFAULT clock_timestamp(), PRIMARY KEY(tenant_id,attempt), CHECK((state='issued')=(chain IS NOT NULL)));
ALTER TABLE mdm_pki.signing ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_pki.signing FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_pki.signing USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON mdm_pki.signing TO mdm_access;
GRANT UPDATE(state,chain) ON mdm_pki.signing TO mdm_access;
CREATE TABLE mdm_pki.certificates (tenant_id uuid NOT NULL, purpose text NOT NULL CHECK(purpose IN ('windows','apple','agent','agent_bootstrap')), fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32), issuer text NOT NULL CHECK(issuer ~ '^[0-9a-f]{64}$'), serial text NOT NULL CHECK(serial ~ '^[1-9][0-9]*$'), registration uuid, not_after bigint NOT NULL, certificate bytea NOT NULL CHECK(octet_length(certificate) BETWEEN 1 AND 32768),
 verification_version integer NOT NULL CHECK(verification_version=1),
 verification_trust bytea NOT NULL CHECK(octet_length(verification_trust)=32),
 verification_start bigint CHECK(verification_start>0),
 verification_end bigint CHECK(verification_end>verification_start AND verification_end<=not_after+1),
 CHECK((verification_start IS NULL)=(verification_end IS NULL)),
 CHECK(fingerprint=sha256(certificate)), PRIMARY KEY(tenant_id,purpose,fingerprint), UNIQUE(tenant_id,purpose,issuer,serial));
ALTER TABLE mdm_pki.certificates ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_pki.certificates FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_pki.certificates USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON mdm_pki.certificates TO mdm_access;
GRANT UPDATE(registration,verification_version,verification_trust,verification_start,verification_end) ON mdm_pki.certificates TO mdm_access;
CREATE TABLE mdm_pki.rotations (tenant_id uuid NOT NULL, id uuid NOT NULL, purpose text NOT NULL CHECK(purpose IN ('windows','apple','agent','agent_bootstrap')), previous text NOT NULL, candidate text NOT NULL, revision bigint NOT NULL CHECK(revision>0), state text NOT NULL CHECK(state IN ('distributing','activated','retired')), PRIMARY KEY(tenant_id,id));
ALTER TABLE mdm_pki.rotations ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_pki.rotations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_pki.rotations USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON mdm_pki.rotations TO mdm_access;
GRANT UPDATE(state) ON mdm_pki.rotations TO mdm_access;
CREATE TABLE mdm_pki.acknowledgements (tenant_id uuid NOT NULL, rotation uuid NOT NULL, registration uuid NOT NULL, revision bigint NOT NULL CHECK(revision>0), digest bytea NOT NULL CHECK(octet_length(digest)=64), confirmed_at timestamptz NOT NULL DEFAULT clock_timestamp(), PRIMARY KEY(tenant_id,rotation,registration));
ALTER TABLE mdm_pki.acknowledgements ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_pki.acknowledgements FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_pki.acknowledgements USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON mdm_pki.acknowledgements TO mdm_access;
GRANT UPDATE(revision,digest,confirmed_at) ON mdm_pki.acknowledgements TO mdm_access;
CREATE TABLE mdm_pki.revocations (tenant_id uuid NOT NULL, purpose text NOT NULL CHECK(purpose IN ('windows','apple','agent','agent_bootstrap')), issuer text NOT NULL, serial text NOT NULL CHECK(serial ~ '^[1-9][0-9]*$'), attempt uuid NOT NULL, state text NOT NULL CHECK(state IN ('pending','submitted','published')), failures integer NOT NULL DEFAULT 0 CHECK(failures BETWEEN 0 AND 32), next_attempt timestamptz NOT NULL DEFAULT clock_timestamp(), crl_number bigint, PRIMARY KEY(tenant_id,purpose,issuer,serial), UNIQUE(tenant_id,attempt));
ALTER TABLE mdm_pki.revocations ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_pki.revocations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_pki.revocations USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON mdm_pki.revocations TO mdm_access;
GRANT UPDATE(state,failures,next_attempt,crl_number) ON mdm_pki.revocations TO mdm_access;
CREATE TABLE mdm_pki.crls (tenant_id uuid NOT NULL, purpose text NOT NULL CHECK(purpose IN ('windows','apple','agent','agent_bootstrap')), issuer text NOT NULL, number bigint NOT NULL CHECK(number>=0), this_update bigint NOT NULL, next_update bigint NOT NULL CHECK(next_update>this_update), der bytea NOT NULL CHECK(octet_length(der) BETWEEN 1 AND 16777216), PRIMARY KEY(tenant_id,purpose,issuer));
ALTER TABLE mdm_pki.crls ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_pki.crls FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_pki.crls USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON mdm_pki.crls TO mdm_access;
GRANT UPDATE(number,this_update,next_update,der) ON mdm_pki.crls TO mdm_access;
CREATE UNIQUE INDEX one_open_rotation ON mdm_pki.rotations(tenant_id,purpose) WHERE state<>'retired';
CREATE UNIQUE INDEX one_active_issuer ON mdm_pki.issuers(tenant_id,purpose) WHERE state='active';

CREATE TABLE mdm_windows.renewal_intents (
 tenant_id uuid NOT NULL, id uuid NOT NULL, registration uuid NOT NULL,
 generation bigint NOT NULL CHECK(generation>0), previous_credential uuid NOT NULL,
 proof_digest bytea NOT NULL CHECK(octet_length(proof_digest)=32),
 profile bytea NOT NULL CHECK(octet_length(profile) BETWEEN 1 AND 4096),
 configuration text NOT NULL CHECK(configuration ~ '^[0-9a-f]{64}$'),
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,registration,generation,previous_credential),
 FOREIGN KEY(tenant_id,registration) REFERENCES mdm_access.registrations(tenant_id,id)
);
ALTER TABLE mdm_windows.renewal_intents ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_windows.renewal_intents FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_windows.renewal_intents USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON mdm_windows.renewal_intents TO mdm_access;

CREATE TABLE mdm_pki.trust (tenant_id uuid NOT NULL,purpose text NOT NULL,revision bigint NOT NULL CHECK(revision>0),body bytea NOT NULL CHECK(octet_length(body) BETWEEN 1 AND 67108864),PRIMARY KEY(tenant_id,purpose));
ALTER TABLE mdm_pki.trust ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_pki.trust FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_pki.trust USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON mdm_pki.trust TO mdm_access;
GRANT UPDATE(revision,body) ON mdm_pki.trust TO mdm_access;
CREATE TABLE mdm_pki.operations(tenant_id uuid NOT NULL,actor text NOT NULL,instance text NOT NULL,operation uuid NOT NULL,phase text NOT NULL,digest bytea NOT NULL CHECK(octet_length(digest)=32),receipt bytea NOT NULL CHECK(octet_length(receipt) BETWEEN 1 AND 131072),PRIMARY KEY(tenant_id,actor,operation,phase));
ALTER TABLE mdm_pki.operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_pki.operations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_pki.operations USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON mdm_pki.operations TO mdm_access;

ALTER TABLE mdm_pki.certificates ADD CONSTRAINT issuer_generation FOREIGN KEY(tenant_id,purpose,issuer) REFERENCES mdm_pki.issuers(tenant_id,purpose,digest);
ALTER TABLE mdm_pki.signing ADD CONSTRAINT issuer_generation FOREIGN KEY(tenant_id,purpose,issuer) REFERENCES mdm_pki.issuers(tenant_id,purpose,digest);
ALTER TABLE mdm_pki.revocations ADD CONSTRAINT issued_certificate FOREIGN KEY(tenant_id,purpose,issuer,serial) REFERENCES mdm_pki.certificates(tenant_id,purpose,issuer,serial);
CREATE TABLE mdm_windows.trust_deliveries (
 tenant_id uuid NOT NULL,id uuid NOT NULL,registration uuid NOT NULL,generation bigint NOT NULL CHECK(generation>0),credential uuid NOT NULL,
 revision bigint NOT NULL CHECK(revision>0),digest text NOT NULL CHECK(digest ~ '^[0-9a-f]{64}$'),session bigint NOT NULL CHECK(session>0),
 message bigint NOT NULL CHECK(message>0),first_command bigint NOT NULL CHECK(first_command>0),request bytea NOT NULL CHECK(octet_length(request) BETWEEN 68 AND 2097220),
 results bytea NOT NULL CHECK(octet_length(results) BETWEEN 68 AND 2097220),authority text NOT NULL CHECK(authority ~ '^[0-9a-f]{64}$'),confirmed boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,registration,session,revision,authority),FOREIGN KEY(tenant_id,registration) REFERENCES mdm_access.registrations(tenant_id,id)
);
ALTER TABLE mdm_windows.trust_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_windows.trust_deliveries FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_windows.trust_deliveries USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY expired_only ON mdm_windows.trust_deliveries AS RESTRICTIVE FOR DELETE USING(EXISTS(SELECT 1 FROM mdm_access.management_sessions s WHERE s.tenant_id=trust_deliveries.tenant_id AND s.registration=trust_deliveries.registration AND s.session_id=trust_deliveries.session::text AND s.expires_at<clock_timestamp()));
GRANT SELECT,INSERT,DELETE ON mdm_windows.trust_deliveries TO mdm_access;
GRANT UPDATE(results,confirmed) ON mdm_windows.trust_deliveries TO mdm_access;
CREATE TABLE mdm_pki.installations(tenant_id uuid NOT NULL,purpose text NOT NULL CHECK(purpose IN ('windows','apple','agent','agent_bootstrap')),registration uuid NOT NULL,
 revision bigint NOT NULL CHECK(revision>0),digest text NOT NULL CHECK(digest ~ '^[0-9a-f]{64}$'),body bytea NOT NULL CHECK(octet_length(body) BETWEEN 1 AND 67108864),
 confirmed_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(tenant_id,purpose,registration),
 FOREIGN KEY(tenant_id,registration) REFERENCES mdm_access.registrations(tenant_id,id));
ALTER TABLE mdm_pki.installations ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_pki.installations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_pki.installations USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON mdm_pki.installations TO mdm_access;
GRANT UPDATE(revision,digest,body,confirmed_at) ON mdm_pki.installations TO mdm_access;
CREATE TABLE mdm_apple.trust_deliveries(tenant_id uuid NOT NULL,id uuid NOT NULL,registration uuid NOT NULL,generation bigint NOT NULL CHECK(generation>0),
 revision bigint NOT NULL CHECK(revision>0),digest text NOT NULL CHECK(digest ~ '^[0-9a-f]{64}$'),body bytea NOT NULL CHECK(octet_length(body) BETWEEN 1 AND 67108864),profile uuid NOT NULL,
 PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,registration,generation,revision),FOREIGN KEY(tenant_id,registration) REFERENCES mdm_access.registrations(tenant_id,id));
ALTER TABLE mdm_apple.trust_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_apple.trust_deliveries FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_apple.trust_deliveries USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON mdm_apple.trust_deliveries TO mdm_access;

ALTER TABLE mdm_apple.attempts ADD CONSTRAINT trust_delivery FOREIGN KEY(tenant_id,trust) REFERENCES mdm_apple.trust_deliveries(tenant_id,id);

-- Native participants borrow the Execution transaction; only trust delivery and
-- installation acknowledgements are available to that role.
GRANT USAGE ON SCHEMA mdm_pki TO mdm_command_runtime;
GRANT SELECT ON mdm_pki.rotations,mdm_pki.trust TO mdm_command_runtime;
GRANT SELECT,INSERT ON mdm_pki.installations,mdm_pki.acknowledgements,mdm_windows.trust_deliveries,mdm_apple.trust_deliveries TO mdm_command_runtime;
GRANT UPDATE(revision,digest,body,confirmed_at) ON mdm_pki.installations TO mdm_command_runtime;
GRANT UPDATE(revision,digest,confirmed_at) ON mdm_pki.acknowledgements TO mdm_command_runtime;
GRANT UPDATE(results,confirmed) ON mdm_windows.trust_deliveries TO mdm_command_runtime;

-- Fixed tenant-scoped presentation relation. Exact trust publication and certificate
-- qualification commit together; queued revocations take effect immediately.
CREATE VIEW mdm_pki.current_certificates WITH (security_barrier=true) AS
WITH current_trust AS MATERIALIZED (
 SELECT tenant_id,purpose,sha256(body) AS digest FROM mdm_pki.trust
 WHERE tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid
)
SELECT c.tenant_id,c.purpose,c.fingerprint,c.verification_end AS valid_until
FROM mdm_pki.certificates c JOIN current_trust t USING(tenant_id,purpose)
WHERE c.tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid
 AND c.verification_version=1 AND c.verification_trust=t.digest
 AND c.verification_start<=floor(extract(epoch FROM statement_timestamp()))::bigint
 AND c.verification_end>floor(extract(epoch FROM statement_timestamp()))::bigint
 AND NOT EXISTS(SELECT FROM mdm_pki.revocations r
  WHERE (r.tenant_id,r.purpose,r.issuer,r.serial)=(c.tenant_id,c.purpose,c.issuer,c.serial));
REVOKE ALL ON mdm_pki.current_certificates FROM PUBLIC;
GRANT SELECT ON mdm_pki.current_certificates TO mdm_access;
COMMIT;
