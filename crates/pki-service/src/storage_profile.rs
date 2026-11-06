//! Fixed, owner-owned SQL. Only these source literals can select objects.
use rss_mdm_install_support::StorageProfile;
pub(crate) struct Statements {
    pub install: &'static str,
    pub observations: &'static str,
    pub certificates_record_candidate_in_1: &'static str,
    pub certificates_record_candidate_in_2: &'static str,
    pub certificates_record_candidate_in_3: &'static str,
    pub certificates_revoke_registration_in_1: &'static str,
    pub certificates_enqueue_in_1: &'static str,
    pub certificates_revoke_credential_in_1: &'static str,
    pub certificates_revoke_attempt_in_1: &'static str,
    pub certificates_current_native_credential_in_1: &'static str,
    pub observations_record_in_1: &'static str,
    pub observations_record_in_2: &'static str,
    pub observations_latest_in_1: &'static str,
    pub maintenance_health_1: &'static str,
    pub maintenance_publish_set_1: &'static str,
    pub maintenance_publish_set_2: &'static str,
    pub maintenance_claim_1: &'static str,
    pub maintenance_claim_2: &'static str,
    pub maintenance_submitted_1: &'static str,
    pub operation_diagnostics: &'static str,
    pub mutation_replay_1: &'static str,
    pub mutation_save_result_1: &'static str,
    pub registry_admit_selected_1: &'static str,
    pub registry_admit_selected_2: &'static str,
    pub registry_admit_selected_3: &'static str,
    pub registry_synchronize_1: &'static str,
    pub registry_transition_1: &'static str,
    pub registry_acknowledge_in_1: &'static str,
    pub registry_acknowledge_in_2: &'static str,
    pub registry_acknowledge_in_3: &'static str,
    pub registry_rotation_replay_1: &'static str,
    pub registry_write_1: &'static str,
    pub registry_write_2: &'static str,
    pub registry_write_3: &'static str,
    pub registry_persist_1: &'static str,
    pub registry_persist_2: &'static str,
    pub registry_persist_3: &'static str,
    pub registry_persist_4: &'static str,
    pub registry_persist_5: &'static str,
    pub registry_persist_6: &'static str,
    pub registry_current_certificate_in_1: &'static str,
    pub registry_current_certificates_in_1: &'static str,
    pub registry_trust_on_1: &'static str,
    pub registry_retained_issuer_on_1: &'static str,
    pub recovery_recover_1: &'static str,
    pub recovery_adopt_in_1: &'static str,
    pub recovery_adopt_in_2: &'static str,
    pub signing_authorize_in_1: &'static str,
    pub signing_supersede_expired_in_1: &'static str,
    pub signing_supersede_expired_in_2: &'static str,
    pub signing_require_active_in_1: &'static str,
    pub signing_issue_1: &'static str,
    pub signing_issue_2: &'static str,
    pub signing_settle_1: &'static str,
    pub signing_settle_2: &'static str,
    pub signing_queries_read_many_in_1: &'static str,
    pub signing_queries_operations_in_1: &'static str,
    pub signing_queries_operation_in_1: &'static str,
    pub qualification_for_certificate_in_1: &'static str,
    pub qualification_publish_in_1: &'static str,
    pub qualification_publish_in_2: &'static str,
    pub rotation_gates_require_1: &'static str,
    pub rotation_mod_rotation_1: &'static str,
    pub rotation_mod_rotation_2: &'static str,
    pub rotation_mod_rotation_blockers_1: &'static str,
    pub object_manifest: &'static str,
    pub rotation_relations: &'static str,
    pub access_contract: &'static str,
}
macro_rules! define_storage {
    ($module:ident, $pki_acknowledgements:literal, $pki_certificates:literal, $pki_crls:literal, $pki_current_certificates:literal, $pki_installations:literal, $pki_issuers:literal, $pki_operations:literal, $pki_revocations:literal, $pki_rotations:literal, $pki_signing:literal, $pki_trust:literal, $pki_trust_observations:literal, $pki_schema:literal, $registrations:literal, $credentials:literal, $certificate_grants:literal, $access_schema:literal, $access_role:literal, $command_role:literal, $policy_role:literal, $owner_role:literal, $index_one_open_rotation:literal, $index_one_active_issuer:literal, $index_signing_recovery_operations:literal, $requests:literal, $agent_bootstraps:literal, $registration_operations:literal, $native_scep:literal, $contract_issuers:literal, $contract_signing:literal, $contract_certificates:literal, $contract_rotations:literal, $contract_acknowledgements:literal, $contract_revocations:literal, $contract_crls:literal, $contract_trust:literal, $contract_operations:literal, $contract_installations:literal, $contract_trust_observations:literal) => {
        mod $module {
            pub(super) const SQL: super::Statements = super::Statements {
                install: concat!(r###"-- Product device PKI and cross-owner trust relationships.
BEGIN;
CREATE SCHEMA IF NOT EXISTS "###, $pki_schema, r###";
GRANT USAGE ON SCHEMA "###, $pki_schema, " TO ", $access_role, r###";
CREATE TABLE "###, $pki_issuers, r###" (tenant_id uuid NOT NULL, purpose text NOT NULL CHECK(purpose IN ('windows','apple','agent','agent_bootstrap','da_device')), digest text NOT NULL CHECK(digest ~ '^[0-9a-f]{64}$'), revision bigint NOT NULL CHECK(revision>0), state text NOT NULL CHECK(state IN ('prepared','active','verify_only','retired')), chain bytea NOT NULL CHECK(octet_length(chain) BETWEEN 1 AND 67108864), provider text NOT NULL CHECK(provider IN ('step_ca','legacy')), not_after bigint NOT NULL, PRIMARY KEY(tenant_id,purpose,digest));
ALTER TABLE "###, $pki_issuers, r###" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "###, $pki_issuers, r###" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON "###, $pki_issuers, r###" USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON "###, $pki_issuers, " TO ", $access_role, r###";
GRANT UPDATE(state) ON "###, $pki_issuers, " TO ", $access_role, r###";
CREATE TABLE "###, $pki_signing, r###" (tenant_id uuid NOT NULL, attempt uuid NOT NULL, purpose text NOT NULL CHECK(purpose IN ('windows','apple','agent','agent_bootstrap','da_device')), issuer text NOT NULL CHECK(issuer ~ '^[0-9a-f]{64}$'), binding bytea NOT NULL CHECK(octet_length(binding) BETWEEN 1 AND 131072), deadline bigint NOT NULL, digest bytea NOT NULL CHECK(octet_length(digest)=32), state text NOT NULL CHECK(state IN ('prepared','signing','unknown','issued','superseded')), chain bytea CHECK(octet_length(chain) BETWEEN 1 AND 524288), created_at timestamptz NOT NULL DEFAULT clock_timestamp(), PRIMARY KEY(tenant_id,attempt), CHECK((state='issued')=(chain IS NOT NULL)));
ALTER TABLE "###, $pki_signing, r###" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "###, $pki_signing, r###" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON "###, $pki_signing, r###" USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON "###, $pki_signing, " TO ", $access_role, r###";
GRANT UPDATE(state,chain) ON "###, $pki_signing, " TO ", $access_role, r###";
ALTER TABLE "###, $pki_signing, r###" ADD COLUMN successor uuid;
ALTER TABLE "###, $pki_signing, r###" ADD CONSTRAINT successor_state CHECK ((state='superseded')=(successor IS NOT NULL));
ALTER TABLE "###, $pki_signing, r###" ADD CONSTRAINT successor_other CHECK (successor<>attempt);
ALTER TABLE "###, $pki_signing, r###" ADD CONSTRAINT successor_unique UNIQUE(tenant_id,successor);
ALTER TABLE "###, $pki_signing, " ADD CONSTRAINT successor_attempt FOREIGN KEY(tenant_id,successor) REFERENCES ", $pki_signing, r###"(tenant_id,attempt) DEFERRABLE INITIALLY DEFERRED;
GRANT UPDATE(successor) ON "###, $pki_signing, " TO ", $access_role, r###";
CREATE TABLE "###, $pki_certificates, r###" (tenant_id uuid NOT NULL, purpose text NOT NULL CHECK(purpose IN ('windows','apple','agent','agent_bootstrap','da_device')), fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32), issuer text NOT NULL CHECK(issuer ~ '^[0-9a-f]{64}$'), serial text NOT NULL CHECK(serial ~ '^[1-9][0-9]*$'), registration uuid, not_after bigint NOT NULL, certificate bytea NOT NULL CHECK(octet_length(certificate) BETWEEN 1 AND 32768),
 verification_version integer NOT NULL CHECK(verification_version=1),
 verification_trust bytea NOT NULL CHECK(octet_length(verification_trust)=32),
 verification_start bigint CHECK(verification_start>0),
 verification_end bigint CHECK(verification_end>verification_start AND verification_end<=not_after+1),
 CHECK((verification_start IS NULL)=(verification_end IS NULL)),
 CHECK(fingerprint=sha256(certificate)), PRIMARY KEY(tenant_id,purpose,fingerprint), UNIQUE(tenant_id,purpose,issuer,serial));
ALTER TABLE "###, $pki_certificates, r###" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "###, $pki_certificates, r###" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON "###, $pki_certificates, r###" USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON "###, $pki_certificates, " TO ", $access_role, r###";
GRANT UPDATE(registration,verification_version,verification_trust,verification_start,verification_end) ON "###, $pki_certificates, " TO ", $access_role, r###";
CREATE TABLE "###, $pki_rotations, r###" (tenant_id uuid NOT NULL, id uuid NOT NULL, purpose text NOT NULL CHECK(purpose IN ('windows','apple','agent','agent_bootstrap','da_device')), previous text NOT NULL, candidate text NOT NULL, revision bigint NOT NULL CHECK(revision>0), state text NOT NULL CHECK(state IN ('distributing','activated','retired')), PRIMARY KEY(tenant_id,id));
ALTER TABLE "###, $pki_rotations, r###" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "###, $pki_rotations, r###" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON "###, $pki_rotations, r###" USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON "###, $pki_rotations, " TO ", $access_role, r###";
GRANT UPDATE(state) ON "###, $pki_rotations, " TO ", $access_role, r###";
CREATE TABLE "###, $pki_acknowledgements, r###" (tenant_id uuid NOT NULL, rotation uuid NOT NULL, registration uuid NOT NULL, revision bigint NOT NULL CHECK(revision>0), digest bytea NOT NULL CHECK(octet_length(digest)=64), confirmed_at timestamptz NOT NULL DEFAULT clock_timestamp(), PRIMARY KEY(tenant_id,rotation,registration));
ALTER TABLE "###, $pki_acknowledgements, r###" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "###, $pki_acknowledgements, r###" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON "###, $pki_acknowledgements, r###" USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON "###, $pki_acknowledgements, " TO ", $access_role, r###";
GRANT UPDATE(revision,digest,confirmed_at) ON "###, $pki_acknowledgements, " TO ", $access_role, r###";
CREATE TABLE "###, $pki_revocations, r###" (tenant_id uuid NOT NULL, purpose text NOT NULL CHECK(purpose IN ('windows','apple','agent','agent_bootstrap','da_device')), issuer text NOT NULL, serial text NOT NULL CHECK(serial ~ '^[1-9][0-9]*$'), attempt uuid NOT NULL, state text NOT NULL CHECK(state IN ('pending','submitted','published')), failures integer NOT NULL DEFAULT 0 CHECK(failures BETWEEN 0 AND 32), next_attempt timestamptz NOT NULL DEFAULT clock_timestamp(), crl_number bigint, PRIMARY KEY(tenant_id,purpose,issuer,serial), UNIQUE(tenant_id,attempt));
ALTER TABLE "###, $pki_revocations, r###" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "###, $pki_revocations, r###" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON "###, $pki_revocations, r###" USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON "###, $pki_revocations, " TO ", $access_role, r###";
GRANT UPDATE(state,failures,next_attempt,crl_number) ON "###, $pki_revocations, " TO ", $access_role, r###";
CREATE TABLE "###, $pki_crls, r###" (tenant_id uuid NOT NULL, purpose text NOT NULL CHECK(purpose IN ('windows','apple','agent','agent_bootstrap','da_device')), issuer text NOT NULL, number bigint NOT NULL CHECK(number>=0), this_update bigint NOT NULL, next_update bigint NOT NULL CHECK(next_update>this_update), der bytea NOT NULL CHECK(octet_length(der) BETWEEN 1 AND 16777216), PRIMARY KEY(tenant_id,purpose,issuer));
ALTER TABLE "###, $pki_crls, r###" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "###, $pki_crls, r###" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON "###, $pki_crls, r###" USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON "###, $pki_crls, " TO ", $access_role, r###";
GRANT UPDATE(number,this_update,next_update,der) ON "###, $pki_crls, " TO ", $access_role, r###";
CREATE UNIQUE INDEX "###, $index_one_open_rotation, " ON ", $pki_rotations, r###"(tenant_id,purpose) WHERE state<>'retired';
CREATE UNIQUE INDEX "###, $index_one_active_issuer, " ON ", $pki_issuers, r###"(tenant_id,purpose) WHERE state='active';

CREATE TABLE "###, $pki_trust, r###" (tenant_id uuid NOT NULL,purpose text NOT NULL,revision bigint NOT NULL CHECK(revision>0),body bytea NOT NULL CHECK(octet_length(body) BETWEEN 1 AND 67108864),PRIMARY KEY(tenant_id,purpose));
ALTER TABLE "###, $pki_trust, r###" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "###, $pki_trust, r###" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON "###, $pki_trust, r###" USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON "###, $pki_trust, " TO ", $access_role, r###";
GRANT UPDATE(revision,body) ON "###, $pki_trust, " TO ", $access_role, r###";
CREATE TABLE "###, $pki_operations, r###"(tenant_id uuid NOT NULL,actor text NOT NULL,instance text NOT NULL,operation uuid NOT NULL,phase text NOT NULL,digest bytea NOT NULL CHECK(octet_length(digest)=32),receipt bytea NOT NULL CHECK(octet_length(receipt) BETWEEN 1 AND 131072),PRIMARY KEY(tenant_id,actor,operation,phase));
ALTER TABLE "###, $pki_operations, r###" ADD COLUMN signing_recovery_attempt uuid;
ALTER TABLE "###, $pki_operations, " ADD CONSTRAINT signing_recovery_operation FOREIGN KEY(tenant_id,signing_recovery_attempt) REFERENCES ", $pki_signing, r###"(tenant_id,attempt);
ALTER TABLE "###, $pki_operations, r###" ADD CONSTRAINT signing_recovery_phase CHECK((phase='signing_recover')=(signing_recovery_attempt IS NOT NULL));
CREATE INDEX "###, $index_signing_recovery_operations, " ON ", $pki_operations, r###"(tenant_id,signing_recovery_attempt,actor,operation) WHERE signing_recovery_attempt IS NOT NULL;
ALTER TABLE "###, $pki_operations, r###" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "###, $pki_operations, r###" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON "###, $pki_operations, r###" USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON "###, $pki_operations, " TO ", $access_role, r###";

ALTER TABLE "###, $pki_certificates, " ADD CONSTRAINT issuer_generation FOREIGN KEY(tenant_id,purpose,issuer) REFERENCES ", $pki_issuers, r###"(tenant_id,purpose,digest);
ALTER TABLE "###, $pki_signing, " ADD CONSTRAINT issuer_generation FOREIGN KEY(tenant_id,purpose,issuer) REFERENCES ", $pki_issuers, r###"(tenant_id,purpose,digest);
ALTER TABLE "###, $pki_revocations, " ADD CONSTRAINT issued_certificate FOREIGN KEY(tenant_id,purpose,issuer,serial) REFERENCES ", $pki_certificates, r###"(tenant_id,purpose,issuer,serial);
CREATE TABLE "###, $pki_installations, r###"(tenant_id uuid NOT NULL,purpose text NOT NULL CHECK(purpose IN ('windows','apple','agent','agent_bootstrap','da_device')),registration uuid NOT NULL,
 revision bigint NOT NULL CHECK(revision>0),digest text NOT NULL CHECK(digest ~ '^[0-9a-f]{64}$'),body bytea NOT NULL CHECK(octet_length(body) BETWEEN 1 AND 67108864),
 confirmed_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(tenant_id,purpose,registration),
 FOREIGN KEY(tenant_id,registration) REFERENCES "###, $registrations, r###"(tenant_id,id));
ALTER TABLE "###, $pki_installations, r###" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "###, $pki_installations, r###" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON "###, $pki_installations, r###" USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON "###, $pki_installations, " TO ", $access_role, r###";
GRANT UPDATE(revision,digest,body,confirmed_at) ON "###, $pki_installations, " TO ", $access_role, r###";
-- Native participants borrow the Execution transaction; only trust delivery and
-- installation acknowledgements are available to that role.
GRANT USAGE ON SCHEMA "###, $pki_schema, " TO ", $command_role, ",", $policy_role, r###";
GRANT SELECT ON "###, $pki_rotations, ",", $pki_trust, " TO ", $command_role, r###";
GRANT SELECT,INSERT ON "###, $pki_installations, ",", $pki_acknowledgements, " TO ", $command_role, r###";
GRANT UPDATE(revision,digest,body,confirmed_at) ON "###, $pki_installations, " TO ", $command_role, r###";
GRANT UPDATE(revision,digest,confirmed_at) ON "###, $pki_acknowledgements, " TO ", $command_role, r###";


-- Fixed tenant-scoped presentation relation. Exact trust publication and certificate
-- qualification commit together; queued revocations take effect immediately.
CREATE VIEW "###, $pki_current_certificates, r###" WITH (security_barrier=true) AS
WITH current_trust AS MATERIALIZED (
 SELECT tenant_id,purpose,sha256(body) AS digest FROM "###, $pki_trust, r###"
 WHERE tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid
)
SELECT c.tenant_id,c.purpose,c.fingerprint,c.verification_end AS valid_until
FROM "###, $pki_certificates, r###" c JOIN current_trust t USING(tenant_id,purpose)
WHERE c.tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid
 AND c.verification_version=1 AND c.verification_trust=t.digest
 AND c.verification_start<=floor(extract(epoch FROM statement_timestamp()))::bigint
 AND c.verification_end>floor(extract(epoch FROM statement_timestamp()))::bigint
 AND NOT EXISTS(SELECT FROM "###, $pki_revocations, r###" r
  WHERE (r.tenant_id,r.purpose,r.issuer,r.serial)=(c.tenant_id,c.purpose,c.issuer,c.serial));
REVOKE ALL ON "###, $pki_current_certificates, r###" FROM PUBLIC;
GRANT SELECT ON "###, $pki_current_certificates, " TO ", $access_role, r###";
-- Registration retirement queues revocation; the PKI worker owns later delivery.
GRANT INSERT ON "###, $pki_revocations, " TO ", $command_role, r###";
COMMIT;
"###),
                observations: concat!(r###"BEGIN;
CREATE TABLE "###, $pki_trust_observations, r###" (
 tenant_id uuid NOT NULL, registration uuid NOT NULL, generation bigint NOT NULL CHECK(generation>0),
 sequence bigint NOT NULL CHECK(sequence>0), operation uuid NOT NULL,
 body jsonb NOT NULL CHECK(jsonb_typeof(body)='object'),
 received_at bigint NOT NULL DEFAULT floor(extract(epoch FROM clock_timestamp()))::bigint,
 PRIMARY KEY(tenant_id,registration,generation,sequence), UNIQUE(tenant_id,operation)
);
ALTER TABLE "###, $pki_trust_observations, r###" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "###, $pki_trust_observations, r###" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON "###, $pki_trust_observations, r###" USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON "###, $pki_trust_observations, r###" FROM PUBLIC;
GRANT SELECT,INSERT ON "###, $pki_trust_observations, " TO ", $access_role, r###";
COMMIT;
"###),
                certificates_record_candidate_in_1: concat!("INSERT INTO ", $pki_certificates, "(tenant_id,purpose,fingerprint,issuer,serial,registration,not_after,certificate,verification_version,verification_trust,verification_start,verification_end) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT(tenant_id,purpose,fingerprint) DO NOTHING"),
                certificates_record_candidate_in_2: concat!("SELECT registration,certificate,issuer,(verification_version=$4 AND verification_trust=$5 AND verification_start IS NOT DISTINCT FROM $6 AND verification_end IS NOT DISTINCT FROM $7) AS verified FROM ", $pki_certificates, " WHERE tenant_id=$1::uuid AND purpose=$2 AND fingerprint=$3"),
                certificates_record_candidate_in_3: concat!("UPDATE ", $pki_certificates, " SET registration=$4 WHERE tenant_id=$1::uuid AND purpose=$2 AND fingerprint=$3 AND registration IS NULL"),
                certificates_revoke_registration_in_1: concat!("SELECT purpose,issuer,serial FROM ", $pki_certificates, " WHERE tenant_id=$1::uuid AND registration=$2 AND not_after>floor(extract(epoch FROM clock_timestamp()))::bigint"),
                certificates_enqueue_in_1: concat!("INSERT INTO ", $pki_revocations, "(tenant_id,purpose,issuer,serial,attempt,state) VALUES($1::uuid,$2,$3,$4,$5,'pending') ON CONFLICT(tenant_id,purpose,issuer,serial) DO NOTHING"),
                certificates_revoke_credential_in_1: concat!("SELECT cert.purpose,cert.issuer,cert.serial FROM ", $pki_certificates, " cert JOIN ", $credentials, " k ON k.tenant_id=cert.tenant_id AND k.registration=cert.registration AND k.locator=encode(cert.fingerprint,'hex') WHERE k.tenant_id=$1::uuid AND k.id=$2 AND cert.not_after>floor(extract(epoch FROM clock_timestamp()))::bigint"),
                certificates_revoke_attempt_in_1: concat!("SELECT purpose,issuer,chain FROM ", $pki_signing, " WHERE tenant_id=$1::uuid AND attempt=$2 AND state='issued'"),
                certificates_current_native_credential_in_1: concat!("SELECT cert.certificate,trust.body,EXISTS(SELECT 1 FROM ", $pki_revocations, " v WHERE v.tenant_id=cert.tenant_id AND v.purpose=cert.purpose AND v.issuer=cert.issuer AND v.serial=cert.serial) AS revoked FROM ", $pki_certificates, " cert JOIN ", $credentials, " k ON k.tenant_id=cert.tenant_id AND k.registration=cert.registration AND k.locator=encode(cert.fingerprint,'hex') JOIN ", $pki_trust, " trust ON trust.tenant_id=cert.tenant_id AND trust.purpose=cert.purpose WHERE cert.tenant_id=$1::uuid AND cert.registration=$2 AND cert.purpose=$3 AND k.state='active' ORDER BY k.id LIMIT 2"),
                observations_record_in_1: concat!("INSERT INTO ", $pki_trust_observations, "(tenant_id,registration,generation,sequence,operation,body) VALUES($1::uuid,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING"),
                observations_record_in_2: concat!("SELECT body FROM ", $pki_trust_observations, " WHERE tenant_id=$1::uuid AND operation=$2"),
                observations_latest_in_1: concat!("SELECT o.body,o.received_at FROM ", $pki_trust_observations, " o JOIN ", $registrations, " r ON (r.tenant_id,r.id,r.generation)=(o.tenant_id,o.registration,o.generation) WHERE r.tenant_id=$1::uuid AND r.device=$2 AND r.channel='agent' AND r.state='active' ORDER BY o.sequence DESC LIMIT 1"),
                maintenance_health_1: concat!("SELECT count(*) FROM ", $pki_revocations, " WHERE tenant_id=$1 AND purpose=$2 AND issuer=$3 AND state<>'published'"),
                maintenance_publish_set_1: concat!("SELECT body FROM ", $pki_trust, " WHERE tenant_id=$1 AND purpose=$2 FOR UPDATE"),
                maintenance_publish_set_2: concat!("UPDATE ", $pki_revocations, " SET state='published',crl_number=$4 WHERE tenant_id=$1 AND purpose=$2 AND issuer=$3 AND serial=ANY($5) AND state<>'published'"),
                maintenance_claim_1: concat!("SELECT serial,attempt,failures FROM ", $pki_revocations, " WHERE tenant_id=$1 AND purpose=$2 AND issuer=$3 AND state<>'published' AND next_attempt<=clock_timestamp() ORDER BY next_attempt,attempt LIMIT 1 FOR UPDATE SKIP LOCKED"),
                maintenance_claim_2: concat!("UPDATE ", $pki_revocations, " SET failures=least(failures+1,32),next_attempt=clock_timestamp()+make_interval(secs=>$4) WHERE tenant_id=$1 AND purpose=$2 AND attempt=$3"),
                maintenance_submitted_1: concat!("UPDATE ", $pki_revocations, " SET state='submitted' WHERE tenant_id=$1 AND purpose=$2 AND attempt=$3 AND state='pending'"),
                operation_diagnostics: concat!("SELECT phase,receipt FROM ", $pki_operations, " WHERE tenant_id=$1::uuid AND actor=$2 AND instance=$3 AND operation=$4 ORDER BY phase LIMIT 17"),
                mutation_replay_1: concat!("SELECT instance,digest,receipt FROM ", $pki_operations, " WHERE tenant_id=$1::uuid AND actor=$2 AND operation=$3 AND phase=$4"),
                mutation_save_result_1: concat!("INSERT INTO ", $pki_operations, "(tenant_id,actor,instance,operation,phase,digest,receipt,signing_recovery_attempt) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8)"),
                registry_admit_selected_1: concat!("SELECT body FROM ", $pki_trust, " WHERE tenant_id=$1::uuid AND purpose=$2"),
                registry_admit_selected_2: concat!("SELECT chain FROM ", $pki_issuers, " WHERE tenant_id=$1::uuid AND purpose=$2"),
                registry_admit_selected_3: concat!("SELECT body FROM ", $pki_trust, " WHERE tenant_id=$1 AND purpose=$2 FOR UPDATE"),
                registry_synchronize_1: concat!("SELECT body FROM ", $pki_trust, " WHERE tenant_id=$1 AND purpose=$2"),
                registry_transition_1: concat!("SELECT previous,candidate,revision,state FROM ", $pki_rotations, " WHERE tenant_id=$1::uuid AND id=$2 AND purpose=$3"),
                registry_acknowledge_in_1: concat!("SELECT revision,digest FROM ", $pki_installations, " WHERE tenant_id=$1::uuid AND purpose=$2 AND registration=$3 FOR UPDATE"),
                registry_acknowledge_in_2: concat!("INSERT INTO ", $pki_installations, "(tenant_id,purpose,registration,revision,digest,body) VALUES($1::uuid,$2,$3,$4,$5,$6) ON CONFLICT(tenant_id,purpose,registration) DO UPDATE SET revision=excluded.revision,digest=excluded.digest,body=excluded.body,confirmed_at=clock_timestamp()"),
                registry_acknowledge_in_3: concat!("INSERT INTO ", $pki_acknowledgements, "(tenant_id,rotation,registration,revision,digest) SELECT $1::uuid,id,$2,$3,$4 FROM ", $pki_rotations, " WHERE tenant_id=$1::uuid AND purpose=$5 AND state='distributing' ON CONFLICT(tenant_id,rotation,registration) DO UPDATE SET revision=excluded.revision,digest=excluded.digest,confirmed_at=clock_timestamp()"),
                registry_rotation_replay_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $pki_operations, " WHERE tenant_id=$1::uuid AND actor=$2 AND operation=$3 AND phase=$4)"),
                registry_write_1: concat!("SELECT revision FROM ", $pki_trust, " WHERE tenant_id=$1::uuid AND purpose=$2 FOR UPDATE"),
                registry_write_2: concat!("INSERT INTO ", $pki_rotations, "(tenant_id,id,purpose,previous,candidate,revision,state) VALUES($1::uuid,$2,$3,$4,$5,$6,'distributing')"),
                registry_write_3: concat!("UPDATE ", $pki_rotations, " SET state=$3 WHERE tenant_id=$1::uuid AND id=$2"),
                registry_persist_1: concat!("INSERT INTO ", $pki_trust, "(tenant_id,purpose,revision,body) VALUES($1,$2,$3,$4) ON CONFLICT(tenant_id,purpose) DO UPDATE SET revision=excluded.revision,body=excluded.body"),
                registry_persist_2: concat!("UPDATE ", $pki_issuers, " SET state='retired' WHERE tenant_id=$1 AND purpose=$2 AND digest<>ALL($3)"),
                registry_persist_3: concat!("UPDATE ", $pki_issuers, " SET state='verify_only' WHERE tenant_id=$1 AND purpose=$2 AND state='active' AND digest<>$3"),
                registry_persist_4: concat!("SELECT number,this_update,der FROM ", $pki_crls, " WHERE tenant_id=$1 AND purpose=$2 AND issuer=$3 FOR UPDATE"),
                registry_persist_5: concat!("INSERT INTO ", $pki_crls, "(tenant_id,purpose,issuer,number,this_update,next_update,der) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(tenant_id,purpose,issuer) DO UPDATE SET number=excluded.number,this_update=excluded.this_update,next_update=excluded.next_update,der=excluded.der"),
                registry_persist_6: concat!("INSERT INTO ", $pki_issuers, "(tenant_id,purpose,digest,revision,state,chain,provider,not_after) VALUES($1,$2,$3,$4,$5,$6,$8,$7) ON CONFLICT(tenant_id,purpose,digest) DO UPDATE SET state=excluded.state"),
                registry_current_certificate_in_1: concat!("SELECT k.certificate,t.body,floor(extract(epoch FROM clock_timestamp()))::bigint AS now FROM ", $pki_certificates, " k JOIN ", $pki_trust, " t USING(tenant_id,purpose) WHERE k.tenant_id=$1::uuid AND k.purpose=$2 AND k.fingerprint=$3 AND NOT EXISTS(SELECT 1 FROM ", $pki_revocations, " r WHERE r.tenant_id=k.tenant_id AND r.purpose=k.purpose AND r.issuer=k.issuer AND r.serial=k.serial)"),
                registry_current_certificates_in_1: concat!("SELECT fingerprint FROM ", $pki_current_certificates, " WHERE tenant_id=$1::uuid AND purpose=$2 AND fingerprint=ANY($3)"),
                registry_trust_on_1: concat!("SELECT body FROM ", $pki_trust, " WHERE tenant_id=$1::uuid AND purpose=$2"),
                registry_retained_issuer_on_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $pki_issuers, " WHERE tenant_id=$1::uuid AND purpose=$2 AND digest=$3 AND state IN('active','verify_only'))"),
                recovery_recover_1: concat!("SELECT binding FROM ", $pki_signing, " WHERE tenant_id=$1::uuid AND attempt=$2"),
                recovery_adopt_in_1: concat!("SELECT binding,state,chain FROM ", $pki_signing, " WHERE tenant_id=$1::uuid AND attempt=$2 FOR UPDATE"),
                recovery_adopt_in_2: concat!("UPDATE ", $pki_signing, " SET state='issued',chain=$3 WHERE tenant_id=$1::uuid AND attempt=$2"),
                signing_authorize_in_1: concat!("INSERT INTO ", $pki_signing, "(tenant_id,attempt,purpose,issuer,binding,deadline,digest,state) VALUES($1,$2,$3,$4,$5,$6,$7,'prepared')"),
                signing_supersede_expired_in_1: concat!("SELECT binding,state FROM ", $pki_signing, " WHERE tenant_id=$1 AND attempt=$2 FOR UPDATE"),
                signing_supersede_expired_in_2: concat!("UPDATE ", $pki_signing, " SET state='superseded',successor=$3 WHERE tenant_id=$1 AND attempt=$2 AND state='prepared'"),
                signing_require_active_in_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $pki_issuers, " WHERE tenant_id=$1 AND purpose=$2 AND digest=$3 AND state='active')"),
                signing_issue_1: concat!("SELECT binding,state,chain FROM ", $pki_signing, " WHERE tenant_id=$1 AND attempt=$2 FOR UPDATE"),
                signing_issue_2: concat!("UPDATE ", $pki_signing, " SET state='signing' WHERE tenant_id=$1 AND attempt=$2 AND state='prepared'"),
                signing_settle_1: concat!("SELECT binding,digest,state,chain FROM ", $pki_signing, " WHERE tenant_id=$1 AND attempt=$2 FOR UPDATE"),
                signing_settle_2: concat!("UPDATE ", $pki_signing, " SET state=$3,chain=$4 WHERE tenant_id=$1 AND attempt=$2"),
                signing_queries_read_many_in_1: concat!("SELECT attempt,purpose,issuer,state,binding,digest,deadline,successor,floor(extract(epoch FROM created_at))::bigint AS created_at FROM ", $pki_signing, " WHERE tenant_id=$1::uuid AND attempt=ANY($2)"),
                signing_queries_operations_in_1: concat!("SELECT jsonb_build_object('actor',actor,'instance',instance,'operationId',operation) FROM ", $pki_operations, " WHERE tenant_id="),
                signing_queries_operation_in_1: concat!("SELECT o.instance,o.receipt,s.chain FROM ", $pki_operations, " o JOIN ", $pki_signing, " s ON (s.tenant_id,s.attempt)=(o.tenant_id,o.signing_recovery_attempt) WHERE o.tenant_id=$1::uuid AND o.actor=$2 AND o.operation=$3 AND o.phase='signing_recover' AND o.signing_recovery_attempt=$4 AND s.purpose='windows'"),
                qualification_for_certificate_in_1: concat!("SELECT body FROM ", $pki_trust, " WHERE tenant_id=$1::uuid AND purpose=$2 FOR SHARE"),
                qualification_publish_in_1: concat!("SELECT fingerprint,certificate FROM ", $pki_certificates, " WHERE tenant_id=$1::uuid AND purpose=$2 AND fingerprint>$3 AND (verification_trust<>$4 OR verification_version<>$5) ORDER BY fingerprint LIMIT 128"),
                qualification_publish_in_2: concat!("UPDATE ", $pki_certificates, " c SET verification_version=$3,verification_trust=$4,verification_start=q.start,verification_end=q.finish FROM unnest($5::bytea[],$6::bigint[],$7::bigint[]) q(fingerprint,start,finish) WHERE c.tenant_id=$1::uuid AND c.purpose=$2 AND c.fingerprint=q.fingerprint"),
                rotation_gates_require_1: concat!("SELECT state FROM ", $pki_rotations, " WHERE tenant_id=$1::uuid AND id=$2"),
                rotation_mod_rotation_1: concat!("SELECT r.id,r.previous,r.candidate,r.revision,r.state,t.body,t.revision AS trust_revision,i.state AS previous_state,j.state AS candidate_state FROM ", $pki_rotations, " r JOIN ", $pki_trust, " t USING(tenant_id,purpose) JOIN ", $pki_issuers, " i ON i.tenant_id=r.tenant_id AND i.purpose=r.purpose AND i.digest=r.previous JOIN ", $pki_issuers, " j ON j.tenant_id=r.tenant_id AND j.purpose=r.purpose AND j.digest=r.candidate WHERE r.tenant_id=$1::uuid AND r.purpose=$2 AND ($3::uuid IS NULL OR r.id=$3) ORDER BY r.revision DESC,r.id DESC LIMIT 1"),
                rotation_mod_rotation_2: concat!("SELECT actor,instance,receipt,phase FROM ", $pki_operations, " WHERE tenant_id=$1::uuid AND operation=$2 AND phase IN ('distributing','activated','retired') ORDER BY phase,actor LIMIT 4"),
                rotation_mod_rotation_blockers_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $pki_rotations, " WHERE tenant_id=$1::uuid AND purpose=$2 AND id=$3)"),
                object_manifest: concat!(r###"{"tables":[""###, $pki_acknowledgements, r###"",""###, $pki_certificates, r###"",""###, $pki_crls, r###"",""###, $pki_installations, r###"",""###, $pki_issuers, r###"",""###, $pki_operations, r###"",""###, $pki_revocations, r###"",""###, $pki_rotations, r###"",""###, $pki_signing, r###"",""###, $pki_trust, r###"",""###, $pki_trust_observations, r###""],"views":[""###, $pki_current_certificates, r###""],"functions":[]}"###),
                rotation_relations: concat!(r###"
), rotation AS (
 SELECT r.*,p.now FROM "###, $pki_rotations, r###" r JOIN params p ON r.tenant_id=p.tenant AND r.id=p.id
), blockers AS (
 SELECT 'missing_ack'::text AS kind,r.id::text AS id,r.device,r.id AS registration,r.generation,
        r.state,NULL::bigint AS deadline,NULL::text AS revocation_state
 FROM rotation x JOIN "###, $registrations, r###" r ON r.tenant_id=x.tenant_id
 WHERE x.state='distributing' AND r.state='active'
 AND ((r.channel='agent' AND x.purpose='agent') OR (r.channel IS NULL AND r.purpose='da_device' AND x.purpose='da_device') OR (r.channel='mdm' AND EXISTS(
   SELECT 1 FROM "###, $requests, r###" q WHERE q.tenant_id=r.tenant_id AND q.id=r.request_id
   AND q.source=CASE x.purpose WHEN 'windows' THEN 'mdm.windows' WHEN 'apple' THEN 'mdm.apple' ELSE x.purpose END)))
 AND NOT EXISTS(SELECT 1 FROM "###, $pki_acknowledgements, r###" a WHERE a.tenant_id=r.tenant_id
   AND a.registration=r.id AND a.rotation=x.id AND a.revision>=x.revision)
 UNION ALL
 SELECT 'unresolved_signing',s.attempt::text,NULL,NULL,NULL,s.state,s.deadline,NULL
 FROM rotation x JOIN "###, $pki_signing, r###" s ON s.tenant_id=x.tenant_id AND s.purpose=x.purpose AND s.issuer=x.previous
 WHERE x.state='activated' AND (s.state IN ('signing','unknown') OR (s.state='prepared' AND s.deadline>x.now))
 UNION ALL
 SELECT 'unsettled_bootstrap',b.id::text,NULL,NULL,NULL,b.state,b.deadline,NULL
 FROM rotation x JOIN "###, $agent_bootstraps, r###" b ON b.tenant_id=x.tenant_id AND b.issuer=x.previous
 WHERE x.state='activated' AND x.purpose='agent_bootstrap'
 AND (b.state='signing' OR (b.state IN ('prepared','issued','consumed') AND b.deadline>x.now))
"###, $native_scep, r###" UNION ALL
 SELECT 'outstanding_certificate',encode(c.fingerprint,'hex'),r.device,c.registration,r.generation,
        'issued',c.not_after,v.state
 FROM rotation x JOIN "###, $pki_certificates, r###" c ON c.tenant_id=x.tenant_id AND c.purpose=x.purpose AND c.issuer=x.previous
 LEFT JOIN "###, $registrations, r###" r ON r.tenant_id=c.tenant_id AND r.id=c.registration
 LEFT JOIN "###, $pki_revocations, r###" v ON (v.tenant_id,v.purpose,v.issuer,v.serial)=(c.tenant_id,c.purpose,c.issuer,c.serial)
 WHERE x.state='activated' AND c.not_after>x.now AND (v.state IS NULL OR v.state<>'published')
)
"###),
                access_contract: concat!(r###"{"tables":[{"###, $contract_issuers, r###","read_write":true,"updates":["state"],"delete_policy":null},{"###, $contract_signing, r###","read_write":true,"updates":["state","chain","successor"],"delete_policy":null},{"###, $contract_certificates, r###","read_write":true,"updates":["registration","verification_version","verification_trust","verification_start","verification_end"],"delete_policy":null},{"###, $contract_rotations, r###","read_write":true,"updates":["state"],"delete_policy":null},{"###, $contract_acknowledgements, r###","read_write":true,"updates":["revision","digest","confirmed_at"],"delete_policy":null},{"###, $contract_revocations, r###","read_write":true,"updates":["state","failures","next_attempt","crl_number"],"delete_policy":null},{"###, $contract_crls, r###","read_write":true,"updates":["number","this_update","next_update","der"],"delete_policy":null},{"###, $contract_trust, r###","read_write":true,"updates":["revision","body"],"delete_policy":null},{"###, $contract_operations, r###","read_write":true,"updates":[],"delete_policy":null},{"###, $contract_installations, r###","read_write":true,"updates":["revision","digest","body","confirmed_at"],"delete_policy":null},{"###, $contract_trust_observations, r###","read_write":true,"updates":[],"delete_policy":null}],"functions":[],"external_relations":[""###, $pki_current_certificates, r###""],"verified_schemas":[]}"###),
            };
        }
    };
}
define_storage!(
    mdm,
    "mdm_pki.acknowledgements",
    "mdm_pki.certificates",
    "mdm_pki.crls",
    "mdm_pki.current_certificates",
    "mdm_pki.installations",
    "mdm_pki.issuers",
    "mdm_pki.operations",
    "mdm_pki.revocations",
    "mdm_pki.rotations",
    "mdm_pki.signing",
    "mdm_pki.trust",
    "mdm_pki.trust_observations",
    "mdm_pki",
    "mdm_access.registrations",
    "mdm_access.credentials",
    "mdm_access.certificate_grants",
    "mdm_access",
    "mdm_access",
    "mdm_command_runtime",
    "mdm_policy_runtime",
    "mdm_owner",
    "one_open_rotation",
    "one_active_issuer",
    "signing_recovery_operations",
    "mdm_access.requests",
    "mdm_access.agent_bootstraps",
    "mdm_access.registration_operations",
    r###" UNION ALL
 SELECT 'unsettled_scep',s.id::text,NULL,s.registration,s.generation,s.state,
        floor(extract(epoch FROM s.expires_at))::bigint,NULL
 FROM rotation x JOIN mdm_apple.scep_attempts s ON s.tenant_id=x.tenant_id AND encode(s.issuer,'hex')=x.previous
 WHERE x.state='activated' AND x.purpose='apple'
 AND ((s.state='consumed' AND s.certificate IS NULL) OR (s.state='prepared' AND s.expires_at>clock_timestamp()))
"###,
    r###""schema":"mdm_pki","table":"issuers""###,
    r###""schema":"mdm_pki","table":"signing""###,
    r###""schema":"mdm_pki","table":"certificates""###,
    r###""schema":"mdm_pki","table":"rotations""###,
    r###""schema":"mdm_pki","table":"acknowledgements""###,
    r###""schema":"mdm_pki","table":"revocations""###,
    r###""schema":"mdm_pki","table":"crls""###,
    r###""schema":"mdm_pki","table":"trust""###,
    r###""schema":"mdm_pki","table":"operations""###,
    r###""schema":"mdm_pki","table":"installations""###,
    r###""schema":"mdm_pki","table":"trust_observations""###
);
define_storage!(
    da,
    "rss_da.pki_acknowledgements",
    "rss_da.pki_certificates",
    "rss_da.pki_crls",
    "rss_da.pki_current_certificates",
    "rss_da.pki_installations",
    "rss_da.pki_issuers",
    "rss_da.pki_operations",
    "rss_da.pki_revocations",
    "rss_da.pki_rotations",
    "rss_da.pki_signing",
    "rss_da.pki_trust",
    "rss_da.pki_trust_observations",
    "rss_da",
    "rss_da.registrations",
    "rss_da.credentials",
    "rss_da.certificate_grants",
    "rss_da",
    "da_access",
    "da_command_runtime",
    "da_policy_runtime",
    "da_owner",
    "pki_one_open_rotation",
    "pki_one_active_issuer",
    "pki_signing_recovery_operations",
    "rss_da.requests",
    "rss_da.agent_bootstraps",
    "rss_da.registration_operations",
    "",
    r###""schema":"rss_da","table":"pki_issuers""###,
    r###""schema":"rss_da","table":"pki_signing""###,
    r###""schema":"rss_da","table":"pki_certificates""###,
    r###""schema":"rss_da","table":"pki_rotations""###,
    r###""schema":"rss_da","table":"pki_acknowledgements""###,
    r###""schema":"rss_da","table":"pki_revocations""###,
    r###""schema":"rss_da","table":"pki_crls""###,
    r###""schema":"rss_da","table":"pki_trust""###,
    r###""schema":"rss_da","table":"pki_operations""###,
    r###""schema":"rss_da","table":"pki_installations""###,
    r###""schema":"rss_da","table":"pki_trust_observations""###
);
pub(crate) const fn sql(profile: StorageProfile) -> &'static Statements {
    match profile {
        StorageProfile::Mdm => &mdm::SQL,
        StorageProfile::Da => &da::SQL,
    }
}
