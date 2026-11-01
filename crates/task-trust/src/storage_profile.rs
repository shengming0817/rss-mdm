//! Fixed, owner-owned SQL. Only these source literals can select objects.
use rss_mdm_install_support::StorageProfile;
pub(crate) struct Statements {
    pub install: &'static str,
    pub observations_install: &'static str,
    pub trust_lock_1: &'static str,
    pub trust_lock_2: &'static str,
    pub trust_current_1: &'static str,
    pub trust_installation_service_1: &'static str,
    pub trust_replay_1: &'static str,
    pub trust_save_1: &'static str,
    pub trust_save_2: &'static str,
    pub trust_prepare_1: &'static str,
    pub trust_prepare_2: &'static str,
    pub trust_prepare_3: &'static str,
    pub trust_activate_1: &'static str,
    pub trust_acknowledge_1: &'static str,
    pub trust_acknowledge_2: &'static str,
    pub trust_acknowledge_3: &'static str,
    pub trust_acknowledge_4: &'static str,
    pub trust_require_issue_1: &'static str,
    pub trust_load_1: &'static str,
    pub trust_selected_trust_1: &'static str,
    pub trust_operation_1: &'static str,
    pub trust_retire_1: &'static str,
    pub trust_rewrap_1: &'static str,
    pub trust_rewrap_2: &'static str,
    pub observations_record_in_1: &'static str,
    pub observations_record_in_2: &'static str,
    pub observations_latest_in_1: &'static str,
    pub service_change_task_trust_1: &'static str,
    pub service_acknowledge_task_trust_1: &'static str,
    pub object_manifest: &'static str,
    pub access_contract: &'static str,
}
macro_rules! define_storage {
    ($module:ident, $schema:literal, $heads:literal, $keys:literal, $versions:literal, $acknowledgements:literal, $observations:literal, $registrations:literal, $installation:literal, $access:literal, $command:literal, $policy:literal, $telemetry:literal, $contract_table_12:literal, $contract_table_13:literal, $contract_table_14:literal, $contract_table_15:literal, $contract_table_16:literal) => {
        mod $module {
            pub(super) const SQL: super::Statements = super::Statements {
                install: concat!(r###"BEGIN;
CREATE SCHEMA IF NOT EXISTS "###, $schema, r###";
CREATE TABLE "###, $heads, r###" (
 tenant_id uuid PRIMARY KEY, revision bigint NOT NULL CHECK(revision>=0)
);
CREATE TABLE "###, $keys, r###" (
 tenant_id uuid NOT NULL, key_id text NOT NULL, private_key bytea NOT NULL,
 PRIMARY KEY(tenant_id,key_id)
);
CREATE TABLE "###, $versions, r###" (
 tenant_id uuid NOT NULL, revision bigint NOT NULL CHECK(revision>0),
 operation_id uuid NOT NULL, fingerprint_key text NOT NULL,
 fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),
 body jsonb NOT NULL CHECK(jsonb_typeof(body)='object'),
 digest text NOT NULL CHECK(digest ~ '^[0-9a-f]{64}$'),
 PRIMARY KEY(tenant_id,revision), UNIQUE(tenant_id,operation_id)
);
CREATE TABLE "###, $acknowledgements, r###" (
 tenant_id uuid NOT NULL, operation_id uuid NOT NULL, registration uuid NOT NULL,
 generation bigint NOT NULL CHECK(generation>0), revision bigint NOT NULL CHECK(revision>0),
 digest text NOT NULL, PRIMARY KEY(tenant_id,operation_id),
 FOREIGN KEY(tenant_id,revision) REFERENCES "###, $versions, r###"(tenant_id,revision)
);
ALTER TABLE "###, $heads, r###" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "###, $heads, r###" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON "###, $heads, r###" USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
ALTER TABLE "###, $keys, r###" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "###, $keys, r###" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON "###, $keys, r###" USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
ALTER TABLE "###, $versions, r###" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "###, $versions, r###" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON "###, $versions, r###" USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
ALTER TABLE "###, $acknowledgements, r###" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "###, $acknowledgements, r###" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON "###, $acknowledgements, r###" USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON SCHEMA "###, $schema, r###" FROM PUBLIC;
REVOKE ALL ON "###, $heads, ",", $keys, ",", $versions, ",", $acknowledgements, r###" FROM PUBLIC;
GRANT USAGE ON SCHEMA "###, $schema, " TO ", $access, ",", $command, r###";
GRANT SELECT,INSERT ON "###, $heads, ",", $keys, ",", $versions, ",", $acknowledgements, " TO ", $access, r###";
GRANT UPDATE(revision) ON "###, $heads, " TO ", $access, r###";
GRANT UPDATE(private_key) ON "###, $keys, " TO ", $access, r###";
GRANT SELECT ON "###, $heads, ",", $versions, ",", $acknowledgements, " TO ", $command, r###";
COMMIT;

GRANT USAGE ON SCHEMA "###, $schema, " TO ", $policy, r###";
GRANT SELECT ON "###, $heads, ",", $versions, ",", $acknowledgements, " TO ", $policy, r###";

-- Telemetry consumes public trust and the device acknowledgement in its original transaction.
GRANT USAGE ON SCHEMA "###, $schema, " TO ", $telemetry, r###";
GRANT SELECT(tenant_id,revision) ON "###, $heads, " TO ", $telemetry, r###";
GRANT SELECT(tenant_id,revision,body,digest) ON "###, $versions, " TO ", $telemetry, r###";
GRANT SELECT(tenant_id,registration,generation,revision,digest) ON "###, $acknowledgements, " TO ", $telemetry, r###";
"###),
                observations_install: concat!(r###"BEGIN;
CREATE TABLE "###, $observations, r###" (
 tenant_id uuid NOT NULL, registration uuid NOT NULL, generation bigint NOT NULL CHECK(generation>0),
 sequence bigint NOT NULL CHECK(sequence>0), operation uuid NOT NULL,
 body jsonb NOT NULL CHECK(jsonb_typeof(body)='object'),
 received_at bigint NOT NULL DEFAULT floor(extract(epoch FROM clock_timestamp()))::bigint,
 PRIMARY KEY(tenant_id,registration,generation,sequence), UNIQUE(tenant_id,operation)
);
ALTER TABLE "###, $observations, r###" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "###, $observations, r###" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON "###, $observations, r###" USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON "###, $observations, r###" FROM PUBLIC;
GRANT SELECT,INSERT ON "###, $observations, " TO ", $access, r###";
COMMIT;
"###),
                trust_lock_1: concat!("INSERT INTO ", $heads, "(tenant_id,revision) VALUES($1::uuid,0) ON CONFLICT DO NOTHING"),
                trust_lock_2: concat!("SELECT revision FROM ", $heads, " WHERE tenant_id=$1::uuid FOR UPDATE"),
                trust_current_1: concat!("SELECT v.body,v.revision,v.digest FROM ", $versions, " v JOIN ", $heads, " h USING(tenant_id,revision) WHERE tenant_id=$1::uuid"),
                trust_installation_service_1: concat!("SELECT instance_id FROM ", $installation),
                trust_replay_1: concat!("SELECT body,fingerprint_key,fingerprint FROM ", $versions, " WHERE tenant_id=$1::uuid AND operation_id=$2"),
                trust_save_1: concat!("INSERT INTO ", $versions, "(tenant_id,revision,operation_id,fingerprint_key,fingerprint,body,digest) VALUES($1::uuid,$2,$3,$4,$5,$6,$7)"),
                trust_save_2: concat!("UPDATE ", $heads, " SET revision=$2 WHERE tenant_id=$1::uuid"),
                trust_prepare_1: concat!("SELECT count(*) FROM ", $registrations, " WHERE tenant_id=$1::uuid AND channel='agent' AND state='active'"),
                trust_prepare_2: concat!("SELECT instance_id FROM ", $installation),
                trust_prepare_3: concat!("INSERT INTO ", $keys, "(tenant_id,key_id,private_key) VALUES($1::uuid,$2,$3)"),
                trust_activate_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $registrations, " r WHERE r.tenant_id=$1::uuid AND r.channel='agent' AND r.state='active' AND NOT EXISTS(SELECT 1 FROM ", $acknowledgements, " a JOIN ", $versions, " v USING(tenant_id,revision) WHERE a.tenant_id=r.tenant_id AND a.registration=r.id AND a.generation=r.generation AND a.digest=v.digest AND EXISTS(SELECT 1 FROM jsonb_array_elements(v.body->'keys') k WHERE k->>'id'=$2 AND k->>'state'='prepared')))"),
                trust_acknowledge_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $registrations, " WHERE tenant_id=$1::uuid AND id=$2 AND generation=$3 AND channel='agent' AND state='active')"),
                trust_acknowledge_2: concat!("SELECT digest FROM ", $versions, " WHERE tenant_id=$1::uuid AND revision=$2"),
                trust_acknowledge_3: concat!("INSERT INTO ", $acknowledgements, "(tenant_id,operation_id,registration,generation,revision,digest) VALUES($1::uuid,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING"),
                trust_acknowledge_4: concat!("SELECT registration=$3 AND generation=$4 AND revision=$5 AND digest=$6 FROM ", $acknowledgements, " WHERE tenant_id=$1::uuid AND operation_id=$2"),
                trust_require_issue_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $acknowledgements, " a JOIN ", $versions, " v USING(tenant_id,revision) WHERE a.tenant_id=$1::uuid AND a.registration=$2 AND a.generation=$3 AND a.digest=v.digest AND EXISTS(SELECT 1 FROM jsonb_array_elements(v.body->'keys') k WHERE k->>'id'=$4 AND k->>'state' IN('prepared','active')))"),
                trust_load_1: concat!("SELECT private_key FROM ", $keys, " WHERE tenant_id=$1::uuid AND key_id=$2"),
                trust_selected_trust_1: concat!("SELECT body,revision,digest FROM ", $versions, " WHERE tenant_id=$1::uuid AND revision=$2"),
                trust_operation_1: concat!("SELECT body FROM ", $versions, " WHERE tenant_id=$1::uuid AND operation_id=$2"),
                trust_retire_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $registrations, " r WHERE r.tenant_id=$1::uuid AND r.channel='agent' AND r.state='active' AND NOT EXISTS(SELECT 1 FROM ", $acknowledgements, " a JOIN ", $versions, " v USING(tenant_id,revision) WHERE a.tenant_id=r.tenant_id AND a.registration=r.id AND a.generation=r.generation AND a.digest=v.digest AND EXISTS(SELECT 1 FROM jsonb_array_elements(v.body->'keys') k WHERE k->>'id'=$2 AND k->>'state'='verify_only')))"),
                trust_rewrap_1: concat!("SELECT key_id,private_key FROM ", $keys, " WHERE tenant_id=$1::uuid AND substring(private_key FROM 1 FOR $2)<>$3 ORDER BY key_id LIMIT 64 FOR UPDATE"),
                trust_rewrap_2: concat!("UPDATE ", $keys, " SET private_key=$3 WHERE tenant_id=$1::uuid AND key_id=$2"),
                observations_record_in_1: concat!("INSERT INTO ", $observations, "(tenant_id,registration,generation,sequence,operation,body) VALUES($1::uuid,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING"),
                observations_record_in_2: concat!("SELECT body FROM ", $observations, " WHERE tenant_id=$1::uuid AND operation=$2"),
                observations_latest_in_1: concat!("SELECT o.body,o.received_at FROM ", $observations, " o JOIN ", $registrations, " r ON (r.tenant_id,r.id,r.generation)=(o.tenant_id,o.registration,o.generation) WHERE r.tenant_id=$1::uuid AND r.device=$2 AND r.channel='agent' AND r.state='active' ORDER BY o.sequence DESC LIMIT 1"),
                service_change_task_trust_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $versions, " WHERE tenant_id=$1::uuid AND operation_id=$2)"),
                service_acknowledge_task_trust_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $acknowledgements, " WHERE tenant_id=$1::uuid AND operation_id=$2)"),
                object_manifest: concat!(r###"{"tables":[""###, $acknowledgements, r###"",""###, $heads, r###"",""###, $keys, r###"",""###, $observations, r###"",""###, $versions, r###""],"functions":[],"views":[]}"###),
                access_contract: concat!(r###"{"tables":[{"###, $contract_table_12, r###","read_write":true,"updates":["revision"],"delete_policy":null},{"###, $contract_table_13, r###","read_write":true,"updates":["private_key"],"delete_policy":null},{"###, $contract_table_14, r###","read_write":true,"updates":[],"delete_policy":null},{"###, $contract_table_15, r###","read_write":true,"updates":[],"delete_policy":null},{"###, $contract_table_16, r###","read_write":true,"updates":[],"delete_policy":null}],"functions":[],"external_relations":[],"verified_schemas":[]}"###),
            };
        }
    };
}
define_storage!(
    mdm,
    "mdm_task_signing",
    "mdm_task_signing.heads",
    "mdm_task_signing.keys",
    "mdm_task_signing.versions",
    "mdm_task_signing.acknowledgements",
    "mdm_task_signing.trust_observations",
    "mdm_access.registrations",
    "public.mdm_installation",
    "mdm_access",
    "mdm_command_runtime",
    "mdm_policy_runtime",
    "mdm_telemetry_runtime",
    r###""schema":"mdm_task_signing","table":"heads""###,
    r###""schema":"mdm_task_signing","table":"keys""###,
    r###""schema":"mdm_task_signing","table":"versions""###,
    r###""schema":"mdm_task_signing","table":"acknowledgements""###,
    r###""schema":"mdm_task_signing","table":"trust_observations""###
);
define_storage!(
    da,
    "rss_da",
    "rss_da.signing_heads",
    "rss_da.signing_keys",
    "rss_da.signing_versions",
    "rss_da.signing_acknowledgements",
    "rss_da.signing_observations",
    "rss_da.registrations",
    "rss_da.installation_binding",
    "da_access",
    "da_command_runtime",
    "da_policy_runtime",
    "da_telemetry_runtime",
    r###""schema":"rss_da","table":"signing_heads""###,
    r###""schema":"rss_da","table":"signing_keys""###,
    r###""schema":"rss_da","table":"signing_versions""###,
    r###""schema":"rss_da","table":"signing_acknowledgements""###,
    r###""schema":"rss_da","table":"signing_observations""###
);
pub(crate) const fn sql(profile: StorageProfile) -> &'static Statements {
    match profile {
        StorageProfile::Mdm => &mdm::SQL,
        StorageProfile::Da => &da::SQL,
    }
}
