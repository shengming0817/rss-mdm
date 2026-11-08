//! Fixed, owner-owned SQL. Only these source literals can select objects.
use crate::Use;
use rss_mdm_install_support::StorageProfile;
pub(crate) struct Statements {
    pub configuration_save: &'static str,
    pub configuration_current: &'static str,
    pub configuration_receipt: &'static str,
    pub retain_until: &'static str,
    pub pending_until: &'static str,
    pub install: &'static str,
    pub observations_install: &'static str,
    pub trust_lock_1: &'static str,
    pub trust_lock_2: &'static str,
    pub trust_current_1: &'static str,
    pub trust_installation_service_1: &'static str,
    pub trust_replay_1: &'static str,
    pub trust_save_1: &'static str,
    pub trust_save_2: &'static str,
    pub trust_prepare_2: &'static str,
    pub trust_prepare_3: &'static str,
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
    ($module:ident, $usage:literal, $schema:literal, $exports:literal, $contract_exports:literal, $heads:literal, $keys:literal, $versions:literal, $acknowledgements:literal, $observations:literal, $installation:literal, $access:literal, $command:literal, $policy:literal, $telemetry:literal, $contract_table_12:literal, $contract_table_13:literal, $contract_table_14:literal, $contract_table_15:literal, $contract_table_16:literal) => {
        mod $module {
            pub(super) const SQL: super::Statements = super::Statements {
                configuration_save: concat!("INSERT INTO ",$exports,"(tenant_id,operation,actor,instance,request,configuration,revision,trust_revision,result,issued_at,expires_at) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)"),
                configuration_current: concat!("SELECT result FROM ",$exports," WHERE tenant_id=$1::uuid AND configuration=$2 AND revision=$3 AND request->>'delivery'='da' AND expires_at>floor(extract(epoch FROM clock_timestamp()))::bigint ORDER BY issued_at DESC,operation DESC LIMIT 1"),
                configuration_receipt: concat!("SELECT actor,instance,request,result FROM ",$exports," WHERE tenant_id=$1::uuid AND operation=$2"),
                retain_until: concat!("UPDATE ", $keys, " SET max_verify_until=greatest(max_verify_until,$3) WHERE usage='",$usage,"' AND tenant_id=$1::uuid AND key_id=$2"),
                pending_until: concat!("SELECT max_verify_until>floor(extract(epoch FROM clock_timestamp()))::bigint FROM ", $keys," WHERE usage='",$usage,"' AND tenant_id=$1::uuid AND key_id=$2"),
                install: concat!(r###"BEGIN;
CREATE SCHEMA IF NOT EXISTS "###, $schema, r###";
CREATE TABLE "###, $exports, r###" (
 tenant_id uuid NOT NULL,operation uuid NOT NULL,actor text NOT NULL,instance text NOT NULL,
 request jsonb NOT NULL CHECK(octet_length(request::text)<=98304),configuration uuid NOT NULL,
 revision bigint NOT NULL CHECK(revision>0),trust_revision bigint NOT NULL CHECK(trust_revision>0),result jsonb NOT NULL CHECK(octet_length(result::text)<=98304),
 issued_at bigint NOT NULL,expires_at bigint NOT NULL CHECK(expires_at>issued_at),
 PRIMARY KEY(tenant_id,operation)
);
ALTER TABLE "###,$exports,r###" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "###,$exports,r###" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON "###,$exports,r###" USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON "###,$exports,r###" FROM PUBLIC;
GRANT SELECT,INSERT ON "###,$exports," TO ",$access,r###";
CREATE TABLE "###, $heads, r###" (
 tenant_id uuid NOT NULL, usage text NOT NULL CHECK(usage IN('agent_task','da_configuration')), PRIMARY KEY(tenant_id,usage), revision bigint NOT NULL CHECK(revision>=0)
);
CREATE TABLE "###, $keys, r###" (
 tenant_id uuid NOT NULL, usage text NOT NULL CHECK(usage IN('agent_task','da_configuration')), key_id text NOT NULL, private_key bytea NOT NULL, max_verify_until bigint NOT NULL DEFAULT 0 CHECK(max_verify_until>=0),
 PRIMARY KEY(tenant_id,usage,key_id)
);
CREATE TABLE "###, $versions, r###" (
 tenant_id uuid NOT NULL, usage text NOT NULL CHECK(usage IN('agent_task','da_configuration')), revision bigint NOT NULL CHECK(revision>0),
 operation_id uuid NOT NULL, fingerprint_key text NOT NULL,
 fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),
 body jsonb NOT NULL CHECK(jsonb_typeof(body)='object'),
 digest text NOT NULL CHECK(digest ~ '^[0-9a-f]{64}$'),
 PRIMARY KEY(tenant_id,usage,revision), UNIQUE(tenant_id,usage,operation_id)
);
CREATE TABLE "###, $acknowledgements, r###" (
 tenant_id uuid NOT NULL, usage text NOT NULL CHECK(usage IN('agent_task','da_configuration')), operation_id uuid NOT NULL, device text NOT NULL,
 revision bigint NOT NULL CHECK(revision>0),
 digest text NOT NULL, PRIMARY KEY(tenant_id,usage,operation_id),
 FOREIGN KEY(tenant_id,usage,revision) REFERENCES "###, $versions, r###"(tenant_id,usage,revision)
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
GRANT UPDATE(private_key,max_verify_until) ON "###, $keys, " TO ", $access, r###";
GRANT SELECT ON "###, $heads, ",", $versions, ",", $acknowledgements, " TO ", $command, r###";
GRANT SELECT(tenant_id,usage,key_id,max_verify_until),UPDATE(max_verify_until) ON "###, $keys, " TO ", $command, ",", $telemetry, r###";
COMMIT;

GRANT USAGE ON SCHEMA "###, $schema, " TO ", $policy, r###";
GRANT SELECT ON "###, $heads, ",", $versions, ",", $acknowledgements, " TO ", $policy, r###";

-- Telemetry consumes public trust and the device acknowledgement in its original transaction.
GRANT USAGE ON SCHEMA "###, $schema, " TO ", $telemetry, r###";
GRANT SELECT(usage,tenant_id,revision) ON "###, $heads, " TO ", $telemetry, r###";
GRANT SELECT(usage,tenant_id,revision,body,digest) ON "###, $versions, " TO ", $telemetry, r###";
GRANT SELECT(usage,tenant_id,device,revision,digest) ON "###, $acknowledgements, " TO ", $telemetry, r###";
"###),
                observations_install: concat!(r###"BEGIN;
CREATE TABLE "###, $observations, r###" (
 tenant_id uuid NOT NULL, usage text NOT NULL CHECK(usage IN('agent_task','da_configuration')), device text NOT NULL,
 sequence bigint NOT NULL CHECK(sequence>0), operation uuid NOT NULL,
 body jsonb NOT NULL CHECK(jsonb_typeof(body)='object'),
 received_at bigint NOT NULL DEFAULT floor(extract(epoch FROM clock_timestamp()))::bigint,
 PRIMARY KEY(tenant_id,usage,device,sequence), UNIQUE(tenant_id,usage,operation)
);
ALTER TABLE "###, $observations, r###" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "###, $observations, r###" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON "###, $observations, r###" USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON "###, $observations, r###" FROM PUBLIC;
GRANT SELECT,INSERT ON "###, $observations, " TO ", $access, r###";
COMMIT;
"###),
                trust_lock_1: concat!("INSERT INTO ", $heads, "(usage,tenant_id,revision) VALUES('", $usage, "',$1::uuid,0) ON CONFLICT DO NOTHING"),
                trust_lock_2: concat!("SELECT revision FROM ", $heads, " WHERE usage='", $usage, "' AND tenant_id=$1::uuid FOR UPDATE"),
                trust_current_1: concat!("SELECT v.body,v.revision,v.digest FROM ", $versions, " v JOIN ", $heads, " h USING(tenant_id,usage,revision) WHERE usage='", $usage, "' AND tenant_id=$1::uuid"),
                trust_installation_service_1: concat!("SELECT instance_id FROM ", $installation),
                trust_replay_1: concat!("SELECT body,fingerprint_key,fingerprint FROM ", $versions, " WHERE usage='", $usage, "' AND tenant_id=$1::uuid AND operation_id=$2"),
                trust_save_1: concat!("INSERT INTO ", $versions, "(usage,tenant_id,revision,operation_id,fingerprint_key,fingerprint,body,digest) VALUES('", $usage, "',$1::uuid,$2,$3,$4,$5,$6,$7)"),
                trust_save_2: concat!("UPDATE ", $heads, " SET revision=$2 WHERE usage='", $usage, "' AND tenant_id=$1::uuid"),
                trust_prepare_2: concat!("SELECT instance_id FROM ", $installation),
                trust_prepare_3: concat!("INSERT INTO ", $keys, "(usage,tenant_id,key_id,private_key) VALUES('", $usage, "',$1::uuid,$2,$3)"),
                trust_acknowledge_2: concat!("SELECT digest FROM ", $versions, " WHERE usage='", $usage, "' AND tenant_id=$1::uuid AND revision=$2"),
                trust_acknowledge_3: concat!("INSERT INTO ", $acknowledgements, "(usage,tenant_id,operation_id,device,revision,digest) VALUES('", $usage, "',$1::uuid,$2,$3,$4,$5) ON CONFLICT DO NOTHING"),
                trust_acknowledge_4: concat!("SELECT device=$3 AND revision=$4 AND digest=$5 FROM ", $acknowledgements, " WHERE usage='", $usage, "' AND tenant_id=$1::uuid AND operation_id=$2"),
                trust_require_issue_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $acknowledgements, " a JOIN ", $versions, " v USING(tenant_id,usage,revision) WHERE a.usage='", $usage, "' AND a.tenant_id=$1::uuid AND a.device=$2 AND a.digest=v.digest AND EXISTS(SELECT 1 FROM jsonb_array_elements(v.body->'keys') k WHERE k->>'id'=$3 AND (k->>'state' IN('prepared','active') OR ($4 AND k->>'state'='verify_only'))))"),
                trust_load_1: concat!("SELECT private_key FROM ", $keys, " WHERE usage='", $usage, "' AND tenant_id=$1::uuid AND key_id=$2"),
                trust_selected_trust_1: concat!("SELECT body,revision,digest FROM ", $versions, " WHERE usage='", $usage, "' AND tenant_id=$1::uuid AND revision=$2"),
                trust_operation_1: concat!("SELECT body FROM ", $versions, " WHERE usage='", $usage, "' AND tenant_id=$1::uuid AND operation_id=$2"),
                trust_retire_1: concat!("SELECT EXISTS(SELECT 1 FROM unnest($3::text[]) r(id) WHERE NOT EXISTS(SELECT 1 FROM ", $acknowledgements, " a JOIN ", $versions, " v USING(tenant_id,usage,revision) WHERE a.tenant_id=$1::uuid AND a.usage='", $usage, "' AND a.device=r.id AND a.digest=v.digest AND EXISTS(SELECT 1 FROM jsonb_array_elements(v.body->'keys') k WHERE k->>'id'=$2 AND k->>'state'='verify_only')))") ,
                trust_rewrap_1: concat!("SELECT key_id,private_key FROM ", $keys, " WHERE usage='", $usage, "' AND tenant_id=$1::uuid AND substring(private_key FROM 1 FOR $2)<>$3 ORDER BY key_id LIMIT 64 FOR UPDATE"),
                trust_rewrap_2: concat!("UPDATE ", $keys, " SET private_key=$3 WHERE usage='", $usage, "' AND tenant_id=$1::uuid AND key_id=$2"),
                observations_record_in_1: concat!("INSERT INTO ", $observations, "(usage,tenant_id,device,sequence,operation,body) VALUES('", $usage, "',$1::uuid,$2,$3,$4,$5) ON CONFLICT DO NOTHING"),
                observations_record_in_2: concat!("SELECT body FROM ", $observations, " WHERE usage='", $usage, "' AND tenant_id=$1::uuid AND operation=$2"),
                observations_latest_in_1: concat!("SELECT body,received_at FROM ", $observations, " WHERE usage='",$usage,"' AND tenant_id=$1::uuid AND device=$2 ORDER BY sequence DESC LIMIT 1"),
                service_change_task_trust_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $versions, " WHERE usage='", $usage, "' AND tenant_id=$1::uuid AND operation_id=$2)"),
                service_acknowledge_task_trust_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $acknowledgements, " WHERE usage='", $usage, "' AND tenant_id=$1::uuid AND operation_id=$2)"),
                object_manifest: concat!(r###"{"tables":[""###,$exports,r###"",""###, $acknowledgements, r###"",""###, $heads, r###"",""###, $keys, r###"",""###, $observations, r###"",""###, $versions, r###""],"functions":[],"views":[]}"###),
                access_contract: concat!(r###"{"tables":[{"###,$contract_exports,r###","read_write":true,"updates":[],"delete_policy":null},{"###, $contract_table_12, r###","read_write":true,"updates":["revision"],"delete_policy":null},{"###, $contract_table_13, r###","read_write":true,"updates":["private_key","max_verify_until"],"delete_policy":null},{"###, $contract_table_14, r###","read_write":true,"updates":[],"delete_policy":null},{"###, $contract_table_15, r###","read_write":true,"updates":[],"delete_policy":null},{"###, $contract_table_16, r###","read_write":true,"updates":[],"delete_policy":null}],"functions":[],"external_relations":[],"verified_schemas":[]}"###),
            };
        }
    };
}
define_storage!(
    mdm_agent_task,
    "agent_task",
    "mdm_task_signing",
    "mdm_task_signing.configuration_exports",
    r###""schema":"mdm_task_signing","table":"configuration_exports""###,
    "mdm_task_signing.heads",
    "mdm_task_signing.keys",
    "mdm_task_signing.versions",
    "mdm_task_signing.acknowledgements",
    "mdm_task_signing.trust_observations",
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
    mdm_da_configuration,
    "da_configuration",
    "mdm_task_signing",
    "mdm_task_signing.configuration_exports",
    r###""schema":"mdm_task_signing","table":"configuration_exports""###,
    "mdm_task_signing.heads",
    "mdm_task_signing.keys",
    "mdm_task_signing.versions",
    "mdm_task_signing.acknowledgements",
    "mdm_task_signing.trust_observations",
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
    da_agent_task,
    "agent_task",
    "rss_da",
    "rss_da.configuration_exports",
    r###""schema":"rss_da","table":"configuration_exports""###,
    "rss_da.signing_heads",
    "rss_da.signing_keys",
    "rss_da.signing_versions",
    "rss_da.signing_acknowledgements",
    "rss_da.signing_observations",
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
define_storage!(
    da_da_configuration,
    "da_configuration",
    "rss_da",
    "rss_da.configuration_exports",
    r###""schema":"rss_da","table":"configuration_exports""###,
    "rss_da.signing_heads",
    "rss_da.signing_keys",
    "rss_da.signing_versions",
    "rss_da.signing_acknowledgements",
    "rss_da.signing_observations",
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
pub(crate) const fn sql(profile: StorageProfile, usage: Use) -> &'static Statements {
    match (profile, usage) {
        (StorageProfile::Mdm, Use::AgentTask) => &mdm_agent_task::SQL,
        (StorageProfile::Mdm, Use::DaConfiguration) => &mdm_da_configuration::SQL,
        (StorageProfile::Da, Use::AgentTask) => &da_agent_task::SQL,
        (StorageProfile::Da, Use::DaConfiguration) => &da_da_configuration::SQL,
    }
}
