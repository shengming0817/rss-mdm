//! Fixed, owner-owned SQL. Only these source literals can select objects.
use rss_mdm_install_support::StorageProfile;
pub(crate) struct Statements {
    pub read_rule: &'static str,
    pub read_group: &'static str,
    pub write_rule: &'static str,
    pub write_group: &'static str,
    pub count_rules: &'static str,
    pub count_groups: &'static str,
    pub install: &'static str,
    pub authority: &'static str,
    pub relations: &'static str,
    pub admission: &'static str,
    pub identity_management_authorize_1: &'static str,
    pub database_require_management_initializer_1: &'static str,
    pub database_require_management_initializer_2: &'static str,
    pub store_grant_tenant_administrator_on_1: &'static str,
    pub store_require_document_capacity_1: &'static str,
    pub store_snapshot_on_1: &'static str,
    pub store_protect_management_initializer_1: &'static str,
    pub store_initialize_on_1: &'static str,
    pub store_initialize_on_2: &'static str,
    pub store_initialize_on_3: &'static str,
    pub store_grant_verified_administrator_on_1: &'static str,
    pub api_key_store_change_on_1: &'static str,
    pub api_key_store_change_on_2: &'static str,
    pub api_key_store_change_on_3: &'static str,
    pub network_policy_read_on_1: &'static str,
    pub network_policy_installation_network_policy_1: &'static str,
    pub network_policy_change_on_1: &'static str,
    pub directory_list_1: &'static str,
    pub directory_list_2: &'static str,
    pub directory_list_3: &'static str,
    pub directory_list_4: &'static str,
    pub authority_valid_1: &'static str,
    pub authority_valid_2: &'static str,
    pub authority_valid_3: &'static str,
    pub authority_valid_4: &'static str,
    pub operations_replay_1: &'static str,
    pub operations_save_1: &'static str,
    pub api_key_authenticate_key_1: &'static str,
    pub api_key_authenticate_key_2: &'static str,
    pub tenancy_load_1: &'static str,
    pub object_manifest: &'static str,
    pub access_contract: &'static str,
}
macro_rules! define_storage {
    ($module:ident, $access_schema:literal, $access_role:literal, $installation:literal, $owner:literal, $command_runtime:literal, $inventory_runtime:literal, $scope_runtime:literal, $policy_runtime:literal, $resource_runtime:literal, $software_runtime:literal, $content_runtime:literal, $telemetry_runtime:literal, $software_driver:literal, $identity_runtime:literal, $profile_name:literal, $index_15:literal, $index_16:literal, $index_17:literal, $index_18:literal, $index_19:literal, $contract_table_20:literal, $contract_table_21:literal, $contract_table_22:literal, $contract_table_23:literal, $contract_table_24:literal, $contract_table_25:literal) => {
        mod $module {
            pub(super) const SQL: super::Statements = super::Statements {
                read_rule: concat!("SELECT revision,document IS NULL AS deleted FROM ", $access_schema, ".authorization_rules WHERE tenant_id=$1::uuid AND instance=$2::uuid AND id=$3::uuid FOR UPDATE"),
                read_group: concat!("SELECT revision,document IS NULL AS deleted FROM ", $access_schema, ".user_groups WHERE tenant_id=$1::uuid AND instance=$2::uuid AND id=$3::uuid FOR UPDATE"),
                write_rule: concat!("INSERT INTO ", $access_schema, ".authorization_rules(tenant_id,instance,id,revision,document) VALUES($1::uuid,$2::uuid,$3::uuid,$4,$5::jsonb) ON CONFLICT(tenant_id,instance,id) DO UPDATE SET revision=excluded.revision,document=excluded.document"),
                write_group: concat!("INSERT INTO ", $access_schema, ".user_groups(tenant_id,instance,id,revision,document) VALUES($1::uuid,$2::uuid,$3::uuid,$4,$5::jsonb) ON CONFLICT(tenant_id,instance,id) DO UPDATE SET revision=excluded.revision,document=excluded.document"),
                count_rules: concat!("SELECT count(*) FROM ", $access_schema, ".authorization_rules WHERE tenant_id=$1::uuid AND instance=$2::uuid"),
                count_groups: concat!("SELECT count(*) FROM ", $access_schema, ".user_groups WHERE tenant_id=$1::uuid AND instance=$2::uuid"),
                install: concat!(r###"-- Fresh installation: authorization-service owns these objects.
BEGIN;
SET LOCAL check_function_bodies = false;

CREATE TABLE "###, $access_schema, r###".authorization_initializations (
    tenant_id uuid NOT NULL,
    instance uuid NOT NULL,
    operation_id uuid NOT NULL,
    principal uuid NOT NULL,
    initialized_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL
);

ALTER TABLE ONLY "###, $access_schema, r###".authorization_initializations FORCE ROW LEVEL SECURITY;

CREATE TABLE "###, $access_schema, r###".authorization_operations (
    tenant_id uuid NOT NULL,
    actor text NOT NULL,
    instance uuid NOT NULL,
    operation_id uuid NOT NULL,
    digest text NOT NULL,
    result text NOT NULL,
    CONSTRAINT authorization_operations_digest_check CHECK ((length(digest) = 64)),
    CONSTRAINT authorization_operations_result_check CHECK ((length(result) <= 2048))
);

ALTER TABLE ONLY "###, $access_schema, r###".authorization_operations FORCE ROW LEVEL SECURITY;

CREATE TABLE "###, $access_schema, r###".authorization_rules (
    tenant_id uuid NOT NULL,
    instance uuid NOT NULL,
    id uuid NOT NULL,
    revision bigint NOT NULL,
    document jsonb,
    CONSTRAINT authorization_rules_document_check CHECK (((document IS NULL) OR ((jsonb_typeof(document) = 'object'::text) AND (octet_length((document)::text) <= 2097152)))),
    CONSTRAINT authorization_rules_revision_check CHECK ((revision > 0))
);

ALTER TABLE ONLY "###, $access_schema, r###".authorization_rules FORCE ROW LEVEL SECURITY;

CREATE TABLE "###, $access_schema, r###".user_groups (
    tenant_id uuid NOT NULL,
    instance uuid NOT NULL,
    id uuid NOT NULL,
    revision bigint NOT NULL,
    document jsonb,
    CONSTRAINT user_groups_document_check CHECK (((document IS NULL) OR ((jsonb_typeof(document) = 'object'::text) AND (octet_length((document)::text) <= 2097152)))),
    CONSTRAINT user_groups_revision_check CHECK ((revision > 0))
);

ALTER TABLE ONLY "###, $access_schema, r###".user_groups FORCE ROW LEVEL SECURITY;

ALTER TABLE ONLY "###, $access_schema, r###".authorization_initializations
    "###, $index_15, r###" PRIMARY KEY (tenant_id, instance);

ALTER TABLE ONLY "###, $access_schema, r###".authorization_operations
    "###, $index_16, r###" PRIMARY KEY (tenant_id, actor, operation_id);

ALTER TABLE ONLY "###, $access_schema, r###".authorization_rules
    "###, $index_17, r###" PRIMARY KEY (tenant_id, instance, id);

ALTER TABLE ONLY "###, $access_schema, r###".user_groups
    "###, $index_18, r###" PRIMARY KEY (tenant_id, instance, id);

ALTER TABLE "###, $access_schema, r###".authorization_initializations ENABLE ROW LEVEL SECURITY;

ALTER TABLE "###, $access_schema, r###".authorization_operations ENABLE ROW LEVEL SECURITY;

ALTER TABLE "###, $access_schema, r###".authorization_rules ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant ON "###, $access_schema, r###".authorization_initializations USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON "###, $access_schema, r###".authorization_operations USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON "###, $access_schema, r###".authorization_rules USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON "###, $access_schema, r###".user_groups USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

ALTER TABLE "###, $access_schema, r###".user_groups ENABLE ROW LEVEL SECURITY;
CREATE TABLE "###, $access_schema, r###".api_keys (
    tenant_id uuid NOT NULL,
    instance uuid NOT NULL,
    id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    authority_revision bigint NOT NULL CHECK (authority_revision > 0),
    credential_revision bigint NOT NULL CHECK (credential_revision > 0),
    metadata jsonb NOT NULL CHECK (jsonb_typeof(metadata)='object' AND octet_length(metadata::text)<=65536),
    secret_digest bytea NOT NULL CHECK (octet_length(secret_digest)=32),
    created_by jsonb NOT NULL CHECK (jsonb_typeof(created_by)='object'),
    created_at bigint NOT NULL,
    revoked boolean NOT NULL DEFAULT false,
    enabled boolean GENERATED ALWAYS AS ((metadata->>'enabled')::boolean) STORED,
    expires_at bigint GENERATED ALWAYS AS ((metadata->>'expiresAt')::bigint) STORED,
    PRIMARY KEY (tenant_id,instance,id)
);
ALTER TABLE "###, $access_schema, r###".api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE "###, $access_schema, r###".api_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON "###, $access_schema, r###".api_keys USING (tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK (tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);

CREATE TABLE "###, $access_schema, r###".api_network_policy (
    tenant_id uuid PRIMARY KEY,
    instance uuid NOT NULL UNIQUE,
    revision bigint NOT NULL CHECK (revision > 0),
    networks jsonb NOT NULL CHECK (jsonb_typeof(networks)='array' AND jsonb_array_length(networks)<=256)
);
ALTER TABLE "###, $access_schema, r###".api_network_policy ENABLE ROW LEVEL SECURITY;
ALTER TABLE "###, $access_schema, r###".api_network_policy FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON "###, $access_schema, r###".api_network_policy USING (tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK (tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
COMMIT;

"###),
                authority: concat!(r###"-- Durable product authorization evidence. Authentication and authority locks remain with callers.
BEGIN;
CREATE FUNCTION "###, $access_schema, r###".operation_authority_valid_until(authority jsonb, requested text, as_of bigint)
RETURNS bigint LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 WITH context AS (
  SELECT authority->'actor' AS actor,authority->'basis' AS basis,authority->'scope' AS scope,
   CASE authority#>>'{actor,kind}' WHEN 'account' THEN authority#>>'{actor,user,tenantId}' ELSE authority#>>'{actor,tenant}' END AS tenant,
   CASE authority#>>'{actor,kind}' WHEN 'account' THEN authority#>>'{actor,user,instanceId}' ELSE authority#>>'{actor,instance}' END AS instance
 ), candidates AS (
  SELECT r.document->'grants' AS grants,r.document->'subject' AS subject,b.value->>'expires_at' AS expires_at,c.*
  FROM context c CROSS JOIN LATERAL jsonb_array_elements(c.basis->'rules') b
  JOIN "###, $access_schema, r###".authorization_rules r ON r.tenant_id=c.tenant::uuid AND r.instance=c.instance::uuid
   AND r.id=(b.value->>'id')::uuid AND r.revision=(b.value->>'revision')::bigint
  WHERE c.actor->>'kind'='account' AND c.basis->>'kind'='account'
   AND (b.value->>'expires_at' IS NULL OR (b.value->>'expires_at')::bigint>as_of)
   AND r.document IS NOT NULL
  UNION ALL
  SELECT k.metadata->'grants',NULL::jsonb,k.expires_at::text,c.* FROM context c
  JOIN "###, $access_schema, r###".api_keys k ON k.tenant_id=c.tenant::uuid AND k.instance=c.instance::uuid AND k.id=(c.actor->>'id')::uuid
   AND k.authority_revision=(c.basis->>'authority_revision')::bigint
  WHERE c.actor->>'kind'='api_key' AND c.basis->>'kind'='api_key'
   AND k.enabled AND NOT k.revoked AND (k.expires_at IS NULL OR k.expires_at>as_of AND to_timestamp(k.expires_at)>statement_timestamp())
   AND requested NOT IN('tenant_create','tenant_read','tenant_update','tenant_delete','tenant_administrator_create',
      'identity_accounts_manage','enterprise_applications_read','enterprise_applications_write','identity_providers_manage','authorization_read','authorization_write','user_group_read','user_group_write','department_read')
 )
 SELECT max(coalesce(c.expires_at::bigint,9223372036854775807))
  FROM candidates c WHERE authority->>'profile'='"###, $profile_name, r###"' AND authority->>'permission'=requested AND c.tenant=nullif(current_setting('rss.tenant_id',true),'')
  AND EXISTS(SELECT FROM jsonb_array_elements(c.grants) g WHERE g->>'operation'=requested AND
   CASE c.scope->>'kind'
    WHEN 'all_devices' THEN g->'scope'='{"kind":"all_devices"}'::jsonb
    WHEN 'tenant' THEN g->'scope'='{"kind":"tenant"}'::jsonb
    WHEN 'device' THEN g->'scope'='{"kind":"all_devices"}'::jsonb OR g->'scope'=c.scope
    ELSE false END)
  AND (c.actor->>'kind'='api_key' OR CASE c.subject->>'kind'
   WHEN 'user' THEN c.subject->'user'=c.actor->'user'
   WHEN 'idp_group' THEN c.expires_at IS NOT NULL
   WHEN 'department' THEN c.expires_at IS NOT NULL
   WHEN 'user_group' THEN EXISTS(SELECT FROM "###, $access_schema, r###".user_groups u
    WHERE u.tenant_id=c.tenant::uuid AND u.instance=c.instance::uuid AND u.id=(c.subject->>'id')::uuid
     AND (u.document->>'enabled')::boolean AND u.document->'members' @> jsonb_build_array(c.actor->'user'))
   ELSE false END)

$$;
REVOKE ALL ON FUNCTION "###, $access_schema, r###".operation_authority_valid_until(jsonb,text,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "###, $access_schema, r###".operation_authority_valid_until(jsonb,text,bigint)
 TO "###, $access_role, ",", $inventory_runtime, ",", $scope_runtime, ",", $policy_runtime, ",", $resource_runtime, ",", $software_runtime, ",", $content_runtime, ",", $telemetry_runtime, ",", $command_runtime, ",", $software_driver, ",", $identity_runtime, r###";
CREATE FUNCTION "###, $access_schema, r###".operation_authority_valid(authority jsonb,requested text,as_of bigint)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT "###, $access_schema, r###".operation_authority_valid_until(authority,requested,as_of) IS NOT NULL
$$;
REVOKE ALL ON FUNCTION "###, $access_schema, r###".operation_authority_valid(jsonb,text,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "###, $access_schema, r###".operation_authority_valid(jsonb,text,bigint)
 TO "###, $access_role, ",", $inventory_runtime, ",", $scope_runtime, ",", $policy_runtime, ",", $resource_runtime, ",", $software_runtime, ",", $content_runtime, ",", $telemetry_runtime, ",", $command_runtime, ",", $software_driver, ",", $identity_runtime, r###";
COMMIT;
"###),
                relations: concat!(r###"-- Fresh installation: authorization-service owns these objects.
BEGIN;
SET LOCAL check_function_bodies = false;

GRANT SELECT,INSERT ON TABLE "###, $access_schema, ".authorization_initializations TO ", $access_role, r###";

GRANT SELECT,INSERT ON TABLE "###, $access_schema, ".authorization_operations TO ", $access_role, r###";

GRANT SELECT,INSERT ON TABLE "###, $access_schema, ".authorization_rules TO ", $access_role, r###";
GRANT SELECT ON TABLE "###, $access_schema, ".authorization_rules TO ", $command_runtime, r###";
GRANT SELECT ON TABLE "###, $access_schema, ".authorization_rules TO ", $inventory_runtime, ",", $scope_runtime, ",", $policy_runtime, ",", $resource_runtime, ",", $software_runtime, ",", $content_runtime, ",", $telemetry_runtime, ",", $software_driver, r###";

GRANT UPDATE(revision) ON TABLE "###, $access_schema, ".authorization_rules TO ", $access_role, r###";

GRANT UPDATE(document) ON TABLE "###, $access_schema, ".authorization_rules TO ", $access_role, r###";

GRANT SELECT,INSERT ON TABLE "###, $access_schema, ".user_groups TO ", $access_role, r###";
GRANT SELECT ON TABLE "###, $access_schema, ".user_groups TO ", $command_runtime, r###";
GRANT SELECT ON TABLE "###, $access_schema, ".user_groups TO ", $inventory_runtime, ",", $scope_runtime, ",", $policy_runtime, ",", $resource_runtime, ",", $software_runtime, ",", $content_runtime, ",", $telemetry_runtime, ",", $software_driver, r###";

GRANT UPDATE(revision) ON TABLE "###, $access_schema, ".user_groups TO ", $access_role, r###";

GRANT UPDATE(document) ON TABLE "###, $access_schema, ".user_groups TO ", $access_role, r###";
GRANT USAGE ON SCHEMA "###, $access_schema, " TO ", $identity_runtime, r###";
GRANT SELECT ON "###, $access_schema, ".authorization_rules,", $access_schema, ".user_groups,", $access_schema, ".authorization_initializations TO ", $identity_runtime, r###";
GRANT SELECT,INSERT ON "###, $access_schema, ".api_keys,", $access_schema, ".api_network_policy TO ", $access_role, r###";
GRANT UPDATE(revision,authority_revision,credential_revision,metadata,secret_digest,revoked) ON "###, $access_schema, ".api_keys TO ", $access_role, r###";
GRANT UPDATE(revision,networks) ON "###, $access_schema, ".api_network_policy TO ", $access_role, r###";
GRANT SELECT ON "###, $access_schema, ".api_keys TO ", $command_runtime, ",", $inventory_runtime, ",", $scope_runtime, ",", $policy_runtime, ",", $resource_runtime, ",", $software_runtime, ",", $content_runtime, ",", $telemetry_runtime, ",", $software_driver, ",", $identity_runtime, r###";
ALTER TABLE "###, $access_schema, ".api_network_policy ", $index_19, " FOREIGN KEY (tenant_id) REFERENCES ", $installation, r###"(management_tenant_id);
COMMIT;

GRANT USAGE ON SCHEMA "###, $access_schema, " TO ", $resource_runtime, ",", $software_runtime, ",", $content_runtime, r###";
"###),
                admission: concat!(r###"-- Only authorization/fencing kernels; bodies come directly from their owner's installation SQL.
WITH expected(signature,language,result,definer,returns_set,volatility,names,config,body,roles) AS (VALUES
 ('"###, $access_schema, ".operation_authority_valid_until(jsonb,text,bigint)', 'sql', 'bigint', true, false, 's', ARRAY['authority','requested','as_of']::text[], ARRAY['search_path=pg_catalog']::text[], $1::text, ARRAY['", $access_role, "','", $command_runtime, "','", $inventory_runtime, "','", $scope_runtime, "','", $policy_runtime, "','", $resource_runtime, "','", $software_runtime, "','", $content_runtime, "','", $telemetry_runtime, "','", $identity_runtime, "','", $owner, "','", $software_driver, r###"']::text[]),
 ('"###, $access_schema, ".operation_authority_valid(jsonb,text,bigint)', 'sql', 'boolean', true, false, 's', ARRAY['authority','requested','as_of']::text[], ARRAY['search_path=pg_catalog']::text[], $2::text, ARRAY['", $access_role, "','", $command_runtime, "','", $inventory_runtime, "','", $scope_runtime, "','", $policy_runtime, "','", $resource_runtime, "','", $software_runtime, "','", $content_runtime, "','", $telemetry_runtime, "','", $identity_runtime, "','", $owner, "','", $software_driver, r###"']::text[])
)
SELECT e.signature FROM expected e
LEFT JOIN pg_proc p ON p.oid=to_regprocedure(e.signature)
LEFT JOIN pg_language l ON l.oid=p.prolang
LEFT JOIN pg_roles r ON r.oid=p.proowner
WHERE p.oid IS NULL OR l.lanname<>e.language OR p.prorettype<>to_regtype(e.result)
 OR p.prokind<>'f' OR p.prosecdef<>e.definer OR p.proretset<>e.returns_set
 OR p.provolatile::text<>e.volatility OR p.proleakproof OR p.prosrc<>e.body
 OR coalesce(p.proargnames,ARRAY[]::text[]) IS DISTINCT FROM e.names OR p.proconfig IS DISTINCT FROM e.config
 OR r.rolname<>'"###, $owner, r###"' OR r.rolsuper OR r.rolbypassrls OR r.rolcreaterole
 OR pg_has_role(current_user,r.oid,'MEMBER')
 OR EXISTS(SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
 WHERE a.grantee=0 OR (a.grantee<>p.proowner AND (a.is_grantable OR a.privilege_type<>'EXECUTE' OR NOT pg_get_userbyid(a.grantee)=ANY(e.roles))))
ORDER BY e.signature LIMIT 1
"###),
                identity_management_authorize_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $access_schema, ".authorization_initializations WHERE tenant_id=$1::uuid AND instance=$2::uuid AND principal=$3::uuid)"),
                database_require_management_initializer_1: concat!("SELECT a.principal::text FROM ", $access_schema, ".authorization_initializations a JOIN ", $installation, " i ON a.instance=i.instance_id AND a.tenant_id=i.management_tenant_id WHERE i.singleton"),
                database_require_management_initializer_2: concat!("SELECT instance_id::text FROM ", $installation, " WHERE singleton"),
                store_grant_tenant_administrator_on_1: concat!("INSERT INTO ", $access_schema, ".authorization_rules(tenant_id,instance,id,revision,document) VALUES($1::uuid,$2::uuid,$3,1,$4)"),
                store_require_document_capacity_1: concat!("SELECT (SELECT coalesce(sum(octet_length(document::text)),0) FROM ", $access_schema, ".authorization_rules WHERE tenant_id=$1::uuid AND instance=$2::uuid)+(SELECT coalesce(sum(octet_length(document::text)),0) FROM ", $access_schema, ".user_groups WHERE tenant_id=$1::uuid AND instance=$2::uuid)<=8388608"),
                store_snapshot_on_1: concat!("WITH rules AS MATERIALIZED (SELECT * FROM ", $access_schema, ".authorization_rules WHERE tenant_id=$1::uuid AND instance=$2::uuid ORDER BY id LIMIT 10001), groups AS MATERIALIZED (SELECT * FROM ", $access_schema, ".user_groups WHERE tenant_id=$1::uuid AND instance=$2::uuid ORDER BY id LIMIT 10001), keys AS MATERIALIZED (SELECT * FROM ", $access_schema, ".api_keys WHERE tenant_id=$1::uuid AND instance=$2::uuid ORDER BY id LIMIT 1001) SELECT CASE WHEN (SELECT coalesce(sum(octet_length(document::text)),0) FROM rules)+(SELECT coalesce(sum(octet_length(document::text)),0) FROM groups)<=8388608 AND (SELECT coalesce(sum(octet_length(metadata::text)+octet_length(created_by::text)),0) FROM keys)<=2097152 THEN jsonb_build_object('rules',coalesce((SELECT jsonb_agg(jsonb_build_object('id',id,'revision',revision,'value',document)) FROM rules),'[]'::jsonb),'groups',coalesce((SELECT jsonb_agg(jsonb_build_object('id',id,'revision',revision,'value',document)) FROM groups),'[]'::jsonb),'keys',coalesce((SELECT jsonb_agg(jsonb_build_object('id',id,'revision',revision,'authorityRevision',authority_revision,'credentialRevision',credential_revision,'metadata',metadata,'createdBy',created_by,'createdAt',created_at,'revoked',revoked)) FROM keys),'[]'::jsonb)) ELSE NULL END::text"),
                store_protect_management_initializer_1: concat!("SELECT principal::text FROM ", $access_schema, ".authorization_initializations WHERE tenant_id=$1::uuid AND instance=$2::uuid"),
                store_initialize_on_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $access_schema, ".authorization_initializations WHERE tenant_id=$1::uuid AND instance=$2::uuid)"),
                store_initialize_on_2: concat!("INSERT INTO ", $access_schema, ".authorization_initializations(tenant_id,instance,operation_id,principal) VALUES($1::uuid,$2::uuid,$3::uuid,$4::uuid)"),
                store_initialize_on_3: concat!("INSERT INTO ", $access_schema, ".authorization_rules(tenant_id,instance,id,revision,document) VALUES($1::uuid,$2::uuid,$3::uuid,1,$4::jsonb)"),
                store_grant_verified_administrator_on_1: concat!("INSERT INTO ", $access_schema, ".authorization_rules(tenant_id,instance,id,revision,document) VALUES($1::uuid,$2::uuid,$3,1,$4)"),
                api_key_store_change_on_1: concat!("INSERT INTO ", $access_schema, ".api_keys(tenant_id,instance,id,revision,authority_revision,credential_revision,metadata,secret_digest,created_by,created_at) VALUES($1::uuid,$2::uuid,$3,1,1,1,$4,$5,$6,$7)"),
                api_key_store_change_on_2: concat!("UPDATE ", $access_schema, ".api_keys SET revision=$4,authority_revision=$5,credential_revision=$6,metadata=$7,secret_digest=coalesce($8,secret_digest),revoked=$9 WHERE tenant_id=$1::uuid AND instance=$2::uuid AND id=$3"),
                api_key_store_change_on_3: concat!("SELECT coalesce(sum(octet_length(metadata::text)+octet_length(created_by::text)),0)<=2097152 FROM ", $access_schema, ".api_keys WHERE tenant_id=$1::uuid AND instance=$2::uuid"),
                network_policy_read_on_1: concat!("SELECT revision,networks FROM ", $access_schema, ".api_network_policy WHERE tenant_id=$1::uuid AND instance=$2::uuid"),
                network_policy_installation_network_policy_1: concat!("SELECT instance_id::text FROM ", $installation, " WHERE singleton"),
                network_policy_change_on_1: concat!("INSERT INTO ", $access_schema, ".api_network_policy(tenant_id,instance,revision,networks) VALUES($1::uuid,$2::uuid,$3,$4) ON CONFLICT(tenant_id) DO UPDATE SET revision=excluded.revision,networks=excluded.networks"),
                directory_list_1: concat!($access_schema, ".authorization_rules"),
                directory_list_2: concat!($access_schema, ".user_groups"),
                directory_list_3: concat!($access_schema, ".user_groups CROSS JOIN LATERAL jsonb_array_elements(document->'members') member"),
                directory_list_4: concat!($access_schema, ".api_keys"),
                authority_valid_1: concat!("SELECT metadata FROM ", $access_schema, ".api_keys WHERE tenant_id=$1::uuid AND instance=$2::uuid AND id=$3 AND authority_revision=$4 AND enabled AND NOT revoked AND (expires_at IS NULL OR expires_at>$5) AND (expires_at IS NULL OR to_timestamp(expires_at)>clock_timestamp())"),
                authority_valid_2: concat!("SELECT document FROM ", $access_schema, ".authorization_rules WHERE tenant_id=$1::uuid AND instance=$2::uuid AND id=$3 AND revision=$4"),
                authority_valid_3: concat!("SELECT document FROM ", $access_schema, ".user_groups WHERE tenant_id=$1::uuid AND instance=$2::uuid AND id=$3"),
                authority_valid_4: concat!("SELECT ", $access_schema, ".operation_authority_valid($1,$2,$3)"),
                operations_replay_1: concat!("SELECT digest,result,instance::text FROM ", $access_schema, ".authorization_operations WHERE tenant_id=$1::uuid AND actor=$2 AND operation_id=$3::uuid"),
                operations_save_1: concat!("INSERT INTO ", $access_schema, ".authorization_operations(tenant_id,actor,operation_id,digest,result,instance) VALUES($1::uuid,$2,$3::uuid,$4,$5,$6::uuid)"),
                api_key_authenticate_key_1: concat!("SELECT instance_id::text FROM ", $installation, " WHERE singleton"),
                api_key_authenticate_key_2: concat!("SELECT authority_revision,credential_revision,extract(epoch FROM (to_timestamp(expires_at)-clock_timestamp()))::double precision AS remaining FROM ", $access_schema, ".api_keys WHERE tenant_id=$1::uuid AND instance=$2::uuid AND id=$3 AND secret_digest=$4 AND enabled AND NOT revoked AND (expires_at IS NULL OR to_timestamp(expires_at)>clock_timestamp())"),
                tenancy_load_1: concat!("SELECT instance_id::text,management_tenant_id::text FROM ", $installation),
                object_manifest: concat!(r###"{"tables":[""###, $access_schema, r###".api_keys",""###, $access_schema, r###".api_network_policy",""###, $access_schema, r###".authorization_initializations",""###, $access_schema, r###".authorization_operations",""###, $access_schema, r###".authorization_rules",""###, $access_schema, r###".user_groups"],"functions":[""###, $access_schema, r###".operation_authority_valid",""###, $access_schema, r###".operation_authority_valid_until"],"views":[]}"###),
                access_contract: concat!(r###"{"tables":[{"###, $contract_table_20, r###","read_write":true,"updates":[],"delete_policy":null},{"###, $contract_table_21, r###","read_write":true,"updates":[],"delete_policy":null},{"###, $contract_table_22, r###","read_write":true,"updates":["revision","document"],"delete_policy":null},{"###, $contract_table_23, r###","read_write":true,"updates":["revision","document"],"delete_policy":null},{"###, $contract_table_24, r###","read_write":true,"updates":["revision","authority_revision","credential_revision","metadata","secret_digest","revoked"],"delete_policy":null},{"###, $contract_table_25, r###","read_write":true,"updates":["revision","networks"],"delete_policy":null}],"functions":[{"name":""###, $access_schema, r###".operation_authority_valid","search_path":"search_path=pg_catalog"},{"name":""###, $access_schema, r###".operation_authority_valid_until","search_path":"search_path=pg_catalog"}],"external_relations":[],"verified_schemas":[]}"###),
            };
        }
    };
}
define_storage!(
    mdm,
    "mdm_access",
    "mdm_access",
    "public.mdm_installation",
    "mdm_owner",
    "mdm_command_runtime",
    "mdm_inventory_runtime",
    "mdm_scope_runtime",
    "mdm_policy_runtime",
    "mdm_resource_runtime",
    "mdm_software_runtime",
    "mdm_content_runtime",
    "mdm_telemetry_runtime",
    "mdm_software_driver",
    "mdm_identity_runtime",
    "mdm",
    "ADD CONSTRAINT authorization_initializations_pkey",
    "ADD CONSTRAINT authorization_operations_pkey",
    "ADD CONSTRAINT authorization_rules_pkey",
    "ADD CONSTRAINT user_groups_pkey",
    "ADD CONSTRAINT api_network_policy_installation_fk",
    r###""schema":"mdm_access","table":"authorization_initializations""###,
    r###""schema":"mdm_access","table":"authorization_operations""###,
    r###""schema":"mdm_access","table":"authorization_rules""###,
    r###""schema":"mdm_access","table":"user_groups""###,
    r###""schema":"mdm_access","table":"api_keys""###,
    r###""schema":"mdm_access","table":"api_network_policy""###
);
define_storage!(
    da,
    "rss_da",
    "da_access",
    "rss_da.authorization_installation",
    "da_owner",
    "da_command_runtime",
    "da_inventory_runtime",
    "da_scope_runtime",
    "da_policy_runtime",
    "da_resource_runtime",
    "da_software_runtime",
    "da_content_runtime",
    "da_telemetry_runtime",
    "da_software_driver",
    "da_identity_runtime",
    "da",
    "ADD CONSTRAINT authorization_authorization_initializations_pkey",
    "ADD CONSTRAINT authorization_authorization_operations_pkey",
    "ADD CONSTRAINT authorization_authorization_rules_pkey",
    "ADD CONSTRAINT authorization_user_groups_pkey",
    "ADD CONSTRAINT authorization_api_network_policy_installation_fk",
    r###""schema":"rss_da","table":"authorization_initializations""###,
    r###""schema":"rss_da","table":"authorization_operations""###,
    r###""schema":"rss_da","table":"authorization_rules""###,
    r###""schema":"rss_da","table":"user_groups""###,
    r###""schema":"rss_da","table":"api_keys""###,
    r###""schema":"rss_da","table":"api_network_policy""###
);
pub(crate) const fn sql(profile: StorageProfile) -> &'static Statements {
    match profile {
        StorageProfile::Mdm => &mdm::SQL,
        StorageProfile::Da => &da::SQL,
    }
}
