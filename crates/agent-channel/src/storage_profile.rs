//! Fixed, owner-owned SQL. Only these source literals can select objects.
use rss_mdm_install_support::StorageProfile;
pub(crate) struct Statements {
    pub bindings_update_context_1: &'static str,
    pub bindings_update_context_2: &'static str,
    pub bindings_announcement_1: &'static str,
    pub bindings_announce_1: &'static str,
    pub bindings_bindings_1: &'static str,
    pub bindings_bind_agent_in_1: &'static str,
    pub delivery_payload_1: &'static str,
    pub delivery_replay_1: &'static str,
    pub delivery_receipt_1: &'static str,
    pub delivery_persist_offer_1: &'static str,
    pub delivery_persist_permit_1: &'static str,
    pub delivery_cancellation_after_1: &'static str,
    pub delivery_cancellation_after_2: &'static str,
    pub delivery_save_cancellation_after_1: &'static str,
    pub delivery_offer_after_in_1: &'static str,
    pub delivery_offer_after_in_2: &'static str,
    pub delivery_offer_through_in_1: &'static str,
    pub signature_retirement_pending_1: &'static str,
    pub install: &'static str,
    pub relations: &'static str,
    pub delivery_admission: &'static str,
    pub authority_admission: &'static str,
    pub update_columns: &'static str,
    pub allowed_tables: &'static str,
    pub object_manifest: &'static str,
    pub access_contract: &'static str,
}
macro_rules! define_storage {
    ($module:ident, $schema:literal, $schema_decl:literal, $access_schema:literal, $access:literal, $bindings:literal, $task_attempts:literal, $task_receipts:literal, $task_polls:literal, $pending_task_signatures:literal, $owner:literal, $command_runtime:literal, $policy_runtime:literal, $inventory_runtime:literal, $software_driver:literal, $create_mdm_agent:literal, $role_mdm_identity_runtime:literal, $role_mdm_scope_runtime:literal, $role_mdm_resource_runtime:literal, $role_mdm_software_runtime:literal, $role_mdm_telemetry_runtime:literal, $index_20:literal, $index_21:literal, $index_22:literal, $contract_table_23:literal, $contract_table_24:literal, $contract_table_25:literal, $contract_table_26:literal) => {
        mod $module {
            pub(super) const SQL: super::Statements = super::Statements {
                bindings_update_context_1: concat!("SELECT platform, execution_context FROM ", $bindings, " WHERE tenant_id = CAST($1 AS uuid) AND device = $2 FOR UPDATE"),
                bindings_update_context_2: concat!("UPDATE ", $bindings, " SET execution_context = $3 WHERE tenant_id = CAST($1 AS uuid) AND device = $2"),
                bindings_announcement_1: concat!("SELECT announcement FROM ", $bindings, " WHERE tenant_id = CAST($1 AS uuid) AND device = $2"),
                bindings_announce_1: concat!("UPDATE ", $bindings, " SET announcement = $3 WHERE tenant_id = CAST($1 AS uuid) AND device = $2"),
                bindings_bindings_1: concat!("SELECT device, platform, architecture, capabilities, execution_context FROM ", $bindings, " WHERE tenant_id = CAST($1 AS uuid) AND device = ANY($2) AND wire_version = 1"),
                bindings_bind_agent_in_1: concat!("INSERT INTO ", $bindings, " (tenant_id, device, wire_version, capabilities, platform, architecture, execution_context) VALUES (CAST($1 AS uuid), $2, 1, $3, $4, $5, $6)"),
                delivery_payload_1: concat!("SELECT coalesce(permit,offer) FROM ", $task_attempts, " WHERE tenant_id=$1::uuid AND run=$2 AND id=$3"),
                delivery_replay_1: concat!("SELECT fingerprint, response FROM ", $task_receipts, " WHERE tenant_id = CAST($1 AS uuid) AND device = $2 AND id = $3"),
                delivery_receipt_1: concat!("INSERT INTO ", $task_receipts, " (tenant_id, device, id, fingerprint, response) VALUES (CAST($1 AS uuid), $2, $3, $4, $5)"),
                delivery_persist_offer_1: concat!("INSERT INTO ", $task_attempts, " (tenant_id, id, run, device, claimed_at, offer, deadline) VALUES (CAST($1 AS uuid), $2, $3, $4, CAST(floor(EXTRACT(EPOCH FROM clock_timestamp())) AS bigint), $5, $6)"),
                delivery_persist_permit_1: concat!("UPDATE ", $task_attempts, " SET permit=$4 WHERE tenant_id=$1::uuid AND run=$2 AND id=$3 AND permit IS NULL"),
                delivery_cancellation_after_1: concat!("INSERT INTO ", $task_polls, " (tenant_id, device) VALUES (CAST($1 AS uuid), $2) ON CONFLICT DO NOTHING"),
                delivery_cancellation_after_2: concat!("SELECT cancellation_after FROM ", $task_polls, " WHERE tenant_id = CAST($1 AS uuid) AND device = $2 FOR UPDATE"),
                delivery_save_cancellation_after_1: concat!("UPDATE ", $task_polls, " SET cancellation_after = $3 WHERE tenant_id = CAST($1 AS uuid) AND device = $2"),
                delivery_offer_after_in_1: concat!("INSERT INTO ", $task_polls, " (tenant_id, device) VALUES (CAST($1 AS uuid), $2) ON CONFLICT DO NOTHING"),
                delivery_offer_after_in_2: concat!("SELECT offer_after_at, offer_after_id FROM ", $task_polls, " WHERE tenant_id = CAST($1 AS uuid) AND device = $2 FOR UPDATE"),
                delivery_offer_through_in_1: concat!("UPDATE ", $task_polls, " SET offer_after_at = $3, offer_after_id = $4 WHERE tenant_id = CAST($1 AS uuid) AND device = $2"),
                signature_retirement_pending_1: concat!("SELECT ", $pending_task_signatures, "($1::uuid,$2)"),
                install: concat!("-- Fresh installation: agent-channel owns these objects.\nBEGIN;\nSET LOCAL check_function_bodies = false;\n\n", $create_mdm_agent, ";\n\nCREATE TABLE ", $bindings, " (\n    tenant_id uuid NOT NULL\n  , device uuid NOT NULL\n  , wire_version smallint NOT NULL\n  , capabilities text NOT NULL\n  , platform text NOT NULL\n  , architecture text NOT NULL\n  , execution_context jsonb NOT NULL\n  , announcement jsonb CHECK (announcement IS NULL\n                           OR (jsonb_typeof(announcement) = 'object'\n                           AND octet_length(CAST(announcement AS text)) <= 65536))\n  , CONSTRAINT agent_execution_context CHECK (jsonb_typeof(execution_context) = 'object'\n                                          AND CAST(execution_context ->> 'revision' AS bigint) > 0\n                                          AND octet_length(CAST(execution_context AS text)) <= 8192)\n  , CONSTRAINT agent_binding_profile CHECK (wire_version = 1\n                                        AND capabilities ~ '^\\[\"inventory\\.collect\\.v1\"(,\"task\\.execute\\.v1\")?(,\"software\\.msi\\.system\\.v1\")?(,\"software\\.msi\\.user\\.v1\")?(,\"software\\.pkg\\.system\\.v1\")?(,\"software\\.bundle\\.windows\\.system\\.v1\")?(,\"software\\.bundle\\.windows\\.user\\.v1\")?(,\"software\\.bundle\\.macos\\.system\\.v1\")?(,\"software\\.bundle\\.macos\\.user\\.v1\")?(,\"software\\.winget\\.system\\.v1\")?(,\"software\\.winget\\.user\\.v1\")?(,\"software\\.brew\\.bottle\\.user\\.v1\")?(,\"software\\.exe\\.system\\.v1\")?(,\"software\\.exe\\.user\\.v1\")?(,\"software\\.dmg\\.app\\.system\\.v1\")?(,\"software\\.dmg\\.app\\.user\\.v1\")?(,\"software\\.dmg\\.pkg\\.system\\.v1\")?(,\"software\\.msix\\.registration\\.user\\.v1\")?(,\"software\\.msix\\.provisioning\\.system\\.v1\")?(,\"mdm\\.enrollment\\.v1\")?(,\"device\\.unmanage\\.v1\")?(,\"inventory\\.native\\.v1\")?(,\"credentials\\.windows\\.v1\")?(,\"telemetry\\.collect\\.v1\")?(,\"telemetry\\.counter\\.local\\.v1\")?(,\"device_access\\.v1\")?(,\"device_access\\.whfb\\.v1\")?\\]$')\n  , CONSTRAINT agent_bindings_architecture_check CHECK (architecture = ANY(ARRAY[CAST('x86_64' AS text)\n                                                                               , CAST('aarch64' AS text)]))\n  , CONSTRAINT agent_bindings_platform_check CHECK (platform = ANY(ARRAY[CAST('windows' AS text)\n                                                                       , CAST('macos' AS text)]))\n);\n\nALTER TABLE ONLY ", $bindings, " FORCE ROW LEVEL SECURITY;\n\nALTER TABLE ONLY ", $bindings, " ", $index_20, " PRIMARY KEY (tenant_id, device);\n\nALTER TABLE ", $bindings, " ENABLE ROW LEVEL SECURITY;\n\n\nCREATE POLICY tenant ON ", $bindings, " USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));\n\nCREATE TABLE ", $task_attempts, " (\n    tenant_id uuid NOT NULL\n  , id uuid NOT NULL\n  , run uuid NOT NULL\n  , device uuid NOT NULL\n  , claimed_at bigint NOT NULL\n  , deadline bigint NOT NULL CHECK (deadline > claimed_at)\n  , offer jsonb NOT NULL\n  , permit jsonb\n  , CONSTRAINT task_attempts_claimed_at_check CHECK (claimed_at >= 0)\n  , CONSTRAINT task_attempts_offer_check CHECK (octet_length(CAST(offer AS text)) <= 6291456)\n  , CONSTRAINT task_attempts_permit_check CHECK (permit IS NULL\n                                              OR octet_length(CAST(permit AS text)) <= 6291456)\n);\nALTER TABLE ", $task_attempts, " ADD PRIMARY KEY(tenant_id,id);\nCREATE TABLE ", $task_receipts, " (\n    tenant_id uuid NOT NULL\n  , device uuid NOT NULL\n  , id uuid NOT NULL\n  , fingerprint bytea NOT NULL CHECK (octet_length(fingerprint) = 32)\n  , response jsonb NOT NULL CHECK (octet_length(CAST(response AS text)) <= 6291456)\n  , PRIMARY KEY (tenant_id, device, id)\n);\nCREATE TABLE ", $task_polls, " (\n    tenant_id uuid NOT NULL\n  , device uuid NOT NULL\n  , cancellation_after uuid\n  , offer_after_at bigint\n  , offer_after_id uuid\n  , CHECK ((offer_after_at IS NULL) = (offer_after_id IS NULL))\n  , PRIMARY KEY (tenant_id, device)\n);\nALTER TABLE ", $task_attempts, " ENABLE ROW LEVEL SECURITY;\nALTER TABLE ", $task_attempts, " FORCE ROW LEVEL SECURITY;\nCREATE POLICY tenant ON ", $task_attempts, " USING (tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK (tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);\nALTER TABLE ", $task_receipts, " ENABLE ROW LEVEL SECURITY;\nALTER TABLE ", $task_receipts, " FORCE ROW LEVEL SECURITY;\nCREATE POLICY tenant ON ", $task_receipts, " USING (tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK (tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);\nALTER TABLE ", $task_polls, " ENABLE ROW LEVEL SECURITY;\nALTER TABLE ", $task_polls, " FORCE ROW LEVEL SECURITY;\nCREATE POLICY tenant ON ", $task_polls, " USING (tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK (tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);\n\nCOMMIT;\n"),
                relations: concat!("-- Fresh installation: agent-channel owns these objects.\nBEGIN;\nSET LOCAL check_function_bodies = false;\n\nALTER TABLE ONLY ", $bindings, " ", $index_21, " FOREIGN KEY (tenant_id, device) REFERENCES ", $access_schema, "devices (tenant_id, id);\n\nGRANT USAGE ON ", $schema_decl, " TO ", $access, ";\nGRANT USAGE ON ", $schema_decl, " TO ", $policy_runtime, ",", $role_mdm_scope_runtime, ",", $inventory_runtime, ",", $role_mdm_telemetry_runtime, ";\nGRANT USAGE ON ", $schema_decl, " TO ", $command_runtime, ";\n\nGRANT SELECT,INSERT ON TABLE ", $bindings, " TO ", $access, ";\nGRANT SELECT ON TABLE ", $bindings, " TO ", $policy_runtime, ",", $role_mdm_scope_runtime, ",", $inventory_runtime, ",", $role_mdm_telemetry_runtime, ";\nGRANT SELECT ON TABLE ", $bindings, " TO ", $command_runtime, ";\nGRANT UPDATE(execution_context) ON TABLE ", $bindings, " TO ", $command_runtime, ",", $policy_runtime, ";\n\nALTER TABLE ONLY ", $task_attempts, " ", $index_22, " FOREIGN KEY (tenant_id, device) REFERENCES ", $access_schema, "devices (tenant_id, id);\nGRANT SELECT,INSERT ON TABLE ", $task_attempts, " TO ", $command_runtime, ";\nGRANT UPDATE(permit) ON TABLE ", $task_attempts, " TO ", $command_runtime, ";\nGRANT SELECT ON ", $task_attempts, " TO ", $policy_runtime, ";\nGRANT SELECT,INSERT ON ", $task_receipts, ",", $task_polls, " TO ", $command_runtime, ";\nGRANT UPDATE(cancellation_after,offer_after_at,offer_after_id) ON ", $task_polls, " TO ", $command_runtime, ";\nGRANT UPDATE(announcement) ON ", $bindings, " TO ", $command_runtime, ";\nALTER TABLE ", $task_receipts, " ADD FOREIGN KEY (tenant_id, device) REFERENCES ", $access_schema, "devices (tenant_id, id);\nALTER TABLE ", $task_polls, " ADD FOREIGN KEY (tenant_id, device) REFERENCES ", $access_schema, "devices (tenant_id, id);\n-- Task Trust checks live Agent signature references without reading task payloads.\nCREATE FUNCTION ", $pending_task_signatures, "(p_tenant uuid, p_key text) RETURNS boolean\nLANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$\nBEGIN\n IF p_tenant IS DISTINCT FROM nullif(current_setting('rss.tenant_id',true),'')::uuid THEN\n  RAISE EXCEPTION 'task signature tenant mismatch' USING ERRCODE='42501';\n END IF;\n RETURN EXISTS(SELECT 1 FROM ", $task_attempts, " a WHERE a.tenant_id=p_tenant AND a.deadline>extract(epoch FROM clock_timestamp()) AND (a.offer->>'keyId'=p_key OR a.permit->>'keyId'=p_key));\nEND $$;\nREVOKE ALL ON FUNCTION ", $pending_task_signatures, "(uuid,text) FROM PUBLIC;\nGRANT EXECUTE ON FUNCTION ", $pending_task_signatures, "(uuid,text) TO ", $access, ";\n\nCOMMIT;\n"),
                delivery_admission: concat!("WITH expected(name) AS (VALUES ('", $task_attempts, "'),('", $task_receipts, "'),('", $task_polls, r###"')), tables AS (SELECT c.* FROM expected e JOIN pg_class c ON c.oid=to_regclass(e.name))
SELECT (SELECT count(*) FROM tables)=3 AND NOT EXISTS(
 SELECT FROM tables t WHERE t.relkind<>'r' OR t.relpersistence<>'p' OR NOT t.relrowsecurity OR NOT t.relforcerowsecurity
 OR t.relowner=(SELECT oid FROM pg_roles WHERE rolname=current_user)
 OR (SELECT count(*) FROM pg_policy p WHERE p.polrelid=t.oid)<>1
 OR EXISTS(SELECT FROM pg_trigger WHERE tgrelid=t.oid AND NOT tgisinternal)
 OR EXISTS(SELECT FROM pg_rewrite WHERE ev_class=t.oid)
)

 AND (SELECT count(*) FROM pg_attribute WHERE attrelid='"###, $task_attempts, r###"'::regclass AND attname='deadline' AND atttypid='bigint'::regtype AND attnotnull AND NOT attisdropped)=1
 AND (SELECT count(*) FROM pg_attribute WHERE attrelid='"###, $task_polls, r###"'::regclass AND NOT attnotnull AND NOT attisdropped AND ((attname='offer_after_at' AND atttypid='bigint'::regtype) OR (attname='offer_after_id' AND atttypid='uuid'::regtype)))=2
 AND EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='"###, $task_polls, r###"'::regclass AND contype='c' AND convalidated AND lower(regexp_replace(pg_get_expr(conbin,conrelid),'[[:space:]()]','','g'))='offer_after_atisnull=offer_after_idisnull')
"###),
                authority_admission: concat!(r###"WITH expected(signature,language,result,definer,returns_set,volatility,names,config,body,roles) AS (VALUES
('"###, $pending_task_signatures, "(uuid,text)', 'plpgsql', 'boolean', true, false, 'v', ARRAY['p_tenant','p_key']::text[], ARRAY['search_path=pg_catalog']::text[], $1::text, ARRAY['", $access, "','", $owner, r###"']::text[])
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
                update_columns: concat!("('", $bindings, r###"','execution_context'),
('"###, $task_polls, r###"','cancellation_after'),
('"###, $bindings, r###"','announcement'),
('"###, $task_attempts, r###"','permit'),
('"###, $task_polls, "','offer_after_at'),('", $task_polls, r###"','offer_after_id')
"###),
                allowed_tables: concat!("('", $task_attempts, r###"',true,true,false),
('"###, $task_polls, r###"',true,true,false),
('"###, $task_receipts, r###"',true,true,false),
('"###, $bindings, r###"',true,false,false)
"###),
                object_manifest: concat!(r###"{"tables":[""###, $bindings, r###"",""###, $task_attempts, r###"",""###, $task_polls, r###"",""###, $task_receipts, r###""],"functions":[""###, $pending_task_signatures, r###""],"views":[]}"###),
                access_contract: concat!(r###"{"tables":[{"###, $contract_table_23, r###","read_write":true,"updates":[],"delete_policy":null},{"###, $contract_table_24, r###","read_write":false,"updates":[],"delete_policy":null},{"###, $contract_table_25, r###","read_write":false,"updates":[],"delete_policy":null},{"###, $contract_table_26, r###","read_write":false,"updates":[],"delete_policy":null}],"functions":[{"name":""###, $pending_task_signatures, r###"","search_path":"search_path=pg_catalog"}],"external_relations":[],"verified_schemas":[]}"###),
            };
        }
    };
}
define_storage!(
    mdm,
    "mdm_agent.",
    "SCHEMA mdm_agent",
    "mdm_access.",
    "mdm_access",
    "mdm_agent.bindings",
    "mdm_agent.task_attempts",
    "mdm_agent.task_receipts",
    "mdm_agent.task_polls",
    "mdm_agent.pending_task_signatures",
    "mdm_owner",
    "mdm_command_runtime",
    "mdm_policy_runtime",
    "mdm_inventory_runtime",
    "mdm_software_driver",
    "CREATE SCHEMA IF NOT EXISTS mdm_agent",
    "mdm_identity_runtime",
    "mdm_scope_runtime",
    "mdm_resource_runtime",
    "mdm_software_runtime",
    "mdm_telemetry_runtime",
    "ADD CONSTRAINT agent_bindings_pkey",
    "ADD CONSTRAINT agent_bindings_tenant_id_registration_fkey",
    "ADD CONSTRAINT task_attempts_tenant_id_registration_fkey",
    r###""schema":"mdm_agent","table":"bindings""###,
    r###""schema":"mdm_agent","table":"task_attempts""###,
    r###""schema":"mdm_agent","table":"task_receipts""###,
    r###""schema":"mdm_agent","table":"task_polls""###
);
define_storage!(
    da,
    "rss_da.",
    "SCHEMA rss_da",
    "rss_da.",
    "da_access",
    "rss_da.agent_bindings",
    "rss_da.agent_task_attempts",
    "rss_da.agent_task_receipts",
    "rss_da.agent_task_polls",
    "rss_da.agent_pending_task_signatures",
    "da_owner",
    "da_command_runtime",
    "da_policy_runtime",
    "da_inventory_runtime",
    "da_software_driver",
    "CREATE SCHEMA IF NOT EXISTS rss_da",
    "da_identity_runtime",
    "da_scope_runtime",
    "da_resource_runtime",
    "da_software_runtime",
    "da_telemetry_runtime",
    "ADD CONSTRAINT agent_agent_bindings_pkey",
    "ADD CONSTRAINT agent_agent_bindings_tenant_id_registration_fkey",
    "ADD CONSTRAINT agent_task_attempts_tenant_id_registration_fkey",
    r###""schema":"rss_da","table":"agent_bindings""###,
    r###""schema":"rss_da","table":"agent_task_attempts""###,
    r###""schema":"rss_da","table":"agent_task_receipts""###,
    r###""schema":"rss_da","table":"agent_task_polls""###
);
pub(crate) const fn sql(profile: StorageProfile) -> &'static Statements {
    match profile {
        StorageProfile::Mdm => &mdm::SQL,
        StorageProfile::Da => &da::SQL,
    }
}
