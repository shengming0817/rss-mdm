//! Fixed, owner-owned SQL. Only these source literals can select objects.
use rss_mdm_install_support::StorageProfile;
pub(crate) struct Statements {
    pub collection: &'static str,
    pub collection_relations: &'static str,
    pub collection_metadata: &'static str,
    pub collection_store_start_in_1: &'static str,
    pub collection_store_save_attempts_in_1: &'static str,
    pub collection_store_seal_1: &'static str,
    pub collection_store_terminate_1: &'static str,
    pub collection_store_agent_report_in_1: &'static str,
    pub collection_store_collection_1: &'static str,
    pub collection_store_load_on_1: &'static str,
    pub collection_store_read_on_1: &'static str,
    pub collection_store_pending_count_1: &'static str,
    pub collection_store_pending_reports_1: &'static str,
    pub collection_store_expire_timed_1: &'static str,
    pub collection_store_next_expiry_1: &'static str,
    pub collection_store_delivered_1: &'static str,
    pub collection_store_delivered_2: &'static str,
    pub collection_store_expire_timed_2: &'static str,
    pub collection_agent_accept_in_1: &'static str,
    pub collection_agent_accept_in_2: &'static str,
    pub collection_agent_accept_in_3: &'static str,
    pub collection_agent_accept_in_4: &'static str,
    pub collection_channel_start_in_1: &'static str,
    pub collection_channel_finish_in_1: &'static str,
    pub collection_channel_finish_in_2: &'static str,
    pub collection_channel_abandon_in_1: &'static str,
    pub collection_channel_abandon_in_2: &'static str,
    pub assets_channel_snapshot_details_in_1: &'static str,
    pub assets_channel_snapshot_details_in_2: &'static str,
    pub object_manifest: &'static str,
    pub access_contract: &'static str,
    pub read_snapshot_install: &'static str,
    pub assets_planning_condition_inputs_in_1: &'static str,
    pub assets_raw_snapshot_read_on_1: &'static str,
    pub authority_admission: &'static str,
    pub trigger_admission: &'static str,
    pub authority_header_1: &'static str,
    pub authority_header_2: &'static str,
    pub authority_header_3: &'static str,
    pub authority_header_4: &'static str,
    pub ingestion_grants: &'static str,
}
macro_rules! define_storage {
    ($module:ident, $access_schema:literal, $access_path:literal, $access:literal, $owner:literal, $command_runtime:literal, $inventory_runtime:literal, $policy_runtime:literal, $scope_runtime:literal, $telemetry_runtime:literal, $runtime:literal, $api:literal, $index_11:literal, $index_12:literal, $index_13:literal, $index_14:literal, $index_15:literal, $index_16:literal, $index_17:literal, $index_18:literal, $index_19:literal, $index_20:literal, $index_21:literal, $index_22:literal, $index_23:literal, $contract_table_24:literal, $contract_table_25:literal, $contract_table_26:literal, $contract_table_27:literal, $access_contract_tables:literal, $access_contract_functions:literal, $access_contract_external_relations:literal, $asset_reader:literal, $asset_source:literal, $asset_schema:literal, $scope_object:literal, $authority_search_path:literal, $ingestion_runtime:literal) => {
        mod $module {
            pub(super) const SQL: super::Statements = super::Statements {
                collection: concat!("BEGIN; SET LOCAL check_function_bodies TO 'false'; CREATE FUNCTION ", $access_schema, "capture_collection_history() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path TO ", $access_path, " AS $$\nDECLARE r jsonb; d jsonb; v bigint; t uuid; fields text[];\nBEGIN\n IF TG_OP='UPDATE' AND NEW IS NOT DISTINCT FROM OLD THEN RETURN NULL; END IF;\n IF TG_OP='DELETE' THEN r=to_jsonb(OLD); ELSE r=to_jsonb(NEW); END IF;\n t=(r->>'tenant_id')::uuid;\n fields=ARRAY(SELECT f->'definition'->>'key' FROM jsonb_array_elements((r->>'attempts')::jsonb->'definition'->'fields') f);\n IF TG_OP='UPDATE' AND (to_jsonb(NEW)-'delivery_pending') IS NOT DISTINCT FROM (to_jsonb(OLD)-'delivery_pending') THEN\n  RETURN NULL;\n ELSIF r->>'result'='pending' AND cardinality(fields)>0 AND fields<@ARRAY['channel.agent.installation','channel.mdm.enrollment']::text[] THEN\n  fields=ARRAY[]::text[];\n END IF;\n v=mdm.record_asset_change(t,'collection',jsonb_build_object('fact',r->>'id','device',r->>'device','source',r->>'source','sourceEpoch',r->>'epoch','scope',r->>'scope','operation',CASE WHEN TG_OP='DELETE' THEN 'deleted' WHEN r->>'result'='failed' THEN 'failed' WHEN TG_OP='INSERT' THEN 'created' ELSE 'updated' END),fields);\n IF TG_OP<>'DELETE' THEN\n  d=jsonb_build_object('id',r->>'id','result',r->>'result','progress_version',r->>'progress_version','delivery_pending',r->'delivery_pending');\n END IF;\n INSERT INTO ", $access_schema, "collection_history VALUES(t,(r->>'id')::uuid,r->>'scope',(r->>'sequence')::bigint,v,d);\n RETURN NULL;\nEND $$; CREATE FUNCTION ", $access_schema, "immutable_collection() RETURNS trigger LANGUAGE plpgsql AS $$\nBEGIN\n IF OLD.sealed_at IS NOT NULL AND (to_jsonb(OLD)-'delivery_pending') IS DISTINCT FROM (to_jsonb(NEW)-'delivery_pending') THEN\n  -- A transport timeout with no device evidence is not a published collection result.\n  -- Only its original Agent attempt may acquire its first immutable batch.\n  IF OLD.reason='timeout' AND OLD.batch IS NULL AND OLD.digest IS NULL\n   AND OLD.source IN('agent.script','agent.osquery','agent.native')\n   AND NEW.reason='complete' AND NEW.batch IS NOT NULL AND NEW.digest IS NOT NULL\n   AND NEW.sealed_at>=OLD.sealed_at\n   AND OLD.attempts::jsonb->'definition'=NEW.attempts::jsonb->'definition'\n   AND (to_jsonb(OLD)-ARRAY['attempts','progress_version','result','reason','batch','digest','sealed_at','delivery_pending'])\n       =(to_jsonb(NEW)-ARRAY['attempts','progress_version','result','reason','batch','digest','sealed_at','delivery_pending'])\n  THEN RETURN NEW; END IF;\n  RAISE EXCEPTION 'sealed collection is immutable' USING ERRCODE='23514';\n END IF;\n RETURN NEW;\nEND $$; CREATE FUNCTION ", $access_schema, "prune_agent_collections(p_device text, p_epoch uuid) RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path TO 'pg_catalog', 'pg_temp' AS $$\nDECLARE removed bigint;\nBEGIN\n DELETE FROM ", $access_schema, "collection_runs r\n WHERE r.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid\n   AND r.device=p_device AND r.source='agent.builtin' AND r.epoch=p_epoch\n   AND NOT r.delivery_pending AND r.id IN (\n    SELECT id FROM ", $access_schema, "collection_runs\n    WHERE tenant_id=r.tenant_id AND device=p_device\n      AND source='agent.builtin' AND epoch=p_epoch AND NOT delivery_pending\n    ORDER BY sealed_at DESC,id DESC OFFSET 224\n   );\n GET DIAGNOSTICS removed = ROW_COUNT;\n RETURN removed;\nEND $$; CREATE TABLE ", $access_schema, "collection_history (tenant_id uuid NOT NULL, run uuid NOT NULL, scope text NOT NULL, sequence bigint NOT NULL, revision bigint NOT NULL, document jsonb, CONSTRAINT collection_history_document_check CHECK (document IS NULL OR octet_length(CAST(document AS text)) <= 67108864)); ALTER TABLE ONLY ", $access_schema, "collection_history FORCE ROW LEVEL SECURITY ; CREATE TABLE ", $access_schema, "collection_runs (tenant_id uuid NOT NULL, id uuid NOT NULL, device text NOT NULL, source text NOT NULL, epoch uuid NOT NULL, scope text NOT NULL, sequence bigint NOT NULL, started_at bigint NOT NULL, attempts text NOT NULL, evidence jsonb, CONSTRAINT collection_evidence_check CHECK (octet_length(CAST(evidence AS text)) <= CASE WHEN source = 'agent.builtin' AND evidence ? 'agentReport' THEN 2097152 ELSE 131072 END), result text NOT NULL, reason text, batch bytea, digest text, input_digest text CHECK (input_digest ~ '^[0-9a-f]{64}$'), sealed_at bigint, delivery_pending boolean DEFAULT FALSE NOT NULL, deadline timestamp with time zone, CONSTRAINT collection_runs_attempts_check CHECK (octet_length(attempts) <= 33554432), CONSTRAINT collection_runs_batch_check CHECK (octet_length(batch) >= 1 AND octet_length(batch) <= 4194304), CONSTRAINT collection_runs_check CHECK ((result = CAST('pending' AS text)) = (sealed_at IS NULL)), CONSTRAINT collection_runs_check1 CHECK ((sealed_at IS NULL) = (reason IS NULL)), CONSTRAINT collection_runs_check2 CHECK ((batch IS NULL) = (digest IS NULL)), CONSTRAINT collection_runs_check3 CHECK (NOT delivery_pending OR batch IS NOT NULL), CONSTRAINT collection_runs_check4 CHECK (batch IS NULL OR sealed_at IS NOT NULL), CONSTRAINT collection_runs_digest_check CHECK (digest ~ CAST('^[0-9a-f]{64}$' AS text)), CONSTRAINT collection_runs_reason_check CHECK (reason = ANY(ARRAY[CAST('complete' AS text), CAST('message_budget' AS text), CAST('aborted' AS text), CAST('timeout' AS text), CAST('superseded' AS text), CAST('revoked' AS text)])), CONSTRAINT collection_runs_result_check CHECK (result = ANY(ARRAY[CAST('pending' AS text), CAST('snapshot' AS text), CAST('partial' AS text), CAST('failed' AS text)])), CONSTRAINT collection_runs_scope_check CHECK (octet_length(scope) <= 4096), CONSTRAINT collection_runs_sequence_check CHECK (sequence >= 0), CONSTRAINT collection_runs_started_at_check CHECK (started_at >= 0), CONSTRAINT collection_source_profile CHECK ((source = 'mdm.apple' OR (source = 'mdm.windows' AND evidence ? 'nativeTemplate')) = (deadline IS NOT NULL))); ALTER TABLE ONLY ", $access_schema, "collection_runs FORCE ROW LEVEL SECURITY ; ALTER TABLE ONLY ", $access_schema, "collection_history ", $index_11, " PRIMARY KEY (tenant_id, run, revision); ALTER TABLE ONLY ", $access_schema, "collection_runs ", $index_12, " PRIMARY KEY (tenant_id, id); ", $index_13, " ON ", $access_schema, "collection_runs (tenant_id, device, source, epoch, sealed_at DESC, id DESC) WHERE source = CAST('agent.builtin' AS text) AND NOT delivery_pending; ", $index_14, " ON ", $access_schema, "collection_runs (tenant_id, deadline, id) WHERE deadline IS NOT NULL AND sealed_at IS NULL; ", $index_15, " ON ", $access_schema, "collection_runs (tenant_id, device, id) WHERE source = 'mdm.windows' AND sealed_at IS NULL; ", $index_16, " ON ", $access_schema, "collection_runs (tenant_id, device, source, epoch, sequence) WHERE source = CAST('mdm.apple' AS text); ", $index_17, " ON ", $access_schema, "collection_runs (tenant_id, device, source, epoch, sequence) WHERE delivery_pending; ", $index_18, " ON ", $access_schema, "collection_runs (tenant_id, scope, sequence) WHERE source = ANY(ARRAY[CAST('agent.script' AS text), CAST('agent.osquery' AS text), CAST('agent.native' AS text)]); ", $index_19, " ON ", $access_schema, "collection_history (tenant_id, scope, run, revision DESC); ", $index_20, " ON ", $access_schema, "collection_runs (tenant_id, device, source, epoch, sequence DESC); ", $index_21, " ON ", $access_schema, "collection_runs (tenant_id, device, source, epoch, sequence) WHERE source = CAST('mdm.windows' AS text); ALTER TABLE ", $access_schema, "collection_history ENABLE ROW LEVEL SECURITY ; ALTER TABLE ", $access_schema, "collection_runs ENABLE ROW LEVEL SECURITY ; CREATE POLICY tenant ON ", $access_schema, "collection_history AS PERMISSIVE FOR all TO PUBLIC USING (tenant_id = CAST(NULLIF(current_setting(CAST('rss.tenant_id' AS text), TRUE), CAST('' AS text)) AS uuid)) WITH CHECK (tenant_id = CAST(NULLIF(current_setting(CAST('rss.tenant_id' AS text), TRUE), CAST('' AS text)) AS uuid)); CREATE POLICY tenant ON ", $access_schema, "collection_runs AS PERMISSIVE FOR all TO PUBLIC USING (tenant_id = CAST(NULLIF(current_setting(CAST('rss.tenant_id' AS text), TRUE), CAST('' AS text)) AS uuid)) WITH CHECK (tenant_id = CAST(NULLIF(current_setting(CAST('rss.tenant_id' AS text), TRUE), CAST('' AS text)) AS uuid)); COMMIT"),
                collection_relations: concat!("BEGIN;\nSET LOCAL check_function_bodies=false;\n\n\nCREATE TRIGGER collection_history AFTER INSERT OR DELETE OR UPDATE ON ", $access_schema, "collection_runs FOR EACH ROW EXECUTE FUNCTION ", $access_schema, "capture_collection_history();\n\n\nCREATE TRIGGER immutable_collection BEFORE UPDATE ON ", $access_schema, "collection_runs FOR EACH ROW EXECUTE FUNCTION ", $access_schema, "immutable_collection();\n\n\nALTER TABLE ONLY ", $access_schema, "collection_history\n    ", $index_22, " FOREIGN KEY (tenant_id, revision) REFERENCES mdm.asset_changes(tenant_id, revision);\n\n\nALTER TABLE ONLY ", $access_schema, "collection_runs ", $index_23, " FOREIGN KEY (tenant_id, device) REFERENCES ", $access_schema, "devices (tenant_id, id);\n\n\nREVOKE ALL ON FUNCTION ", $access_schema, "capture_collection_history() FROM PUBLIC;\n\n\nREVOKE ALL ON FUNCTION ", $access_schema, "immutable_collection() FROM PUBLIC;\n\n\nREVOKE ALL ON FUNCTION ", $access_schema, "prune_agent_collections(p_device text, p_epoch uuid) FROM PUBLIC;\n\nGRANT ALL ON FUNCTION ", $access_schema, "prune_agent_collections(p_device text, p_epoch uuid) TO ", $access, ";\n\n\nGRANT SELECT ON TABLE ", $access_schema, "collection_history TO ", $inventory_runtime, ",", $access, ";\n\n\nGRANT SELECT,INSERT ON TABLE ", $access_schema, "collection_runs TO ", $access, ";\n\nGRANT SELECT,INSERT ON TABLE ", $access_schema, "collection_runs TO ", $inventory_runtime, ";\n\nGRANT SELECT,INSERT ON TABLE ", $access_schema, "collection_runs TO ", $command_runtime, ";\n\nGRANT SELECT(tenant_id,scope,id,result,attempts,evidence,sequence,sealed_at) ON ", $access_schema, "collection_runs TO ", $policy_runtime, ";\n\n\nGRANT UPDATE(attempts) ON TABLE ", $access_schema, "collection_runs TO ", $access, ";\n\nGRANT UPDATE(attempts) ON TABLE ", $access_schema, "collection_runs TO ", $command_runtime, ";\n\n\nGRANT UPDATE(result) ON TABLE ", $access_schema, "collection_runs TO ", $access, ";\n\nGRANT UPDATE(result) ON TABLE ", $access_schema, "collection_runs TO ", $command_runtime, ";\n\n\nGRANT UPDATE(reason) ON TABLE ", $access_schema, "collection_runs TO ", $access, ";\n\nGRANT UPDATE(reason) ON TABLE ", $access_schema, "collection_runs TO ", $command_runtime, ";\n\n\nGRANT UPDATE(batch) ON TABLE ", $access_schema, "collection_runs TO ", $access, ";\n\nGRANT UPDATE(batch) ON TABLE ", $access_schema, "collection_runs TO ", $command_runtime, ";\n\n\nGRANT UPDATE(digest) ON TABLE ", $access_schema, "collection_runs TO ", $access, ";\n\nGRANT UPDATE(digest) ON TABLE ", $access_schema, "collection_runs TO ", $command_runtime, ";\n\n\nGRANT UPDATE(sealed_at) ON TABLE ", $access_schema, "collection_runs TO ", $access, ";\n\nGRANT UPDATE(sealed_at) ON TABLE ", $access_schema, "collection_runs TO ", $command_runtime, ";\n\n\nGRANT UPDATE(delivery_pending) ON TABLE ", $access_schema, "collection_runs TO ", $access, ";\n\nGRANT UPDATE(delivery_pending) ON TABLE ", $access_schema, "collection_runs TO ", $command_runtime, ";\n\nGRANT UPDATE(evidence) ON ", $access_schema, "collection_runs TO ", $access, ",", $command_runtime, ";\n\n\nGRANT SELECT ON ", $access_schema, "collection_versions,", $access_schema, "collection_items TO ", $access, ",", $inventory_runtime, ",", $command_runtime, ";\n\nGRANT SELECT (tenant_id, device, source, epoch, id, scope, sequence, started_at, sealed_at, attempts, result, reason, batch, digest, input_digest)\n  ON TABLE ", $access_schema, "collection_runs\n  TO ", $telemetry_runtime, ";\n\nGRANT INSERT (tenant_id, device, source, epoch, id, scope, sequence, started_at, sealed_at, attempts, result, reason, batch, digest, input_digest, delivery_pending)\n  ON TABLE ", $access_schema, "collection_runs\n  TO ", $telemetry_runtime, ";\nCOMMIT;\n"),
                collection_metadata: concat!(r###"-- Collection progress remains canonical for worker recovery; display reads use immutable metadata.
BEGIN;
CREATE TABLE "###, $access_schema, r###"collection_versions (
 tenant_id uuid NOT NULL,
 version text COLLATE "C" NOT NULL CHECK(version ~ '^[0-9a-f]{64}$'),
 format integer NOT NULL CHECK(format=1),
 metadata jsonb NOT NULL,
 metadata_bytes integer GENERATED ALWAYS AS (octet_length(metadata::text)) STORED,
 PRIMARY KEY(tenant_id,version)
);
CREATE TABLE "###, $access_schema, r###"collection_items (
 tenant_id uuid NOT NULL, version text COLLATE "C" NOT NULL, field text NOT NULL,
 ordinal bigint NOT NULL CHECK(ordinal>=0),
 quality text NOT NULL CHECK(quality IN ('unknown','pending','success','unsupported','failed','invalid','missing','deleted')),
 item_bytes integer GENERATED ALWAYS AS (octet_length(quality)) STORED,
 prefix_bytes bigint NOT NULL CHECK(prefix_bytes>=octet_length(quality)),
 PRIMARY KEY(tenant_id,version,field,ordinal),
 FOREIGN KEY(tenant_id,version) REFERENCES "###, $access_schema, r###"collection_versions(tenant_id,version)
);
ALTER TABLE "###, $access_schema, r###"collection_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE "###, $access_schema, r###"collection_versions FORCE ROW LEVEL SECURITY;
ALTER TABLE "###, $access_schema, r###"collection_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE "###, $access_schema, r###"collection_items FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON "###, $access_schema, r###"collection_versions USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY tenant ON "###, $access_schema, r###"collection_items USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON "###, $access_schema, "collection_versions,", $access_schema, r###"collection_items FROM PUBLIC;
ALTER TABLE "###, $access_schema, r###"collection_runs ADD COLUMN progress_version text COLLATE "C" NOT NULL;
ALTER TABLE "###, $access_schema, "collection_runs ADD FOREIGN KEY(tenant_id,progress_version) REFERENCES ", $access_schema, r###"collection_versions(tenant_id,version);
CREATE FUNCTION "###, $access_schema, r###"capture_collection_metadata() RETURNS trigger
 LANGUAGE plpgsql SECURITY DEFINER SET search_path TO 'pg_catalog' AS $$
DECLARE progress jsonb; summary jsonb; inserted bigint;
BEGIN
 IF TG_OP='UPDATE' AND NEW.attempts IS NOT DISTINCT FROM OLD.attempts THEN
  NEW.progress_version=OLD.progress_version;
  RETURN NEW;
 END IF;
 progress=NEW.attempts::jsonb;
 NEW.progress_version=encode(sha256(convert_to(NEW.attempts,'UTF8')),'hex');
 SELECT jsonb_build_object('definition',progress->'definition','finished',progress->'finished','completeCoverage',progress->'completeCoverage',
   'fields',coalesce(jsonb_object_agg(f.key,(f.value-ARRAY['value','digest','confirmed','terminal','items']) ||
     jsonb_build_object('itemCount',jsonb_array_length(f.value->'items'),'invalidItems',
       (SELECT count(*) FROM jsonb_array_elements_text(f.value->'items') q WHERE q='invalid'))),'{}'::jsonb))
 INTO summary FROM jsonb_each(progress->'fields') f;
 INSERT INTO "###, $access_schema, r###"collection_versions(tenant_id,version,format,metadata)
 VALUES(NEW.tenant_id,NEW.progress_version,1,summary) ON CONFLICT DO NOTHING;
 GET DIAGNOSTICS inserted=ROW_COUNT;
 IF inserted=1 THEN
  INSERT INTO "###, $access_schema, r###"collection_items(tenant_id,version,field,ordinal,quality,prefix_bytes)
  SELECT NEW.tenant_id,NEW.progress_version,f.key,q.ordinal-1,q.quality,
    sum(octet_length(q.quality)) OVER(PARTITION BY f.key ORDER BY q.ordinal)
  FROM jsonb_each(progress->'fields') f
  CROSS JOIN LATERAL jsonb_array_elements_text(f.value->'items') WITH ORDINALITY q(quality,ordinal);
 ELSIF NOT EXISTS(SELECT FROM "###, $access_schema, r###"collection_versions WHERE tenant_id=NEW.tenant_id AND version=NEW.progress_version AND metadata=summary AND format=1) THEN
  RAISE EXCEPTION 'collection version mismatch' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION "###, $access_schema, r###"capture_collection_metadata() FROM PUBLIC;
CREATE TRIGGER capture_collection_metadata BEFORE INSERT OR UPDATE ON "###, $access_schema, r###"collection_runs
 FOR EACH ROW EXECUTE FUNCTION "###, $access_schema, r###"capture_collection_metadata();
COMMIT;
"###),
                collection_store_start_in_1: concat!("INSERT INTO ", $access_schema, "collection_runs (tenant_id, id, device, source, epoch, scope, sequence, started_at, attempts, result) VALUES (CAST($1 AS uuid), CAST($2 AS uuid), CAST($3 AS text), $4, CAST($5 AS uuid), $6, $7, CAST(floor(EXTRACT(EPOCH FROM clock_timestamp())) AS bigint), $8, 'pending')"),
                collection_store_save_attempts_in_1: concat!("UPDATE ", $access_schema, "collection_runs SET attempts=$3 WHERE tenant_id=$1::uuid AND id=$2::uuid AND sealed_at IS NULL"),
                collection_store_seal_1: concat!("UPDATE ", $access_schema, "collection_runs SET attempts=$3,result=$4,reason=$5,batch=$6,digest=$7,sealed_at=$8,delivery_pending=$9 WHERE tenant_id=$1::uuid AND id=$2::uuid AND sealed_at IS NULL"),
                collection_store_terminate_1: concat!("SELECT CAST(tenant_id AS text), CAST(device AS text), source, CAST(epoch AS text), CAST(id AS text), scope, sequence, started_at, sealed_at, attempts, result, reason, batch, digest FROM ", $access_schema, "collection_runs WHERE tenant_id = CAST($1 AS uuid) AND device = CAST($2 AS text) AND sealed_at IS NULL ORDER BY sequence FOR UPDATE"),
                collection_store_agent_report_in_1: concat!("SELECT CAST(tenant_id AS text), CAST(device AS text), source, CAST(epoch AS text), CAST(id AS text), scope, sequence, started_at, sealed_at, attempts, result, reason, batch, digest FROM ", $access_schema, "collection_runs WHERE tenant_id = CAST($1 AS uuid) AND device = CAST($2 AS text) AND source = $3 AND epoch = CAST($4 AS uuid) AND id = CAST($5 AS uuid)"),
                collection_store_collection_1: concat!("SELECT CAST(tenant_id AS text), CAST(device AS text), source, CAST(epoch AS text), CAST(id AS text), scope, sequence, started_at, sealed_at, attempts, result, reason, batch, digest FROM ", $access_schema, "collection_runs WHERE tenant_id = CAST($1 AS uuid) AND device = CAST($2 AS text) AND source = $3 AND epoch = CAST($4 AS uuid) AND CAST(scope AS jsonb) ->> 'dataset' = 'inventory' AND (CAST($5 AS uuid) IS NULL OR id = CAST($5 AS uuid)) ORDER BY sequence DESC LIMIT 1"),
                collection_store_load_on_1: concat!("SELECT CAST(tenant_id AS text), CAST(device AS text), source, CAST(epoch AS text), CAST(id AS text), scope, sequence, started_at, sealed_at, attempts, result, reason, batch, digest FROM ", $access_schema, "collection_runs WHERE tenant_id = CAST($1 AS uuid) AND id = CAST($2 AS uuid) FOR UPDATE"),
                collection_store_read_on_1: concat!("SELECT CAST(tenant_id AS text), CAST(device AS text), source, CAST(epoch AS text), CAST(id AS text), scope, sequence, started_at, sealed_at, attempts, result, reason, batch, digest FROM ", $access_schema, "collection_runs WHERE tenant_id = CAST($1 AS uuid) AND id = CAST($2 AS uuid)"),
                collection_store_pending_count_1: concat!("SELECT count(*) FROM (SELECT 1 FROM ", $access_schema, "collection_runs WHERE tenant_id=$1::uuid AND delivery_pending LIMIT 1001) q"),
                collection_store_pending_reports_1: concat!("SELECT CAST(tenant_id AS text), CAST(device AS text), source, CAST(epoch AS text), CAST(id AS text), scope, sequence, started_at, sealed_at, attempts, result, reason, batch, digest FROM ", $access_schema, "collection_runs WHERE tenant_id = CAST($1 AS uuid) AND delivery_pending ORDER BY device, source, epoch, sequence, id LIMIT 32"),
                collection_store_expire_timed_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $access_schema, "collection_runs WHERE tenant_id=$1::uuid AND sealed_at IS NULL AND deadline<=clock_timestamp())"),
                collection_store_next_expiry_1: concat!("SELECT ceil(extract(epoch FROM min(deadline)-clock_timestamp())*1000)::bigint FROM ", $access_schema, "collection_runs WHERE tenant_id=$1::uuid AND sealed_at IS NULL AND deadline>clock_timestamp()"),
                collection_store_delivered_1: concat!("SELECT scope,sequence,digest,delivery_pending FROM ", $access_schema, "collection_runs WHERE tenant_id=$1::uuid AND id=$2::uuid FOR UPDATE"),
                collection_store_delivered_2: concat!("UPDATE ", $access_schema, "collection_runs SET delivery_pending=false WHERE tenant_id=$1::uuid AND id=$2::uuid AND digest=$3 AND delivery_pending"),
                collection_store_expire_timed_2: concat!("SELECT id::text,scope::jsonb->>'dataset' FROM ", $access_schema, "collection_runs WHERE tenant_id=$1::uuid AND sealed_at IS NULL AND deadline<=clock_timestamp() ORDER BY deadline,id LIMIT 32 FOR UPDATE SKIP LOCKED"),
                collection_agent_accept_in_1: concat!("SELECT CAST(device AS text), source, CAST(epoch AS text), input_digest, sealed_at FROM ", $access_schema, "collection_runs WHERE tenant_id = CAST($1 AS uuid) AND id = CAST($2 AS uuid) FOR SHARE"),
                collection_agent_accept_in_2: concat!("SELECT count(*) FROM ", $access_schema, "collection_runs WHERE tenant_id = CAST($1 AS uuid) AND device = CAST($2 AS text) AND source = 'agent.builtin' AND epoch = CAST($3 AS uuid) AND delivery_pending"),
                collection_agent_accept_in_3: concat!("SELECT ", $access_schema, "prune_agent_collections($1::text,$2::uuid)"),
                collection_agent_accept_in_4: concat!("INSERT INTO ", $access_schema, "collection_runs (tenant_id, id, device, source, epoch, scope, sequence, started_at, attempts, result, reason, batch, digest, sealed_at, delivery_pending, input_digest, evidence) VALUES (CAST($1 AS uuid), CAST($4 AS uuid), CAST($2 AS text), 'agent.builtin', CAST($3 AS uuid), $6, $5, $9, $11, $10, 'complete', $7, $8, $9, TRUE, $12, $13)"),
                collection_channel_start_in_1: concat!("INSERT INTO ", $access_schema, "collection_runs (tenant_id, id, device, source, epoch, scope, sequence, started_at, attempts, result, evidence, deadline) VALUES (CAST($1 AS uuid), $2, $3, $4, CAST($5 AS uuid), $6, $7, $8, $9, 'pending', $10, CASE WHEN $4 = 'mdm.apple' THEN clock_timestamp() + CAST('5 minutes' AS interval) END)"),
                collection_channel_finish_in_1: concat!("SELECT scope, sequence, sealed_at, attempts FROM ", $access_schema, "collection_runs WHERE tenant_id = CAST($1 AS uuid) AND id = $2 AND device = $3 AND source = $4 AND epoch = CAST($5 AS uuid) FOR UPDATE"),
                collection_channel_finish_in_2: concat!("UPDATE ", $access_schema, "collection_runs SET attempts=$3,result='snapshot',reason='complete',batch=$4,digest=$5,sealed_at=$6,delivery_pending=true,evidence=$7::jsonb WHERE tenant_id=$1::uuid AND id=$2"),
                collection_channel_abandon_in_1: concat!("SELECT attempts FROM ", $access_schema, "collection_runs WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE"),
                collection_channel_abandon_in_2: concat!("UPDATE ", $access_schema, "collection_runs SET attempts = $3, result = 'failed', reason = $4, sealed_at = $5, delivery_pending = FALSE WHERE tenant_id = CAST($1 AS uuid) AND id = $2 AND sealed_at IS NULL RETURNING device"),

                assets_channel_snapshot_details_in_1: concat!("SELECT r.id, s.source, s.epoch FROM unnest(CAST($2 AS text[]), CAST($3 AS text[]), CAST($4 AS text[])) AS t (id, source, channel) INNER JOIN ", $access_schema, "devices AS r ON r.tenant_id = CAST($1 AS uuid) AND r.id = t.id AND r.channel = t.channel AND r.state = 'active' INNER JOIN ", $access_schema, "report_sources AS s ON s.tenant_id = r.tenant_id AND s.device = r.id AND s.source = t.source AND s.enabled"),
                assets_channel_snapshot_details_in_2: concat!("WITH selected AS MATERIALIZED(SELECT DISTINCT ON(scope) scope,id,result,attempts,evidence::text AS evidence FROM ", $access_schema, "collection_runs WHERE tenant_id=$1::uuid AND scope=ANY($2) AND sealed_at IS NOT NULL ORDER BY scope,sequence DESC),budget AS(SELECT coalesce(sum(pg_column_size(selected)),0)<=16777216 AS ok FROM selected) SELECT selected.*,budget.ok AS within_budget FROM budget LEFT JOIN selected ON budget.ok"),
                object_manifest: concat!(r###"{"tables":[""###, $access_schema, r###"collection_history",""###, $access_schema, r###"collection_items",""###, $access_schema, r###"collection_runs",""###, $access_schema, r###"collection_versions"],"functions":[""###, $access_schema, r###"capture_collection_history",""###, $access_schema, r###"capture_collection_metadata",""###, $access_schema, r###"immutable_collection",""###, $access_schema, r###"prune_agent_collections",""###, $asset_reader, r###""],"views":[]}"###),
                access_contract: concat!(r###"{"tables":[{"###, $contract_table_24, r###","read_write":false,"read_only":true,"updates":[],"delete_policy":null},{"###, $contract_table_25, r###","read_write":true,"updates":["attempts","result","reason","batch","digest","sealed_at","delivery_pending","evidence"],"delete_policy":null},{"###, $contract_table_26, r###","read_write":false,"read_only":true,"updates":[],"delete_policy":null},{"###, $contract_table_27, r###","read_write":false,"read_only":true,"updates":[],"delete_policy":null}"###, $access_contract_tables, r###"],"functions":[{"name":""###, $asset_reader, r###"","search_path":"search_path=pg_catalog"},{"name":""###, $access_schema, r###"prune_agent_collections","search_path":"search_path=pg_catalog, pg_temp"},{"name":"mdm.capture_asset_cut","search_path":"search_path=pg_catalog, mdm"},{"name":"mdm.asset_cut_contains","search_path":"search_path=pg_catalog, mdm"},{"name":"mdm.asset_cut_context","search_path":"search_path=pg_catalog, mdm"},{"name":"mdm.asset_visible","search_path":"search_path=pg_catalog, mdm"}"###, $access_contract_functions, r###"],"external_relations":["mdm.field_versions","mdm.collection_definitions","mdm.collection_results","mdm.array_versions","mdm.array_items","mdm.manual_assignments""###, $access_contract_external_relations, r###"],"verified_schemas":[]}"###),
                read_snapshot_install: concat!(r###"-- Bounded raw facts only. Rust retains field validation, provenance decoding and resolution.
CREATE FUNCTION "###, $asset_reader, r###"(p_devices text[],p_fields text[],p_cut jsonb,p_scope jsonb)
RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
WITH context AS (
 SELECT nullif(current_setting('rss.tenant_id',true),'')::uuid AS tenant
 WHERE cardinality(p_devices)<=1000 AND cardinality(p_fields)<=1024 AND (p_cut IS NULL OR (p_cut->>'tenant')::uuid=nullif(current_setting('rss.tenant_id',true),'')::uuid)
), catalog AS MATERIALIZED (
 SELECT field,definition FROM (
  SELECT DISTINCT ON(field) field,definition FROM mdm.field_versions
  WHERE tenant_id=(SELECT tenant FROM context) AND field=ANY(p_fields) AND (p_cut IS NULL OR mdm.asset_visible(p_cut,revision))
  ORDER BY field,version DESC
 ) latest WHERE definition IS NOT NULL AND definition->>'sensitivity'<>'secret'
), datasets AS MATERIALIZED (
 SELECT DISTINCT source,dataset FROM mdm.collection_definitions
 WHERE tenant_id=(SELECT tenant FROM context) AND EXISTS(
  SELECT FROM jsonb_array_elements(definition->'fields') f WHERE f->'scope'=p_scope AND f->'definition'->>'key'=ANY(p_fields)
 ) ORDER BY source,dataset LIMIT 4097
), sources AS MATERIALIZED (
 SELECT DISTINCT r.device,r.channel,r.source,r.epoch,d.dataset,
 format('{"tenant":%s,"object":%s,"registration":%s,"source":%s,"dataset":%s,"epoch":%s}',
  to_json((SELECT tenant::text FROM context)),to_json("###, $scope_object, r###"),
  to_json(r.device),to_json(r.source),to_json(d.dataset),to_json(r.epoch)) AS scope
 FROM "###, $asset_source, r###"(p_devices,p_cut) r JOIN datasets d USING(source)
 LIMIT 2001
), latest AS MATERIALIZED (
 SELECT DISTINCT ON(h.scope_digest,h.field,h.field_scope) h.scope_digest,h.field,h.field_scope,h.document
 FROM sources s JOIN mdm.inventory_history h ON h.scope_digest=sha256(convert_to(jsonb_build_array('mdm.observation.v1'::text,'inventory-projection-v1'::text,s.scope)::text,'UTF8'))
 WHERE h.tenant_id=(SELECT tenant FROM context) AND (p_cut IS NULL OR mdm.asset_visible(p_cut,h.revision)) AND h.field IN(SELECT field FROM catalog)
 ORDER BY h.scope_digest,h.field,h.field_scope,h.revision DESC
), observed AS MATERIALIZED (
 SELECT DISTINCT ON(r.scope,r.field,r.field_scope) to_jsonb(r)||jsonb_build_object('definition',d.definition::text) AS document
 FROM latest h CROSS JOIN LATERAL jsonb_populate_record(NULL::mdm.inventory,h.document) r
 JOIN mdm.collection_definitions d ON(d.tenant_id,d.coverage,d.source)=(r.tenant_id,r.coverage,r.source)
 WHERE h.document IS NOT NULL AND r.journal='mdm.observation.v1' AND r.generation='inventory-projection-v1'
  AND r.scope IN(SELECT scope FROM sources) AND r.field_scope::jsonb=p_scope
 ORDER BY r.scope,r.field,r.field_scope,r.collection_sequence DESC LIMIT 131073
), manual AS MATERIALIZED (
 SELECT document||jsonb_build_object('array',c.definition->'valueType'->>'kind'='array') AS document
 FROM (
  SELECT DISTINCT ON(device,field) field,document FROM mdm.manual_history
  WHERE tenant_id=(SELECT tenant FROM context) AND device=ANY(p_devices) AND (p_cut IS NULL OR mdm.asset_visible(p_cut,revision))
   AND field IN(SELECT field FROM catalog) AND p_scope='{"kind":"device"}'::jsonb
  ORDER BY device,field,revision DESC
 ) h JOIN catalog c USING(field) WHERE document IS NOT NULL LIMIT 131073
), versions AS MATERIALIZED (
 SELECT version,format,jsonb_build_object('version',version,'field',field,'definitionDigest',definition_digest,'count',item_count,'bytes',canonical_bytes,'digest',digest) AS document
 FROM mdm.array_versions WHERE tenant_id=(SELECT tenant FROM context) AND version IN(
  SELECT document->>'value_version' FROM observed UNION SELECT document->>'last_known_version' FROM observed
  UNION SELECT document->>'value_version' FROM manual UNION SELECT document->>'last_known_version' FROM manual
 )
), quality_history AS MATERIALIZED (
 SELECT DISTINCT ON(h.scope,h.run) h.scope,h.sequence,h.run,h.document
 FROM sources s JOIN "###, $access_schema, r###"collection_history h ON h.scope=s.scope
 WHERE h.tenant_id=(SELECT tenant FROM context) AND (p_cut IS NULL OR mdm.asset_visible(p_cut,h.revision))
 ORDER BY h.scope,h.run,h.revision DESC
), quality_fields AS MATERIALIZED (
 SELECT DISTINCT ON(h.scope,f->'definition'->>'key') h.scope,h.sequence,h.run,h.document,f->'definition'->>'key' AS field
 FROM quality_history h JOIN "###, $access_schema, r###"collection_versions v ON v.tenant_id=(SELECT tenant FROM context) AND v.version=h.document->>'progress_version'
 CROSS JOIN LATERAL jsonb_array_elements(v.metadata->'definition'->'fields') f
 WHERE h.document IS NOT NULL AND f->'scope'=p_scope AND f->'definition'->>'key'=ANY(p_fields)
  AND (h.document->>'result'<>'pending' OR f->'definition'->>'key' NOT IN('channel.agent.installation','channel.mdm.enrollment'))
 ORDER BY h.scope,f->'definition'->>'key',h.sequence DESC,h.run DESC
), quality AS MATERIALIZED (
 SELECT jsonb_build_object('scope',h.scope,'sequence',h.sequence,'id',h.run,'result',h.document->>'result',
  'metadata',CASE WHEN v.metadata_bytes<=67108864 THEN v.metadata::text END,
  'delivery_pending',(h.document->>'delivery_pending')::boolean,'selected_fields',jsonb_agg(h.field ORDER BY h.field)) AS document
 FROM quality_fields h JOIN "###, $access_schema, r###"collection_versions v ON v.tenant_id=(SELECT tenant FROM context) AND v.version=h.document->>'progress_version'
 GROUP BY h.scope,h.sequence,h.run,h.document,v.metadata,v.metadata_bytes LIMIT 131073
), budget AS (
 SELECT (SELECT count(*) FROM context)=1 AND (SELECT count(*) FROM sources)<=2000 AND (SELECT count(*) FROM datasets)<=4096
  AND (SELECT count(*) FROM observed)<=131072 AND (SELECT count(*) FROM manual)<=131072 AND (SELECT count(*) FROM quality)<=131072
  AND coalesce((SELECT sum(octet_length(document::text)) FROM (
   SELECT document FROM observed UNION ALL SELECT document FROM manual UNION ALL SELECT document FROM quality UNION ALL SELECT document FROM versions
  ) bytes),0)<=16777216 AND NOT EXISTS(SELECT FROM versions WHERE format<>1) AS ok
)
SELECT CASE WHEN (SELECT ok FROM budget) THEN jsonb_build_object('ok',true,
 'catalog',coalesce((SELECT jsonb_agg(definition ORDER BY field) FROM catalog),'[]'::jsonb),
 'sources',coalesce((SELECT jsonb_agg(to_jsonb(s) ORDER BY scope) FROM sources s),'[]'::jsonb),
 'observed',coalesce((SELECT jsonb_agg(document) FROM observed),'[]'::jsonb),
 'manual',coalesce((SELECT jsonb_agg(document) FROM manual),'[]'::jsonb),
 'versions',coalesce((SELECT jsonb_object_agg(version,document) FROM versions),'{}'::jsonb),
 'quality',coalesce((SELECT jsonb_agg(document) FROM quality),'[]'::jsonb))
 ELSE jsonb_build_object('ok',false) END
$$;
REVOKE ALL ON FUNCTION "###, $asset_reader, r###"(text[],text[],jsonb,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "###, $asset_reader, "(text[],text[],jsonb,jsonb) TO ", $access, ",mdm_identity_runtime,", $inventory_runtime, ",", $scope_runtime, ",", $policy_runtime, ",", $telemetry_runtime, ",", $command_runtime, r###";
GRANT USAGE ON "###, $asset_schema, " TO ", $command_runtime, r###";
"###),
                assets_planning_condition_inputs_in_1: concat!("SELECT DISTINCT (f->'scope')::text AS scope FROM ", $access_schema, "collection_history h JOIN ", $access_schema, "collection_versions v ON v.tenant_id=h.tenant_id AND v.version=h.document->>'progress_version' CROSS JOIN LATERAL jsonb_array_elements(v.metadata->'definition'->'fields') f WHERE h.tenant_id=$1::uuid AND mdm.asset_visible($2,h.revision) AND h.scope::jsonb->>'registration'=ANY($3) AND ($4::text IS NULL OR ($5::text='macos' AND ((f->'scope'->>'kind' IN ('macos_applications','macos_brew') AND f->'scope'->>'uid'=$4) OR (f->'scope'->'owner'->>'kind'='macos' AND f->'scope'->'owner'->>'uid'=$4))) OR ($5::text='windows' AND f->'scope'->'owner'->>'kind'='windows' AND f->'scope'->'owner'->>'sid'=$4)) LIMIT 129"),
                assets_raw_snapshot_read_on_1: concat!("SELECT ", $asset_reader, "($2,$3,$4,$5) WHERE nullif(current_setting('rss.tenant_id',true),'')=$1"),
                authority_admission: concat!(r###"-- Only authorization/fencing kernels; bodies come directly from their owner's installation SQL.
WITH expected(signature,language,result,definer,returns_set,volatility,names,config,body,roles) AS (VALUES
 ('"###, $access_schema, "capture_collection_history()', 'plpgsql', 'trigger', true, false, 'v', ARRAY[]::text[], ARRAY['", $authority_search_path, "']::text[], $1::text, ARRAY['", $owner, r###"']::text[]),
 ('"###, $access_schema, "immutable_collection()', 'plpgsql', 'trigger', false, false, 'v', ARRAY[]::text[], NULL::text[], $2::text, ARRAY['", $owner, r###"']::text[]),
 ('"###, $access_schema, "capture_collection_metadata()', 'plpgsql', 'trigger', true, false, 'v', ARRAY[]::text[], ARRAY['search_path=pg_catalog']::text[], $3::text, ARRAY['", $owner, r###"']::text[]),
 ('"###, $asset_reader, "(text[],text[],jsonb,jsonb)', 'sql', 'jsonb', true, false, 's', ARRAY['p_devices','p_fields','p_cut','p_scope']::text[], ARRAY['search_path=pg_catalog']::text[], $4::text, ARRAY['", $access, "','mdm_identity_runtime','", $inventory_runtime, "','", $scope_runtime, "','", $policy_runtime, "','", $telemetry_runtime, "','", $command_runtime, "','", $owner, r###"']::text[])
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
                trigger_admission: concat!(r###"-- The producer's history and immutable metadata must run on every relevant write.
WITH required(name,function,events) AS (VALUES
 ('collection_history','"###, $access_schema, r###"capture_collection_history()',29),
 ('immutable_collection','"###, $access_schema, r###"immutable_collection()',19),
 ('capture_collection_metadata','"###, $access_schema, r###"capture_collection_metadata()',23)
)
SELECT NOT EXISTS(SELECT 1 FROM required r WHERE NOT EXISTS(
 SELECT 1 FROM pg_trigger t WHERE t.tgrelid='"###, $access_schema, r###"collection_runs'::regclass
 AND t.tgname=r.name AND t.tgfoid=to_regprocedure(r.function) AND t.tgtype=r.events
 AND t.tgenabled IN('O','A') AND NOT t.tgisinternal AND t.tgqual IS NULL
 AND t.tgnargs=0 AND t.tgattr=''::int2vector))
"###),
                authority_header_1: concat!("CREATE FUNCTION ", $access_schema, "capture_collection_history("),
                authority_header_2: concat!("CREATE FUNCTION ", $access_schema, "immutable_collection("),
                authority_header_3: concat!("CREATE FUNCTION ", $access_schema, "capture_collection_metadata("),
                authority_header_4: concat!("CREATE FUNCTION ", $asset_reader, "("),
                ingestion_grants: concat!(r###"BEGIN;
GRANT USAGE ON SCHEMA mdm TO "###, $ingestion_runtime, r###";
GRANT USAGE ON SCHEMA rss_observation TO "###, $ingestion_runtime, r###";
GRANT USAGE ON SCHEMA rss_projection TO "###, $ingestion_runtime, r###";
GRANT ALL ON FUNCTION mdm.record_asset_change(t uuid, k text, i jsonb, f text[]) TO "###, $ingestion_runtime, r###";
REVOKE ALL ON FUNCTION rss_observation.activate(p_scope text, p_expected numeric, p_policy text, p_initial text) FROM PUBLIC;
GRANT ALL ON FUNCTION rss_observation.activate(p_scope text, p_expected numeric, p_policy text, p_initial text) TO "###, $ingestion_runtime, r###";
REVOKE ALL ON FUNCTION rss_observation.commit_batch(p_scope text, p_id text, p_sequence numeric, p_raw bytea, p_fingerprint bytea, p_received bigint, p_policy text, p_decision text, p_expected numeric, p_applicable boolean) FROM PUBLIC;
GRANT ALL ON FUNCTION rss_observation.commit_batch(p_scope text, p_id text, p_sequence numeric, p_raw bytea, p_fingerprint bytea, p_received bigint, p_policy text, p_decision text, p_expected numeric, p_applicable boolean) TO "###, $ingestion_runtime, r###";
GRANT SELECT ON TABLE rss_observation.streams TO "###, $ingestion_runtime, r###";
REVOKE ALL ON FUNCTION rss_observation.lock_stream(p_scope text) FROM PUBLIC;
GRANT ALL ON FUNCTION rss_observation.lock_stream(p_scope text) TO "###, $ingestion_runtime, r###";
REVOKE ALL ON FUNCTION rss_projection.append_event(t uuid, s text, e text, bytes bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION rss_projection.assert_tenant(t uuid) FROM PUBLIC;
GRANT ALL ON FUNCTION rss_projection.assert_tenant(t uuid) TO "###, $ingestion_runtime, r###";
REVOKE ALL ON FUNCTION rss_projection.finish_event(t uuid, s text, p text, g text, worker_epoch bigint, token uuid, expected bigint, at_position bigint, e text, digest bytea, definition bytea) FROM PUBLIC;
GRANT ALL ON FUNCTION rss_projection.finish_event(t uuid, s text, p text, g text, worker_epoch bigint, token uuid, expected bigint, at_position bigint, e text, digest bytea, definition bytea) TO "###, $ingestion_runtime, r###";
REVOKE ALL ON FUNCTION rss_projection.initialize(t uuid, s text, p text, g text, start_at bigint, is_replay boolean, end_at bigint, ids text[], digests bytea[], definition bytea) FROM PUBLIC;
GRANT ALL ON FUNCTION rss_projection.initialize(t uuid, s text, p text, g text, start_at bigint, is_replay boolean, end_at bigint, ids text[], digests bytea[], definition bytea) TO "###, $ingestion_runtime, r###";
REVOKE ALL ON FUNCTION rss_projection.lock_event(t uuid, s text, p text, g text, worker_epoch bigint, token uuid, expected bigint, at_position bigint, e text, digest bytea, definition bytea) FROM PUBLIC;
GRANT ALL ON FUNCTION rss_projection.lock_event(t uuid, s text, p text, g text, worker_epoch bigint, token uuid, expected bigint, at_position bigint, e text, digest bytea, definition bytea) TO "###, $ingestion_runtime, r###";
REVOKE ALL ON FUNCTION rss_projection.takeover(t uuid, s text, p text, g text, token uuid, definition bytea) FROM PUBLIC;
GRANT ALL ON FUNCTION rss_projection.takeover(t uuid, s text, p text, g text, token uuid, definition bytea) TO "###, $ingestion_runtime, r###";
GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE mdm.inventory TO "###, $ingestion_runtime, r###";
GRANT SELECT ON TABLE rss_observation.batches TO "###, $ingestion_runtime, r###";
GRANT SELECT ON TABLE rss_observation.journals TO "###, $ingestion_runtime, r###";
GRANT SELECT ON TABLE rss_observation.objects TO "###, $ingestion_runtime, r###";
GRANT SELECT ON TABLE rss_projection.checkpoints TO "###, $ingestion_runtime, r###";
GRANT SELECT ON TABLE rss_projection.events TO "###, $ingestion_runtime, r###";
GRANT SELECT ON TABLE rss_projection.receipts TO "###, $ingestion_runtime, r###";
GRANT SELECT ON TABLE rss_projection.sources TO "###, $ingestion_runtime, r###";
GRANT SELECT,INSERT ON mdm.array_versions,mdm.array_items TO "###, $ingestion_runtime, r###";
GRANT SELECT ON mdm.field_versions,mdm.collection_definitions,mdm.collection_results TO "###, $ingestion_runtime, r###";
COMMIT;
"###),
            };
        }
    };
}
define_storage!(
    mdm,
    "mdm_access.",
    "'pg_catalog', 'mdm_access'",
    "mdm_access",
    "mdm_owner",
    "mdm_command_runtime",
    "mdm_inventory_runtime",
    "mdm_policy_runtime",
    "mdm_scope_runtime",
    "mdm_telemetry_runtime",
    "mdm_runtime",
    "mdm_api",
    "ADD CONSTRAINT collection_history_pkey",
    "ADD CONSTRAINT collection_runs_pkey",
    "CREATE INDEX collection_agent_retention",
    "CREATE INDEX collection_timed_pending",
    "CREATE INDEX collection_windows_pending",
    "CREATE UNIQUE INDEX collection_apple_sequence",
    "CREATE INDEX collection_delivery",
    "CREATE UNIQUE INDEX collection_enterprise_sequence",
    "CREATE INDEX collection_history_scope",
    "CREATE INDEX collection_latest",
    "CREATE UNIQUE INDEX collection_windows_sequence",
    "ADD CONSTRAINT collection_history_tenant_id_revision_fkey",
    "ADD CONSTRAINT collection_runs_tenant_id_registration_fkey",
    r###""schema":"mdm_access","table":"collection_history""###,
    r###""schema":"mdm_access","table":"collection_runs""###,
    r###""schema":"mdm_access","table":"collection_versions""###,
    r###""schema":"mdm_access","table":"collection_items""###,
    r###",{"schema":"mdm_inventory","table":"collection_operations","read_write":true,"updates":[],"delete_policy":null},{"schema":"mdm_inventory","table":"collection_tasks","read_write":false,"updates":[],"delete_policy":null,"read_only":true},{"schema":"mdm_inventory","table":"collection_admission","read_write":false,"updates":[],"delete_policy":null},{"schema":"mdm_inventory","table":"collection_output_chunks","read_write":false,"updates":[],"delete_policy":null},{"schema":"mdm_inventory","table":"collection_policy_recovery","read_write":false,"updates":[],"delete_policy":null},{"schema":"mdm_inventory","table":"collection_native_checkins","read_write":false,"updates":[],"delete_policy":null}"###,
    r###",{"name":"mdm_inventory.save_retired_collection_agent","search_path":"search_path=pg_catalog"},{"name":"mdm_inventory.cancel_retired_collection","search_path":"search_path=pg_catalog"}"###,
    r###","mdm_assets.directory_fields","mdm_assets.directory_sources","mdm_assets.hardware_keys","mdm_assets.directory_inputs","mdm.inventory_presence""###,
    "mdm_assets.read_snapshot",
    "mdm_access.asset_sources_at",
    "SCHEMA mdm_assets",
    "CASE WHEN d.dataset='inventory' THEN r.device ELSE r.device||':'||d.dataset END",
    "search_path=pg_catalog, mdm_access",
    "mdm_runtime"
);
define_storage!(
    da,
    "rss_da.",
    "'pg_catalog', 'rss_da'",
    "da_access",
    "da_owner",
    "da_command_runtime",
    "da_inventory_runtime",
    "da_policy_runtime",
    "da_scope_runtime",
    "da_telemetry_runtime",
    "da_runtime",
    "da_api",
    "ADD CONSTRAINT inventory_collection_history_pkey",
    "ADD CONSTRAINT inventory_collection_runs_pkey",
    "CREATE INDEX inventory_collection_agent_retention",
    "CREATE INDEX inventory_collection_timed_pending",
    "CREATE INDEX inventory_collection_windows_pending",
    "CREATE UNIQUE INDEX inventory_collection_apple_sequence",
    "CREATE INDEX inventory_collection_delivery",
    "CREATE UNIQUE INDEX inventory_collection_enterprise_sequence",
    "CREATE INDEX inventory_collection_history_scope",
    "CREATE INDEX inventory_collection_latest",
    "CREATE UNIQUE INDEX inventory_collection_windows_sequence",
    "ADD CONSTRAINT inventory_collection_history_tenant_id_revision_fkey",
    "ADD CONSTRAINT inventory_collection_runs_tenant_id_registration_fkey",
    r###""schema":"rss_da","table":"collection_history""###,
    r###""schema":"rss_da","table":"collection_runs""###,
    r###""schema":"rss_da","table":"collection_versions""###,
    r###""schema":"rss_da","table":"collection_items""###,
    "",
    "",
    "",
    "rss_da.read_asset_snapshot",
    "rss_da.asset_sources_at",
    "SCHEMA rss_da",
    "'da:'||(CASE WHEN d.dataset='inventory' THEN r.device ELSE r.device||':'||d.dataset END)",
    "search_path=pg_catalog, rss_da",
    "da_runtime"
);
pub(crate) const fn sql(profile: StorageProfile) -> &'static Statements {
    match profile {
        StorageProfile::Mdm => &mdm::SQL,
        StorageProfile::Da => &da::SQL,
    }
}
