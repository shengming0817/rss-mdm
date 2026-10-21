CREATE SCHEMA mdm;
CREATE TABLE mdm.inventory (
 tenant_id uuid NOT NULL,
 journal text NOT NULL,
 generation text NOT NULL,
 scope text NOT NULL,
 coverage text NOT NULL,
 field text NOT NULL CHECK(length(field)<=128 AND field ~ '^(device|custom|channel)\.[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$'),
 value text CHECK(octet_length(value) BETWEEN 1 AND 16777216),
 batch_id text NOT NULL,
 observed_at bigint NOT NULL,
 received_at bigint NOT NULL,
 state text NOT NULL CHECK(state IN ('known','null','deleted','unsupported','unknown_conflict','unknown_incomplete','unknown_native','unknown_limit')),
 last_known text,
 last_known_batch text,
 last_known_observed bigint,
 last_known_received bigint,
 registration text NOT NULL,
 source text NOT NULL,
 epoch text NOT NULL,
 collection_sequence bigint NOT NULL CHECK(collection_sequence>=0),
 field_scope text NOT NULL CHECK(octet_length(field_scope) BETWEEN 1 AND 32768),
 CONSTRAINT inventory_value_state CHECK((state='known')=(value IS NOT NULL)),
 PRIMARY KEY(tenant_id,journal,generation,scope,field,field_scope)
);
ALTER TABLE mdm.inventory ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm.inventory FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm.inventory
 USING (tenant_id = nullif(current_setting('rss.tenant_id',true),'')::uuid)
 WITH CHECK (tenant_id = nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON SCHEMA mdm FROM PUBLIC;
REVOKE ALL ON mdm.inventory FROM PUBLIC;
GRANT USAGE ON SCHEMA mdm,rss_observation,rss_projection TO mdm_runtime;
GRANT SELECT,INSERT,UPDATE,DELETE ON mdm.inventory TO mdm_runtime;
GRANT SELECT ON rss_observation.objects,rss_observation.streams,rss_observation.batches,rss_observation.journals,
 rss_projection.sources,rss_projection.events,rss_projection.checkpoints,rss_projection.receipts TO mdm_runtime;
GRANT EXECUTE ON FUNCTION
 rss_observation.activate(text,numeric,text,text),rss_observation.lock_stream(text),
 rss_observation.commit_batch(text,text,numeric,bytea,bytea,bigint,text,text,numeric,boolean),
 rss_projection.assert_tenant(uuid),
 rss_projection.initialize(uuid,text,text,text,bigint,boolean,bigint,text[],bytea[],bytea),
 rss_projection.takeover(uuid,text,text,text,uuid,bytea),
 rss_projection.lock_event(uuid,text,text,text,bigint,uuid,bigint,bigint,text,bytea,bytea),
 rss_projection.finish_event(uuid,text,text,text,bigint,uuid,bigint,bigint,text,bytea,bytea)
 TO mdm_runtime;

CREATE INDEX inventory_source ON mdm.inventory(tenant_id,registration,source,epoch);
CREATE TABLE mdm.manual_assignments (
 tenant_id uuid NOT NULL, device text NOT NULL, field text NOT NULL CHECK(length(field)<=128 AND field ~ '^custom\.[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$'),
 revision bigint NOT NULL CHECK(revision>0), fact jsonb NOT NULL CHECK(octet_length(fact::text)<=16777216),
 PRIMARY KEY(tenant_id,device,field)
);
ALTER TABLE mdm.manual_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm.manual_assignments FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm.manual_assignments
 USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)
 WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON mdm.manual_assignments FROM PUBLIC;


-- Product-owned asset history. No timer, lease, or execution authority lives here.
CREATE TABLE mdm.asset_clock (
 tenant_id uuid PRIMARY KEY, revision bigint NOT NULL CHECK(revision>=0)
);
CREATE TABLE mdm.asset_changes (
 tenant_id uuid NOT NULL, revision bigint NOT NULL CHECK(revision>0),
 kind text NOT NULL CHECK(kind IN ('inventory','manual','device','registration','source','credential','collection','catalog')),
 identity jsonb NOT NULL CHECK(octet_length(identity::text)<=16384),
 fields text[] NOT NULL, forwarded boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,revision)
);
CREATE INDEX asset_changes_pending ON mdm.asset_changes(tenant_id,revision) WHERE NOT forwarded;
CREATE TABLE mdm.inventory_history (
 tenant_id uuid NOT NULL, scope_digest bytea NOT NULL CHECK(octet_length(scope_digest)=32),
 field text NOT NULL, revision bigint NOT NULL,
 document jsonb,
 field_scope text NOT NULL CHECK(octet_length(field_scope) BETWEEN 1 AND 32768),
 PRIMARY KEY(tenant_id,scope_digest,field,field_scope,revision),
 FOREIGN KEY(tenant_id,revision) REFERENCES mdm.asset_changes(tenant_id,revision),
 CHECK(document IS NULL OR octet_length(document::text)<=33554432)
);
CREATE TABLE mdm.manual_history (
 tenant_id uuid NOT NULL, device text NOT NULL, field text NOT NULL, revision bigint NOT NULL,
 document jsonb, PRIMARY KEY(tenant_id,device,field,revision),
 FOREIGN KEY(tenant_id,revision) REFERENCES mdm.asset_changes(tenant_id,revision),
 CHECK(document IS NULL OR octet_length(document::text)<=33554432)
);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['asset_clock','asset_changes','inventory_history','manual_history'] LOOP
  EXECUTE format('ALTER TABLE mdm.%I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE mdm.%I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('CREATE POLICY tenant ON mdm.%I USING(tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid) WITH CHECK(tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid)',t);
  EXECUTE format('REVOKE ALL ON mdm.%I FROM PUBLIC',t);
 END LOOP;
END $$;

-- The row lock is held until the fact transaction settles. Reading the committed
-- clock therefore cannot skip an earlier uncommitted revision, unlike a sequence.
CREATE FUNCTION mdm.record_asset_change(t uuid,k text,i jsonb,f text[]) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,mdm AS $$
DECLARE v bigint;
BEGIN
 IF t IS DISTINCT FROM nullif(current_setting('rss.tenant_id',true),'')::uuid THEN
  RAISE EXCEPTION 'asset tenant mismatch' USING ERRCODE='42501';
 END IF;
 INSERT INTO mdm.asset_clock(tenant_id,revision) VALUES(t,1)
 ON CONFLICT(tenant_id) DO UPDATE SET revision=mdm.asset_clock.revision+1
 RETURNING revision INTO v;
 INSERT INTO mdm.asset_changes(tenant_id,revision,kind,identity,fields) VALUES(t,v,k,i,f);
 PERFORM pg_catalog.pg_notify('mdm_work_' || replace(t::text,'-',''),'automation_input');
 RETURN v;
END $$;
REVOKE ALL ON FUNCTION mdm.record_asset_change(uuid,text,jsonb,text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mdm.record_asset_change(uuid,text,jsonb,text[]) TO mdm_runtime;

CREATE FUNCTION mdm.capture_inventory_history() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,mdm AS $$
DECLARE r jsonb; d jsonb; v bigint; t uuid; s bytea;
BEGIN
 IF TG_OP='UPDATE' AND NEW IS NOT DISTINCT FROM OLD THEN RETURN NEW; END IF;
 IF TG_OP='DELETE' THEN r=to_jsonb(OLD); d=NULL; ELSE r=to_jsonb(NEW); d=r; END IF;
 t=(r->>'tenant_id')::uuid;
 s=sha256(convert_to(jsonb_build_array(r->>'journal',r->>'generation',r->>'scope')::text,'UTF8'));
 v=mdm.record_asset_change(t,'inventory',jsonb_build_object('registration',r->>'registration','scope',r->>'scope','fieldScope',r->>'field_scope'),ARRAY[r->>'field']);
 INSERT INTO mdm.inventory_history(tenant_id,scope_digest,field,revision,document,field_scope) VALUES(t,s,r->>'field',v,d,r->>'field_scope');
 RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION mdm.capture_inventory_history() FROM PUBLIC;
CREATE TRIGGER inventory_history AFTER INSERT OR UPDATE OR DELETE ON mdm.inventory
 FOR EACH ROW EXECUTE FUNCTION mdm.capture_inventory_history();

CREATE FUNCTION mdm.capture_manual_history() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,mdm AS $$
DECLARE r jsonb; d jsonb; v bigint; t uuid;
BEGIN
 IF TG_OP='UPDATE' AND NEW IS NOT DISTINCT FROM OLD THEN RETURN NEW; END IF;
 IF TG_OP='DELETE' THEN r=to_jsonb(OLD); d=NULL; ELSE r=to_jsonb(NEW); d=r; END IF;
 t=(r->>'tenant_id')::uuid;
 v=mdm.record_asset_change(t,'manual',jsonb_build_object('device',r->>'device'),ARRAY[r->>'field']);
 INSERT INTO mdm.manual_history VALUES(t,r->>'device',r->>'field',v,d);
 RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION mdm.capture_manual_history() FROM PUBLIC;
CREATE TRIGGER manual_history AFTER INSERT OR UPDATE OR DELETE ON mdm.manual_assignments
 FOR EACH ROW EXECUTE FUNCTION mdm.capture_manual_history();


CREATE TABLE mdm.field_versions (
 tenant_id uuid NOT NULL, field text NOT NULL, version bigint NOT NULL CHECK(version>0),
 revision bigint NOT NULL, definition jsonb,
 PRIMARY KEY(tenant_id,field,version),
 FOREIGN KEY(tenant_id,revision) REFERENCES mdm.asset_changes(tenant_id,revision),
 CHECK(definition IS NULL OR octet_length(definition::text)<=65536)
);
CREATE INDEX field_versions_watermark ON mdm.field_versions(tenant_id,revision,field);
CREATE TABLE mdm.collection_definitions (
 tenant_id uuid NOT NULL, dataset text NOT NULL, version text NOT NULL CHECK(length(version) BETWEEN 1 AND 128),
 source text NOT NULL CHECK(source IN ('mdm.windows','mdm.apple','agent.builtin','agent.script','agent.osquery','agent.native')),
 fingerprint text NOT NULL CHECK(fingerprint ~ '^[0-9a-f]{64}$'),
 coverage text NOT NULL, definition jsonb NOT NULL CHECK(octet_length(definition::text)<=1048576),
 CONSTRAINT collection_field_scopes CHECK(
 NOT (definition ? 'scope') AND jsonb_typeof(definition->'fields')='array'
 AND jsonb_array_length(definition->'fields') BETWEEN 1 AND 128
 AND NOT jsonb_path_exists(definition, '$.fields[*] ? (!exists(@.scope) || !exists(@.definition))')),
 PRIMARY KEY(tenant_id,dataset,source,version), UNIQUE(tenant_id,coverage,source)
);
CREATE TABLE mdm.collection_results (
 tenant_id uuid NOT NULL,run text NOT NULL CHECK(length(run) BETWEEN 1 AND 256),
 scope text NOT NULL,coverage text NOT NULL,sequence bigint NOT NULL CHECK(sequence>=0),
 observed_at bigint NOT NULL,digest text NOT NULL CHECK(digest ~ '^[0-9a-f]{64}$'),
 document bytea NOT NULL CHECK(octet_length(document)<=33554432),
 PRIMARY KEY(tenant_id,run)
);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['field_versions','collection_definitions','collection_results'] LOOP
  EXECUTE format('ALTER TABLE mdm.%I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE mdm.%I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('CREATE POLICY tenant ON mdm.%I USING(tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid) WITH CHECK(tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid)',t);
  EXECUTE format('REVOKE ALL ON mdm.%I FROM PUBLIC',t);
 END LOOP;
END $$;
GRANT SELECT ON mdm.field_versions,mdm.collection_definitions,mdm.collection_results TO mdm_runtime;
GRANT SELECT ON mdm.field_versions,mdm.collection_definitions TO mdm_api;
-- Shared append primitive: publishing and owner-only initial seeds retain identical history.
CREATE FUNCTION mdm.append_field_version(t uuid, f text, v bigint, d jsonb) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $append$
DECLARE r bigint;
BEGIN
 r=mdm.record_asset_change(t,'catalog',jsonb_build_object('field',f),ARRAY[f]);
 INSERT INTO mdm.field_versions(tenant_id,field,version,revision,definition) VALUES(t,f,v,r,d);
END;
$append$;
REVOKE ALL ON FUNCTION mdm.append_field_version(uuid,text,bigint,jsonb) FROM PUBLIC;

CREATE TABLE mdm.retention_policies (
 tenant_id uuid NOT NULL,key text NOT NULL CHECK(length(key) BETWEEN 1 AND 64),
 revision bigint NOT NULL CHECK(revision>0),definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object'),
 PRIMARY KEY(tenant_id,key,revision)
);
ALTER TABLE mdm.retention_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm.retention_policies FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm.retention_policies USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON mdm.retention_policies FROM PUBLIC;
GRANT SELECT,INSERT ON mdm.retention_policies TO mdm_flow_runtime;
