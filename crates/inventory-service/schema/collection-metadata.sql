-- Collection progress remains canonical for worker recovery; display reads use immutable metadata.
BEGIN;
CREATE TABLE mdm_access.collection_versions (
 tenant_id uuid NOT NULL,
 version text COLLATE "C" NOT NULL CHECK(version ~ '^[0-9a-f]{64}$'),
 format integer NOT NULL CHECK(format=1),
 metadata jsonb NOT NULL,
 metadata_bytes integer GENERATED ALWAYS AS (octet_length(metadata::text)) STORED,
 PRIMARY KEY(tenant_id,version)
);
CREATE TABLE mdm_access.collection_items (
 tenant_id uuid NOT NULL, version text COLLATE "C" NOT NULL, field text NOT NULL,
 ordinal bigint NOT NULL CHECK(ordinal>=0),
 quality text NOT NULL CHECK(quality IN ('unknown','pending','success','unsupported','failed','invalid','missing','deleted')),
 item_bytes integer GENERATED ALWAYS AS (octet_length(quality)) STORED,
 prefix_bytes bigint NOT NULL CHECK(prefix_bytes>=octet_length(quality)),
 PRIMARY KEY(tenant_id,version,field,ordinal),
 FOREIGN KEY(tenant_id,version) REFERENCES mdm_access.collection_versions(tenant_id,version)
);
ALTER TABLE mdm_access.collection_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_access.collection_versions FORCE ROW LEVEL SECURITY;
ALTER TABLE mdm_access.collection_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_access.collection_items FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_access.collection_versions USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY tenant ON mdm_access.collection_items USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON mdm_access.collection_versions,mdm_access.collection_items FROM PUBLIC;
ALTER TABLE mdm_access.collection_runs ADD COLUMN progress_version text COLLATE "C" NOT NULL;
ALTER TABLE mdm_access.collection_runs ADD FOREIGN KEY(tenant_id,progress_version) REFERENCES mdm_access.collection_versions(tenant_id,version);
CREATE FUNCTION mdm_access.capture_collection_metadata() RETURNS trigger
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
 INSERT INTO mdm_access.collection_versions(tenant_id,version,format,metadata)
 VALUES(NEW.tenant_id,NEW.progress_version,1,summary) ON CONFLICT DO NOTHING;
 GET DIAGNOSTICS inserted=ROW_COUNT;
 IF inserted=1 THEN
  INSERT INTO mdm_access.collection_items(tenant_id,version,field,ordinal,quality,prefix_bytes)
  SELECT NEW.tenant_id,NEW.progress_version,f.key,q.ordinal-1,q.quality,
    sum(octet_length(q.quality)) OVER(PARTITION BY f.key ORDER BY q.ordinal)
  FROM jsonb_each(progress->'fields') f
  CROSS JOIN LATERAL jsonb_array_elements_text(f.value->'items') WITH ORDINALITY q(quality,ordinal);
 ELSIF NOT EXISTS(SELECT FROM mdm_access.collection_versions WHERE tenant_id=NEW.tenant_id AND version=NEW.progress_version AND metadata=summary AND format=1) THEN
  RAISE EXCEPTION 'collection version mismatch' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION mdm_access.capture_collection_metadata() FROM PUBLIC;
CREATE TRIGGER capture_collection_metadata BEFORE INSERT OR UPDATE ON mdm_access.collection_runs
 FOR EACH ROW EXECUTE FUNCTION mdm_access.capture_collection_metadata();
COMMIT;
