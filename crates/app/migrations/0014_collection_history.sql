-- Collection quality is an existing asset projection. Preserve it at query watermarks.
BEGIN;
ALTER TABLE mdm.asset_changes DROP CONSTRAINT asset_changes_kind_check;
ALTER TABLE mdm.asset_changes ADD CONSTRAINT asset_changes_kind_check
 CHECK(kind IN ('inventory','manual','device','registration','source','credential','collection'));
CREATE TABLE mdm_access.collection_history (
 tenant_id uuid NOT NULL, scope text NOT NULL, sequence bigint NOT NULL,
 revision bigint NOT NULL, document jsonb CHECK(document IS NULL OR octet_length(document::text)<=16384),
 PRIMARY KEY(tenant_id,scope,sequence,revision),
 FOREIGN KEY(tenant_id,revision) REFERENCES mdm.asset_changes(tenant_id,revision)
);
ALTER TABLE mdm_access.collection_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_access.collection_history FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_access.collection_history
 USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)
 WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON mdm_access.collection_history FROM PUBLIC;
GRANT SELECT ON mdm_access.collection_history TO mdm_management_runtime;
CREATE FUNCTION mdm_access.capture_collection_history() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,mdm_access AS $$
DECLARE r jsonb; d jsonb; v bigint; t uuid;
BEGIN
 IF TG_OP='UPDATE' AND NEW IS NOT DISTINCT FROM OLD THEN RETURN NULL; END IF;
 IF TG_OP='DELETE' THEN r=to_jsonb(OLD); ELSE r=to_jsonb(NEW); END IF;
 t=(r->>'tenant_id')::uuid;
 v=mdm.record_asset_change(t,'collection',jsonb_build_object('run',r->>'id'),ARRAY[]::text[]);
 IF TG_OP<>'DELETE' THEN
  d=jsonb_build_object('id',r->>'id','result',r->>'result','attempts',r->>'attempts','delivery_pending',r->'delivery_pending');
 END IF;
 INSERT INTO mdm_access.collection_history VALUES(t,r->>'scope',(r->>'sequence')::bigint,v,d);
 RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION mdm_access.capture_collection_history() FROM PUBLIC;
CREATE TRIGGER collection_history AFTER INSERT OR UPDATE OR DELETE ON mdm_access.collection_runs
 FOR EACH ROW EXECUTE FUNCTION mdm_access.capture_collection_history();
COMMIT;
