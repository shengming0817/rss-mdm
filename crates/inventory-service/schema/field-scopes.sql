-- Frozen host selection metadata; the criteria remain solely in the Group core rule.
BEGIN;
CREATE TABLE mdm_assets.group_selections (
 tenant_id uuid NOT NULL, group_id uuid NOT NULL, rule_version text NOT NULL,
 selection jsonb NOT NULL CHECK(octet_length(selection::text)<=65536),
 PRIMARY KEY(tenant_id,group_id,rule_version)
);
ALTER TABLE mdm_assets.group_selections ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_assets.group_selections FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_assets.group_selections
 USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid)
 WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
ALTER TABLE mdm_assets.group_selections ADD FOREIGN KEY(tenant_id,group_id,rule_version) REFERENCES mdm_group.rules(tenant_id,group_id,version);
GRANT SELECT,INSERT ON mdm_assets.group_selections TO mdm_flow_runtime;
CREATE OR REPLACE FUNCTION mdm_access.capture_collection_history() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'mdm_access'
    AS $$
DECLARE r jsonb; d jsonb; v bigint; t uuid;
BEGIN
 IF TG_OP='UPDATE' AND NEW IS NOT DISTINCT FROM OLD THEN RETURN NULL; END IF;
 IF TG_OP='DELETE' THEN r=to_jsonb(OLD); ELSE r=to_jsonb(NEW); END IF;
 t=(r->>'tenant_id')::uuid;
 v=mdm.record_asset_change(t,'collection',jsonb_build_object('run',r->>'id'),ARRAY(SELECT f->'definition'->>'key' FROM jsonb_array_elements((r->>'attempts')::jsonb->'definition'->'fields') f));
 IF TG_OP<>'DELETE' THEN
  d=jsonb_build_object('id',r->>'id','result',r->>'result','attempts',r->>'attempts','delivery_pending',r->'delivery_pending');
 END IF;
 INSERT INTO mdm_access.collection_history VALUES(t,(r->>'id')::uuid,r->>'scope',(r->>'sequence')::bigint,v,d);
 RETURN NULL;
END $$;

COMMIT;
