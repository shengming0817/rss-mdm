-- Maintenance queries do not supersede the last sealed channel fact.
BEGIN;
CREATE OR REPLACE FUNCTION mdm_access.capture_collection_history() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'mdm_access'
    AS $$
DECLARE r jsonb; d jsonb; v bigint; t uuid; fields text[];
BEGIN
 IF TG_OP='UPDATE' AND NEW IS NOT DISTINCT FROM OLD THEN RETURN NULL; END IF;
 IF TG_OP='DELETE' THEN r=to_jsonb(OLD); ELSE r=to_jsonb(NEW); END IF;
 t=(r->>'tenant_id')::uuid;
 fields=ARRAY(SELECT f->'definition'->>'key' FROM jsonb_array_elements((r->>'attempts')::jsonb->'definition'->'fields') f);
 IF TG_OP='UPDATE' AND (to_jsonb(NEW)-'delivery_pending') IS NOT DISTINCT FROM (to_jsonb(OLD)-'delivery_pending') THEN
  fields=ARRAY[]::text[];
 ELSIF r->>'result'='pending' AND cardinality(fields)>0 AND fields<@ARRAY['channel.agent.installation','channel.mdm.enrollment']::text[] THEN
  fields=ARRAY[]::text[];
 END IF;
 v=mdm.record_asset_change(t,'collection',jsonb_build_object('run',r->>'id'),fields);
 IF TG_OP<>'DELETE' THEN
  d=jsonb_build_object('id',r->>'id','result',r->>'result','attempts',r->>'attempts','delivery_pending',r->'delivery_pending');
 END IF;
 INSERT INTO mdm_access.collection_history VALUES(t,(r->>'id')::uuid,r->>'scope',(r->>'sequence')::bigint,v,d);
 RETURN NULL;
END $$;
COMMIT;
