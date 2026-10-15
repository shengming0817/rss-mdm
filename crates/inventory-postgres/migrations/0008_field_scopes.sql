-- #2726: one required namespace per frozen field. No legacy evidence conversion.
BEGIN;
SET LOCAL row_security=off;
DO $$ DECLARE n text; occupied boolean; BEGIN
 IF EXISTS(SELECT 1 FROM mdm.collection_definitions) OR EXISTS(SELECT 1 FROM mdm.collection_results)
 OR EXISTS(SELECT 1 FROM mdm.inventory) OR EXISTS(SELECT 1 FROM mdm.inventory_history) THEN
  RAISE EXCEPTION 'incompatible collection state; matching fresh installation required';
 END IF;
 FOREACH n IN ARRAY ARRAY['mdm.manual_assignments','mdm.manual_history','mdm_access.collection_runs','mdm_access.collection_history','mdm_policy.versions','mdm_commands.action_attempts','mdm_commands.remote_operations','mdm_assets.saved_queries','mdm_assets.asset_query_runs','mdm_assets.group_fields','mdm_compliance.rules','mdm_group.rules','mdm_group.member_runs','mdm_automation.automation_jobs'] LOOP
  IF to_regclass(n) IS NOT NULL THEN
   EXECUTE format('SELECT EXISTS(SELECT 1 FROM %s)',n) INTO occupied;
   IF occupied THEN RAISE EXCEPTION 'incompatible state in %; matching fresh installation required',n; END IF;
  END IF;
 END LOOP;
 FOR n IN SELECT conname FROM pg_constraint WHERE conrelid='mdm.collection_definitions'::regclass
 AND contype='c' AND pg_get_constraintdef(oid) LIKE '%scope%' LOOP
  EXECUTE format('ALTER TABLE mdm.collection_definitions DROP CONSTRAINT %I',n);
 END LOOP;
END $$;
ALTER TABLE mdm.collection_definitions ADD CONSTRAINT collection_field_scopes CHECK(
 NOT (definition ? 'scope') AND jsonb_typeof(definition->'fields')='array'
 AND jsonb_array_length(definition->'fields') BETWEEN 1 AND 128
 AND NOT jsonb_path_exists(definition, '$.fields[*] ? (!exists(@.scope) || !exists(@.definition))'));
ALTER TABLE mdm.inventory ADD COLUMN field_scope text NOT NULL CHECK(octet_length(field_scope) BETWEEN 1 AND 32768);
ALTER TABLE mdm.inventory DROP CONSTRAINT inventory_pkey;
ALTER TABLE mdm.inventory ADD PRIMARY KEY(tenant_id,journal,generation,scope,field,field_scope);
ALTER TABLE mdm.inventory_history ADD COLUMN field_scope text NOT NULL CHECK(octet_length(field_scope) BETWEEN 1 AND 32768);
ALTER TABLE mdm.inventory_history DROP CONSTRAINT inventory_history_pkey;
ALTER TABLE mdm.inventory_history ADD PRIMARY KEY(tenant_id,scope_digest,field,field_scope,revision);
CREATE OR REPLACE FUNCTION mdm.capture_inventory_history() RETURNS trigger
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
COMMIT;
