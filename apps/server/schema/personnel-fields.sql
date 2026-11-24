CREATE VIEW mdm_user_profiles.device_fields WITH(security_barrier=true) AS
SELECT field_id,revision,collected_after_micros,value FROM mdm_user_profiles.definitions
 WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
 AND value->'enabled'='true' AND value->'sensitive'='false'
 AND value->>'visibility' IN ('profiles_read','both') AND value->>'valueType' IN ('string','boolean','integer','number');
CREATE VIEW mdm_user_profiles.device_group_members WITH(security_barrier=true) AS
SELECT g.instance,(member->>'principalId')::uuid AS principal,g.id FROM mdm_access.user_groups g
 CROSS JOIN LATERAL jsonb_array_elements(g.document->'members') member
 WHERE g.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND g.document->'enabled'='true'
 AND (member->>'tenantId')::uuid=g.tenant_id AND (member->>'instanceId')::uuid=g.instance;
GRANT USAGE ON SCHEMA mdm_user_profiles TO mdm_inventory_runtime;
GRANT SELECT ON mdm_user_profiles.device_fields,mdm_user_profiles.device_group_members TO mdm_inventory_runtime;
CREATE VIEW mdm_user_profiles.attributed_devices WITH(security_barrier=true) AS
 SELECT tenant_id,device FROM mdm_access.directory_users;
GRANT SELECT ON mdm_user_profiles.attributed_devices TO mdm_inventory_runtime;

CREATE TABLE mdm_user_profiles.input_revisions (
 tenant_id uuid PRIMARY KEY, revision bigint NOT NULL
);
ALTER TABLE mdm_user_profiles.input_revisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_user_profiles.input_revisions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_user_profiles.input_revisions USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE FUNCTION mdm_user_profiles.touch_input() RETURNS trigger
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
 BEGIN
  INSERT INTO mdm_user_profiles.input_revisions VALUES(coalesce(NEW.tenant_id,OLD.tenant_id),1)
  ON CONFLICT(tenant_id) DO UPDATE SET revision=mdm_user_profiles.input_revisions.revision+1;
  RETURN NULL;
 END $$;
REVOKE ALL ON FUNCTION mdm_user_profiles.touch_input() FROM PUBLIC;
CREATE TRIGGER personnel_changed AFTER INSERT OR UPDATE OR DELETE ON mdm_access.registration_users FOR EACH ROW EXECUTE FUNCTION mdm_user_profiles.touch_input();
CREATE TRIGGER personnel_changed AFTER INSERT OR UPDATE OR DELETE ON mdm_access.current_users FOR EACH ROW EXECUTE FUNCTION mdm_user_profiles.touch_input();
CREATE TRIGGER personnel_changed AFTER INSERT OR UPDATE OR DELETE ON mdm_access.user_groups FOR EACH ROW EXECUTE FUNCTION mdm_user_profiles.touch_input();
CREATE TRIGGER personnel_changed AFTER INSERT OR UPDATE OR DELETE ON mdm_user_profiles.definitions FOR EACH ROW EXECUTE FUNCTION mdm_user_profiles.touch_input();
CREATE TRIGGER personnel_changed AFTER UPDATE OF state OR DELETE ON mdm_access.devices FOR EACH ROW EXECUTE FUNCTION mdm_user_profiles.touch_input();
CREATE TRIGGER personnel_changed AFTER INSERT OR UPDATE OF state OR DELETE ON mdm_access.credentials FOR EACH ROW EXECUTE FUNCTION mdm_user_profiles.touch_input();

-- The generation-only Identity call requests zero principals. Consumers can only test readiness.
CREATE FUNCTION mdm_user_profiles.input_stamp(instance uuid) RETURNS bigint[]
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT ARRAY[f.generation,coalesce(r.revision,0)] FROM identity_authority.personnel_facts(instance,
 nullif(current_setting('rss.tenant_id',true),'')::uuid,ARRAY[]::uuid[],'local','profile',ARRAY['emailVerified'],1) f
 LEFT JOIN mdm_user_profiles.input_revisions r ON r.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
$$;
CREATE FUNCTION mdm_user_profiles.fields_current() RETURNS boolean
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT EXISTS(SELECT FROM mdm_assets.personnel_cursor s WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
 AND published=mdm_user_profiles.input_stamp(instance) AND (valid_until IS NULL OR valid_until>extract(epoch FROM statement_timestamp())))
$$;
CREATE FUNCTION mdm_user_profiles.group_fields(ids uuid[]) RETURNS SETOF text
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 WITH RECURSIVE deps(id) AS (
  SELECT unnest(ids) UNION SELECT unnest(r.group_ids) FROM deps JOIN mdm_group.groups g
  ON g.id=deps.id AND g.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
  JOIN mdm_group.rules r ON (r.tenant_id,r.group_id,r.version)=(g.tenant_id,g.id,g.rule_version)
 ) SELECT DISTINCT f.field FROM deps JOIN mdm_assets.group_fields f ON f.group_id=deps.id AND
 f.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND split_part(f.field,'.',1)='device' AND split_part(f.field,'.',2) IN ('current_user','registration_user')
$$;
CREATE FUNCTION mdm_user_profiles.group_inputs_current(id uuid,cut jsonb) RETURNS boolean
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 WITH fields AS MATERIALIZED (SELECT * FROM mdm_user_profiles.group_fields(ARRAY[id]) AS f(field))
 SELECT NOT EXISTS(SELECT FROM fields) OR (mdm_user_profiles.fields_current()
 AND NOT EXISTS(SELECT FROM mdm.asset_changes a JOIN fields f ON f.field=ANY(a.fields)
 WHERE a.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND NOT mdm.asset_visible(cut,a.revision)))
$$;
REVOKE ALL ON FUNCTION mdm_user_profiles.input_stamp(uuid),mdm_user_profiles.fields_current(),mdm_user_profiles.group_fields(uuid[]),mdm_user_profiles.group_inputs_current(uuid,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mdm_user_profiles.input_stamp(uuid) TO mdm_inventory_runtime;
GRANT USAGE ON SCHEMA mdm_user_profiles TO mdm_access,mdm_scope_runtime,mdm_policy_runtime,mdm_telemetry_runtime;
GRANT EXECUTE ON FUNCTION mdm_user_profiles.fields_current(),mdm_user_profiles.group_fields(uuid[]),mdm_user_profiles.group_inputs_current(uuid,jsonb)
 TO mdm_access,mdm_inventory_runtime,mdm_scope_runtime,mdm_policy_runtime,mdm_telemetry_runtime;
