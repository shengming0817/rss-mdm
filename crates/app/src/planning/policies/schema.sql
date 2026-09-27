CREATE TABLE mdm_planning.configuration_claims (
 tenant_id uuid NOT NULL, policy uuid NOT NULL, device text NOT NULL, version uuid NOT NULL,
 operation uuid, diagnosis text, PRIMARY KEY(tenant_id,policy,device),
 FOREIGN KEY(tenant_id,policy) REFERENCES mdm_policy.policies(tenant_id,id),
 FOREIGN KEY(tenant_id,version) REFERENCES mdm_policy.versions(tenant_id,id)
);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['configuration_claims'] LOOP
 EXECUTE format('ALTER TABLE mdm_planning.%I ENABLE ROW LEVEL SECURITY',t);
 EXECUTE format('ALTER TABLE mdm_planning.%I FORCE ROW LEVEL SECURITY',t);
 EXECUTE format('CREATE POLICY tenant ON mdm_planning.%I USING(tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid) WITH CHECK(tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid)',t);
 END LOOP;
END $$;
GRANT SELECT ON mdm_planning.configuration_claims TO mdm_command_runtime,mdm_flow_runtime;
GRANT USAGE ON SCHEMA mdm_policy TO mdm_command_runtime;
GRANT SELECT ON mdm_policy.policies,mdm_policy.versions,mdm_policy.target_revisions,mdm_policy.triggers TO mdm_command_runtime;
GRANT INSERT,DELETE ON mdm_planning.configuration_claims TO mdm_command_runtime;
GRANT UPDATE(version,operation,diagnosis) ON mdm_planning.configuration_claims TO mdm_command_runtime;

CREATE FUNCTION mdm_planning.scope_admission(p_scope uuid,p_device text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $admission$
DECLARE s record; token record; head record; member record; tenant uuid:=nullif(current_setting('rss.tenant_id',true),'')::uuid;
BEGIN
 SELECT x.deleted,x.revision,x.resolution,r.phase,r.definition_revision,r.asset_watermark,r.input INTO s
 FROM mdm_planning.scopes x LEFT JOIN mdm_planning.scope_runs r ON(r.tenant_id,r.id)=(x.tenant_id,x.resolution)
 WHERE x.tenant_id=tenant AND x.id=p_scope FOR SHARE OF x;
 IF NOT FOUND OR s.deleted THEN RETURN jsonb_build_object('state','excluded'); END IF;
 IF s.phase IS DISTINCT FROM 'published' OR s.definition_revision IS DISTINCT FROM s.revision THEN RETURN jsonb_build_object('state','pending'); END IF;
 FOR token IN
  SELECT 'group-'||v.kind||'.'||(src->'reference'->>'id') AS id,(src->>v.field)::bigint AS revision
  FROM jsonb_array_elements(s.input->'sources') src
  CROSS JOIN (VALUES('definition','definitionVersion'),('members','memberVersion'),('authority','authorityVersion')) v(kind,field)
  WHERE src->'reference'->>'kind'='group' ORDER BY id
 LOOP
  SELECT h.revision,h.required_input,h.observed_input INTO head FROM mdm_planning.source_heads h WHERE h.tenant_id=tenant AND h.id=token.id FOR SHARE;
  IF NOT FOUND OR head.revision<>token.revision OR head.observed_input<head.required_input THEN RETURN jsonb_build_object('state','pending'); END IF;
  IF token.id LIKE 'group-members.%' AND EXISTS(
   SELECT 1 FROM mdm.asset_changes c WHERE c.tenant_id=tenant AND c.revision>head.observed_input
   AND (p_device IS NULL OR c.identity->>'device'=p_device OR EXISTS(SELECT 1 FROM mdm_access.asset_authority_history h WHERE h.tenant_id=tenant AND h.kind='registration' AND h.identity=c.identity->>'registration' AND h.device=p_device))
   AND (c.kind IN('device','registration','source','credential') OR EXISTS(SELECT 1 FROM mdm_planning.group_fields f WHERE f.tenant_id=tenant AND f.group_id=substring(token.id FROM 15)::uuid AND f.field=ANY(c.fields)))
  ) THEN RETURN jsonb_build_object('state','pending'); END IF;
 END LOOP;
 IF EXISTS(SELECT 1 FROM mdm_access.asset_authority_history h WHERE h.tenant_id=tenant AND (h.device=p_device OR (p_device IS NULL AND EXISTS(SELECT 1 FROM jsonb_array_elements(s.input->'sources') src WHERE src->'reference'->>'kind'='group' OR src->'reference'->>'id'=h.device))) AND h.revision>s.asset_watermark)
 OR EXISTS(SELECT 1 FROM mdm.asset_changes c WHERE c.tenant_id=tenant AND c.revision>s.asset_watermark AND (p_device IS NULL OR c.identity->>'device'=p_device OR EXISTS(SELECT 1 FROM mdm_access.asset_authority_history h WHERE h.tenant_id=tenant AND h.kind='registration' AND h.identity=c.identity->>'registration' AND h.device=p_device))
  AND EXISTS(SELECT 1 FROM jsonb_array_elements(s.input->'sources') src JOIN mdm_planning.group_fields f ON f.tenant_id=tenant AND f.group_id=CASE WHEN src->'reference'->>'kind'='group' THEN (src->'reference'->>'id')::uuid END WHERE f.field=ANY(c.fields)))
 THEN RETURN jsonb_build_object('state','pending'); END IF;
 IF p_device IS NULL THEN RETURN jsonb_build_object('state','fresh'); END IF;
 SELECT m.matched,m.explanation,m.entry_revision INTO member FROM mdm_planning.scope_results m WHERE m.tenant_id=tenant AND m.run=s.resolution AND m.device=p_device;
 IF NOT FOUND THEN RETURN jsonb_build_object('state','excluded'); END IF;
 IF member.matched THEN RETURN jsonb_build_object('state','eligible','entry',member.entry_revision); END IF;
 IF member.explanation->'reasons' ?| ARRAY['unknown_target','unknown_limitation','unknown_exclusion'] THEN RETURN jsonb_build_object('state','pending'); END IF;
 RETURN jsonb_build_object('state','excluded');
END;
$admission$;
REVOKE ALL ON FUNCTION mdm_planning.scope_admission(uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mdm_planning.scope_admission(uuid,text) TO mdm_command_runtime,mdm_flow_runtime;
GRANT SELECT ON mdm_access.agent_bindings,mdm_access.authorization_rules,mdm_access.user_groups TO mdm_flow_runtime;
CREATE TABLE mdm_planning.configuration_devices (
 tenant_id uuid NOT NULL,device text NOT NULL,input_revision bigint NOT NULL DEFAULT 1 CHECK(input_revision>0),
 observed_revision bigint NOT NULL DEFAULT 0 CHECK(observed_revision>=0),operation uuid,digest bytea,diagnosis text,
 PRIMARY KEY(tenant_id,device)
);
ALTER TABLE mdm_planning.configuration_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_planning.configuration_devices FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_planning.configuration_devices USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON mdm_planning.configuration_devices TO mdm_flow_runtime,mdm_command_runtime;
GRANT UPDATE(input_revision) ON mdm_planning.configuration_devices TO mdm_flow_runtime,mdm_command_runtime;
GRANT UPDATE(observed_revision,operation,digest,diagnosis) ON mdm_planning.configuration_devices TO mdm_command_runtime;

CREATE FUNCTION mdm_planning.policy_lock(p_policy uuid) RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $lock$
 SELECT FROM mdm_policy.policies WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND id=p_policy FOR SHARE;
$lock$;
REVOKE ALL ON FUNCTION mdm_planning.policy_lock(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mdm_planning.policy_lock(uuid) TO mdm_flow_runtime,mdm_command_runtime;
