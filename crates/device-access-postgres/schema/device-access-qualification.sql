-- The Policy provider owns definitions; DA uses only an explicit override or tenant default.
CREATE FUNCTION rss_da.access_policy(p_policy uuid,p_device uuid,p_as_of bigint) RETURNS jsonb
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT coalesce((SELECT CASE WHEN selected.id=p_policy AND selected.state='enabled' THEN
  jsonb_build_object('state','eligible','version',selected.current_version,'configuration',v.frozen->'configuration','validUntil',9223372036854775807::bigint)
  ELSE jsonb_build_object('state','excluded') END FROM (
   SELECT p.* FROM rss_da.policies p WHERE p.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
    AND (p.definition#>>'{target,kind}'='tenant_default' OR
      (p.definition#>>'{target,kind}'='device' AND (p.definition#>>'{target,device}')::uuid=p_device))
   ORDER BY (p.definition#>>'{target,kind}'='device') DESC LIMIT 1
  ) selected JOIN rss_da.policy_versions v ON(v.tenant_id,v.id)=(selected.tenant_id,selected.current_version)
  WHERE v.action_kind='device_access'),jsonb_build_object('state','excluded'))
$$;
REVOKE ALL ON FUNCTION rss_da.access_policy(uuid,uuid,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION rss_da.access_policy(uuid,uuid,bigint) TO da_access,da_policy_runtime,da_command_runtime,da_identity_runtime;

CREATE FUNCTION rss_da.active_access_binding(p_binding uuid,p_generation bigint,p_as_of bigint) RETURNS jsonb
 LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE tenant uuid:=nullif(current_setting('rss.tenant_id',true),'')::uuid; binding jsonb; selection jsonb;
BEGIN
 SELECT b.document INTO binding FROM rss_da.bindings b
 WHERE b.tenant_id=tenant AND b.id=p_binding AND b.generation=p_generation
  AND rss_da.current_da_registration(b.device)=jsonb_build_object('device',b.device)
  AND rss_da.access_binding_ready(b.document)
  AND rss_da.binding_application_current(b.document,p_as_of);
 IF NOT FOUND THEN RETURN jsonb_build_object('state','excluded'); END IF;
 IF binding->>'tenant' IS DISTINCT FROM tenant::text OR binding->>'id' IS DISTINCT FROM p_binding::text THEN
  RAISE EXCEPTION 'invalid access binding identity' USING ERRCODE='23514';
 END IF;
 IF binding#>>'{configuration,enabled}' IS DISTINCT FROM 'true'
  OR rss_da.access_policy((binding->>'policy')::uuid,(binding->>'device')::uuid,p_as_of)->>'version' IS DISTINCT FROM binding->>'policyVersion' THEN
  RETURN jsonb_build_object('state','excluded');
 END IF;
 RETURN jsonb_build_object('state','eligible','binding',binding,'validUntil',9223372036854775807::bigint);
END $$;
REVOKE ALL ON FUNCTION rss_da.active_access_binding(uuid,bigint,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION rss_da.active_access_binding(uuid,bigint,bigint) TO da_access,da_inventory_runtime,da_scope_runtime,da_policy_runtime,da_telemetry_runtime,da_command_runtime,da_identity_runtime;
