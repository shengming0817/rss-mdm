-- Live Policy/Scope qualification shared by credential verification and bounded display queries.
CREATE FUNCTION mdm_commands.access_policy(p_policy uuid,p_device text,p_as_of bigint) RETURNS jsonb
 LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE tenant uuid:=nullif(current_setting('rss.tenant_id',true),'')::uuid; policy record; admission jsonb; valid_until bigint;
BEGIN
 SELECT p.current_version,p.definition,v.frozen INTO policy FROM mdm_policy.policies p
 JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(p.tenant_id,p.current_version)
 WHERE p.tenant_id=tenant AND p.id=p_policy AND p.state='enabled' AND v.action_kind='device_access';
 IF NOT FOUND OR policy.frozen->>'kind' IS DISTINCT FROM 'device_access' THEN
  RETURN jsonb_build_object('state','excluded');
 END IF;
 valid_until=mdm_access.operation_authority_valid_until(policy.frozen->'grant','account_write',p_as_of);
 IF valid_until IS NULL THEN
  RETURN jsonb_build_object('state','excluded');
 END IF;
 admission=mdm_planning.channel_admission((policy.definition->>'scope')::uuid,'agent',p_device);
 IF admission->>'state' IS DISTINCT FROM 'eligible' THEN RETURN admission; END IF;
 RETURN jsonb_build_object('state','eligible','version',policy.current_version,
  'configuration',policy.frozen->'configuration','validUntil',valid_until);
END $$;
REVOKE ALL ON FUNCTION mdm_commands.access_policy(uuid,text,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mdm_commands.access_policy(uuid,text,bigint) TO mdm_access,mdm_flow_runtime,mdm_command_runtime;

CREATE FUNCTION mdm_commands.active_access_binding(p_binding uuid,p_generation bigint,p_as_of bigint) RETURNS jsonb
 LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE tenant uuid:=nullif(current_setting('rss.tenant_id',true),'')::uuid; binding jsonb; selection jsonb;
BEGIN
 SELECT b.document INTO binding FROM mdm_access.device_access_bindings b
 JOIN mdm_access.devices d ON(d.tenant_id,d.id)=(b.tenant_id,b.device) AND d.retirement IS NULL
 JOIN mdm_access.registrations r ON(r.tenant_id,r.id,r.device,r.generation)=(b.tenant_id,b.registration,b.device,b.registration_generation)
 WHERE b.tenant_id=tenant AND b.id=p_binding AND b.generation=p_generation
  AND r.channel='agent' AND r.purpose='primary' AND r.state='active'
  AND EXISTS(SELECT FROM mdm_access.credentials k WHERE (k.tenant_id,k.registration)=(r.tenant_id,r.id) AND k.state='active')
  AND mdm_access.access_binding_ready(b.document);
 IF NOT FOUND THEN RETURN jsonb_build_object('state','excluded'); END IF;
 IF binding->>'tenant' IS DISTINCT FROM tenant::text OR binding->>'id' IS DISTINCT FROM p_binding::text THEN
  RAISE EXCEPTION 'invalid access binding identity' USING ERRCODE='23514';
 END IF;
 selection=mdm_commands.access_policy((binding->>'policy')::uuid,binding->>'device',p_as_of);
 IF selection->>'state' IS DISTINCT FROM 'eligible' THEN RETURN selection; END IF;
 IF selection->>'version' IS DISTINCT FROM binding->>'policyVersion'
  OR selection#>>'{configuration,enabled}' IS DISTINCT FROM 'true' THEN
  RETURN jsonb_build_object('state','excluded');
 END IF;
 RETURN jsonb_build_object('state','eligible','binding',binding,'validUntil',selection->'validUntil');
END $$;
REVOKE ALL ON FUNCTION mdm_commands.active_access_binding(uuid,bigint,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mdm_commands.active_access_binding(uuid,bigint,bigint) TO mdm_access,mdm_flow_runtime,mdm_command_runtime;
