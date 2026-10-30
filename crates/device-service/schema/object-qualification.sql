-- Current frozen-object qualification is shared by locked execution and read projections.
-- This function reads one supplied object; it never enumerates the tenant universe or takes locks.
CREATE FUNCTION mdm_devices.object_current(p_input jsonb,p_channel text) RETURNS jsonb
 LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE tenant uuid:=nullif(current_setting('rss.tenant_id',true),'')::uuid;
 live jsonb; selected jsonb;
BEGIN
 IF p_channel NOT IN('agent','mdm') OR p_input->>'verified' IS DISTINCT FROM 'true' THEN RETURN NULL; END IF;
 IF jsonb_typeof(p_input->'members') IS DISTINCT FROM 'array' THEN
  RAISE EXCEPTION 'invalid device input' USING ERRCODE='23514';
 END IF;
 IF p_input#>>'{object,kind}'='association' THEN
  -- Interpret only relevant facts outside the published input. An unrelated
  -- endpoint or pending owner task is not an execution barrier.
  IF EXISTS(SELECT FROM mdm.asset_changes e WHERE e.tenant_id=tenant
   AND NOT mdm.asset_visible((SELECT from_cut FROM mdm_devices.checkpoints WHERE tenant_id=tenant),e.revision)
   AND (e.kind IN('device','registration','source','credential') OR e.fields && ARRAY['device.serial_number','device.hardware_uuid','device.manufacturer']::text[])
   AND (e.identity->>'device' IN(SELECT m->>'device' FROM jsonb_array_elements(p_input->'members') m)
    OR e.identity->>'registration' IN(SELECT m->>'registrationId' FROM jsonb_array_elements(p_input->'members') m)
    OR (e.identity->>'device' IS NULL AND e.identity->>'registration' IS NULL))
  ) THEN RETURN NULL; END IF;
  -- A new competing endpoint is visible immediately, before Device's key fanout.
  IF EXISTS(SELECT FROM mdm_devices.associations a CROSS JOIN LATERAL jsonb_each(a.hardware) h
   CROSS JOIN LATERAL (
    SELECT 'serial'::text AS kind,jsonb_array_elements_text(h.value->'serial') AS value
    UNION ALL SELECT 'uuid',jsonb_array_elements_text(h.value->'uuid')
   ) k JOIN mdm_assets.hardware_keys p ON p.tenant_id=a.tenant_id AND p.kind=k.kind AND p.value=k.value
   WHERE a.tenant_id=tenant AND a.id=(p_input#>>'{object,id}')::uuid
    AND p.device NOT IN(SELECT m->>'device' FROM jsonb_array_elements(p_input->'members') m)
  ) THEN RETURN NULL; END IF;
  SELECT v.input INTO live FROM mdm_devices.object_heads h JOIN mdm_devices.object_versions v USING(tenant_id,object,revision)
  JOIN mdm_devices.associations a ON(a.tenant_id,a.id)=(v.tenant_id,(p_input#>>'{object,id}')::uuid)
  WHERE h.tenant_id=tenant AND h.object='association:'||(p_input#>>'{object,id}')
    AND a.version=(p_input->>'associationVersion')::bigint AND a.state='confirmed';
  IF NOT FOUND OR live->>'verified' IS DISTINCT FROM 'true'
   OR live->'associationVersion' IS DISTINCT FROM p_input->'associationVersion'
   OR live->'members' IS DISTINCT FROM p_input->'members' THEN RETURN NULL; END IF;
  IF EXISTS(SELECT FROM jsonb_array_elements(p_input->'members') member WHERE NOT EXISTS(
   SELECT FROM mdm_devices.members m WHERE m.tenant_id=tenant AND m.association_id=(p_input#>>'{object,id}')::uuid
    AND NOT m.released AND m.device=member->>'device' AND m.channel=member->>'channel'
    AND m.registration_id::text=member->>'registrationId' AND m.generation=(member->>'generation')::bigint
  )) THEN RETURN NULL; END IF;
 ELSIF p_input#>>'{object,kind}' IS DISTINCT FROM 'endpoint' THEN
  RAISE EXCEPTION 'invalid device object' USING ERRCODE='23514';
 END IF;
 IF EXISTS(SELECT FROM jsonb_array_elements(p_input->'members') m WHERE NOT EXISTS(
  SELECT FROM mdm_access.registrations r WHERE r.tenant_id=tenant AND r.device=m->>'device'
   AND r.channel=m->>'channel' AND r.id::text=m->>'registrationId' AND r.generation=(m->>'generation')::bigint
   AND r.purpose='primary' AND r.state='active' AND EXISTS(
    SELECT FROM mdm_access.credentials k WHERE (k.tenant_id,k.registration)=(r.tenant_id,r.id) AND k.state='active')
 )) THEN RETURN NULL; END IF;
 IF (SELECT count(*) FROM jsonb_array_elements(p_input->'members') m WHERE m->>'channel'=p_channel)>1 THEN
  RAISE EXCEPTION 'ambiguous execution channel' USING ERRCODE='23514';
 END IF;
 SELECT m INTO selected FROM jsonb_array_elements(p_input->'members') m WHERE m->>'channel'=p_channel;
 RETURN selected;
END $$;
REVOKE ALL ON FUNCTION mdm_devices.object_current(jsonb,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mdm_devices.object_current(jsonb,text) TO mdm_access,mdm_inventory_runtime,mdm_scope_runtime,mdm_policy_runtime,mdm_telemetry_runtime,mdm_command_runtime;
