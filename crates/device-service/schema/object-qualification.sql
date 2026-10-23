-- Current frozen-object qualification is shared by locked execution and read projections.
-- This function reads one supplied object; it never enumerates the tenant universe or takes locks.
CREATE FUNCTION mdm_devices.object_current(p_input jsonb,p_channel text) RETURNS jsonb
 LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE tenant uuid:=nullif(current_setting('rss.tenant_id',true),'')::uuid;
 v_snapshot uuid; live jsonb; selected jsonb;
BEGIN
 IF p_channel NOT IN('agent','mdm') OR p_input->>'verified' IS DISTINCT FROM 'true' THEN RETURN NULL; END IF;
 IF jsonb_typeof(p_input->'members') IS DISTINCT FROM 'array' THEN
  RAISE EXCEPTION 'invalid device input' USING ERRCODE='23514';
 END IF;
 IF p_input#>>'{object,kind}'='association' THEN
  SELECT s.id INTO v_snapshot FROM mdm_devices.input_snapshots s JOIN mdm_devices.checkpoints k USING(tenant_id)
  WHERE s.tenant_id=tenant AND s.watermark>=k.identity_watermark AND s.relation_revision=k.relation_revision
   AND s.phase='sealed' ORDER BY s.watermark DESC LIMIT 1;
  IF NOT FOUND THEN RETURN NULL; END IF;
  SELECT o.input INTO live FROM mdm_devices.input_objects o
  WHERE o.tenant_id=tenant AND o.snapshot=v_snapshot AND o.object='association:'||(p_input#>>'{object,id}');
  IF NOT FOUND OR live->>'verified' IS DISTINCT FROM 'true'
   OR live->'associationVersion' IS DISTINCT FROM p_input->'associationVersion'
   OR live->'members' IS DISTINCT FROM p_input->'members' THEN RETURN NULL; END IF;
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
GRANT EXECUTE ON FUNCTION mdm_devices.object_current(jsonb,text) TO mdm_access,mdm_flow_runtime,mdm_command_runtime;
