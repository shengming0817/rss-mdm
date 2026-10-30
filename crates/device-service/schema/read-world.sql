-- A bounded raw product snapshot. Personnel projection remains inside Identity's read scope.
CREATE FUNCTION mdm_devices.read_world(p_associations uuid[],p_devices text[],p_fields text[])
RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
WITH context AS (
 SELECT nullif(current_setting('rss.tenant_id',true),'')::uuid AS tenant
 WHERE cardinality(p_devices)<=202 AND cardinality(p_associations)<=101
), fields AS (
 SELECT field FROM (
  SELECT DISTINCT ON(field) field,definition FROM mdm.field_versions WHERE tenant_id=(SELECT tenant FROM context)
  ORDER BY field,version DESC
 ) c WHERE definition IS NOT NULL AND definition->>'sensitivity'<>'secret'
 AND (p_fields IS NULL OR field=ANY(p_fields) OR field IN('device.serial_number','device.hardware_uuid','device.manufacturer')) LIMIT 1025
), associations AS (
 SELECT jsonb_build_object('id',a.id,'version',a.version,'state',a.state,'evidence',a.evidence,'hardware',a.hardware,
  'confirmedBy',a.confirmed_by,'confirmedAt',a.confirmed_at,'revokedBy',a.revoked_by,'revokedAt',a.revoked_at,'reason',a.reason,
  'members',(SELECT jsonb_agg(jsonb_build_object('device',m.device,'channel',m.channel,'registrationId',m.registration_id,'generation',m.generation) ORDER BY m.channel) FROM mdm_devices.members m WHERE (m.tenant_id,m.association_id)=(a.tenant_id,a.id))) AS document
 FROM mdm_devices.associations a WHERE a.tenant_id=(SELECT tenant FROM context) AND a.id=ANY(p_associations)
), primary_registrations AS (
 SELECT jsonb_build_object('device',r.device,'channel',r.channel,'registrationId',r.id,'generation',r.generation) AS document
 FROM mdm_access.registrations r WHERE r.tenant_id=(SELECT tenant FROM context) AND r.device=ANY(p_devices) AND r.purpose='primary' AND r.state='active'
 AND EXISTS(SELECT FROM mdm_access.credentials k WHERE(k.tenant_id,k.registration)=(r.tenant_id,r.id) AND k.state='active')
), keys AS (
 SELECT DISTINCT kind,value FROM mdm_assets.hardware_keys WHERE tenant_id=(SELECT tenant FROM context) AND device=ANY(p_devices)
), peers AS (
 SELECT q.kind,q.value,p.device FROM keys q CROSS JOIN LATERAL (
  SELECT DISTINCT device FROM mdm_assets.hardware_keys h WHERE h.tenant_id=(SELECT tenant FROM context) AND h.kind=q.kind AND h.value=q.value ORDER BY device LIMIT 3
 ) p
)
SELECT CASE WHEN EXISTS(SELECT FROM context) THEN jsonb_build_object(
 'associations',coalesce((SELECT jsonb_agg(document) FROM associations),'[]'::jsonb),
 'primary',coalesce((SELECT jsonb_agg(document) FROM primary_registrations),'[]'::jsonb),
 'peers',coalesce((SELECT jsonb_agg(to_jsonb(p)) FROM peers p),'[]'::jsonb),
 'endpoints',coalesce((SELECT jsonb_agg(e.summary||jsonb_build_object('assetState',coalesce(s.state,'active')) ORDER BY e.id COLLATE "C")
  FROM mdm_access.directory_endpoints e LEFT JOIN mdm_devices.asset_states s ON(s.tenant_id,s.device)=(e.tenant_id,e.id)
  WHERE e.tenant_id=(SELECT tenant FROM context) AND e.id=ANY(p_devices)),'[]'::jsonb),
 'assets',mdm_assets.read_snapshot(p_devices,ARRAY(SELECT field FROM fields),NULL::jsonb,'{"kind":"device"}'::jsonb)) ELSE jsonb_build_object('assets',jsonb_build_object('ok',false)) END
$$;
REVOKE ALL ON FUNCTION mdm_devices.read_world(uuid[],text[],text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mdm_devices.read_world(uuid[],text[],text[]) TO mdm_access,mdm_identity_runtime;
