-- Read-only native qualification; caller authentication/locks remain with their owners.
CREATE FUNCTION mdm_apple.application_valid_until(registration uuid,config jsonb,as_of bigint)
RETURNS bigint LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 WITH facts AS MATERIALIZED (
  SELECT DISTINCT ON(i.scope,i.field_scope) i.*
  FROM mdm.inventory i JOIN mdm_access.report_sources s
   ON (s.tenant_id,s.registration::text,s.source,s.epoch::text)=(i.tenant_id,i.registration,i.source,i.epoch)
  JOIN mdm_access.registrations r ON(r.tenant_id,r.id)=(s.tenant_id,s.registration)
  WHERE i.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
   AND s.registration=$1 AND s.enabled AND r.state='active' AND s.source='mdm.apple'
   AND i.journal='mdm.observation.v1' AND i.generation='inventory-projection-v1'
   AND i.field='device.software.apple.installed_applications'
  ORDER BY i.scope,i.field_scope,i.collection_sequence DESC LIMIT 129
 ), qualified AS (
  SELECT f.received_at,f.state,v.version,
   (SELECT count(*)=1 AND bool_and(item#>'{value,version}' IS NOT DISTINCT FROM jsonb_build_object('kind','string','value',config->>'applicationVersion')
      AND item#>'{value,installing}' IS DISTINCT FROM '{"kind":"boolean","value":true}'::jsonb)
    FROM mdm.array_items a CROSS JOIN LATERAL (SELECT convert_from(a.payload,'UTF8')::jsonb AS item) p
    WHERE (a.tenant_id,a.version)=(f.tenant_id,f.value_version)
     AND item->>'kind'='object' AND item#>'{value,id}'=jsonb_build_object('kind','string','value',config->>'applicationId')) AS matches
  FROM facts f LEFT JOIN mdm.array_versions v ON(v.tenant_id,v.version,v.field)=(f.tenant_id,f.value_version,f.field)
  WHERE (SELECT count(*) FROM facts)<=128 AND f.field_scope::jsonb='{"kind":"device"}'::jsonb
 )
 SELECT CASE WHEN count(*)>0 AND (SELECT count(*) FROM facts)<=128
  AND bool_and((state='known' AND version IS NOT NULL AND matches AND received_at BETWEEN as_of-86400 AND as_of) IS TRUE)
  THEN min(received_at)+86401 END FROM qualified
$$;
REVOKE ALL ON FUNCTION mdm_apple.application_valid_until(uuid,jsonb,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mdm_apple.application_valid_until(uuid,jsonb,bigint) TO mdm_access,mdm_command_runtime,mdm_identity_runtime;

CREATE FUNCTION mdm_apple.platform_session_qualifications(p_source uuid,config jsonb,as_of bigint)
RETURNS TABLE(tenant_id uuid,instance_id uuid,principal_id uuid,binding_id uuid,binding_generation bigint,source_id uuid,source_version bigint,valid_until bigint)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT u.tenant_id,(b.value#>>'{binding,person,instance}')::uuid,
  (b.value#>>'{binding,person,principal}')::uuid,u.binding,(u.document->>'bindingGeneration')::bigint,
  u.id,u.version,least(a.until,(b.value->>'validUntil')::bigint)
 FROM mdm_apple.psso_sources u
 JOIN mdm_apple.psso_sources d ON(d.tenant_id,d.id)=(u.tenant_id,u.parent)
 CROSS JOIN LATERAL (SELECT mdm_devices.object_current(u.document->'object','mdm') AS member) o
 CROSS JOIN LATERAL (SELECT mdm_commands.active_access_binding(u.binding,(u.document->>'bindingGeneration')::bigint,as_of) AS value) b
 CROSS JOIN LATERAL (SELECT mdm_apple.application_valid_until(u.registration,config,as_of) AS until) a
 WHERE config IS NOT NULL AND config<>'null'::jsonb
  AND u.id=p_source
  AND u.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
  AND u.kind='user' AND NOT u.revoked AND u.document->>'id'=u.id::text
  AND u.document->>'kind'='user' AND u.document->>'configuration'=config->>'configuration'
  AND d.kind='device' AND NOT d.revoked AND d.document->>'id'=d.id::text AND d.document->>'kind'='device'
  AND d.version=(u.document->>'parentVersion')::bigint AND d.registration=u.registration
  AND d.document->'object'=u.document->'object' AND d.document->>'configuration'=u.document->>'configuration'
  AND o.member->>'registrationId'=u.registration::text
  AND EXISTS(SELECT FROM mdm_apple.devices x WHERE(x.tenant_id,x.registration)=(u.tenant_id,u.registration) AND x.state='active')
  AND a.until IS NOT NULL AND b.value->>'state'='eligible'
  AND EXISTS(SELECT FROM jsonb_array_elements(u.document#>'{object,members}') m
   WHERE m->>'registrationId'=b.value#>>'{binding,registration}'
    AND m->>'generation'=b.value#>>'{binding,registrationGeneration}' AND m->>'device'=b.value#>>'{binding,device}')
  AND u.document->'subject'=jsonb_build_object('instance',b.value#>'{binding,person,instance}',
    'account',jsonb_build_object('tenant',u.tenant_id,'principal',b.value#>'{binding,person,principal}'),
    'bindingId',u.binding,'bindingEpoch',(u.document->>'bindingGeneration')::bigint,
    'sourceId',u.id,'sourceVersion',u.version,'externalIdentity',NULL)
  AND (SELECT count(*)=1 AND bool_and(q.verification='matched') FROM mdm_apple.profiles p
    JOIN mdm_apple.profile_qualifications q USING(tenant_id,operation)
    WHERE p.tenant_id=u.tenant_id AND p.registration=u.registration
     AND p.generation=(o.member->>'generation')::bigint AND p.user_key=''
     AND p.identifier=config->>'profileIdentifier' AND p.profile=(config->>'profileUuid')::uuid
     AND p.present AND p.retired_at IS NULL AND p.observed_at IS NOT NULL)
$$;
REVOKE ALL ON FUNCTION mdm_apple.platform_session_qualifications(uuid,jsonb,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mdm_apple.platform_session_qualifications(uuid,jsonb,bigint) TO mdm_access,mdm_identity_runtime;
