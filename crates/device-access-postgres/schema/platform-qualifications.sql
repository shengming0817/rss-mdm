-- Verified deployment payloads are written only by the DA verifier. Every read rechecks
-- current authority fingerprints, exact targets/configuration and server-bounded validity.
CREATE FUNCTION rss_da.deployment_valid_until(p_registration uuid,p_generation bigint,config jsonb,p_profile uuid,as_of bigint) RETURNS bigint
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT CASE WHEN count(*)>0 AND bool_and(coalesce(
  e.fingerprint=config#>>ARRAY['authorities',e.authority::text]
  AND e.document->>'installation'=(SELECT instance_id::text FROM rss_da.installation_binding WHERE singleton)
  AND e.document->>'tenant'=e.tenant_id::text AND e.document->>'registration'=e.registration::text
  AND (e.document->>'generation')::bigint=e.generation AND (e.document->>'sequence')::bigint=e.sequence
  AND e.document->>'revoked'='false' AND e.document#>>'{deployment,platform}'='macos'
  AND rss_da.access_policy((e.document->>'policy')::uuid,e.document->>'device',as_of)->>'version'=e.document->>'policyVersion' AND e.document#>>'{deployment,applicationInstalled}'='true' AND e.document#>>'{deployment,profileMatched}'='true'
  AND e.document#>>'{deployment,configuration}'=config->>'configuration'
  AND e.document#>>'{deployment,applicationId}'=config->>'applicationId' AND e.document#>>'{deployment,applicationVersion}'=config->>'applicationVersion'
  AND e.document#>>'{deployment,profileIdentifier}'=config->>'profileIdentifier' AND e.document#>>'{deployment,profileUuid}'=p_profile::text
  AND e.document#>>'{deployment,architecture}'='aarch64' AND e.document#>'{deployment,osVersion}'>='[26,4,0,0]'::jsonb
  AND e.document#>>'{deployment,userHelper}'='true' AND e.document#>>'{deployment,systemBroker}'='true'
  AND (e.document->>'issuedAt')::bigint<=e.received_at AND e.received_at<=as_of
  AND (e.document->>'expiresAt')::bigint>as_of
  AND (e.document->>'expiresAt')::bigint-(e.document->>'issuedAt')::bigint BETWEEN 1 AND 86400
  AND rss_da.current_da_registration(e.document->>'device')=jsonb_build_object('device',e.document->>'device','registrationId',e.registration,'generation',e.generation)
 ,false)) THEN min((e.document->>'expiresAt')::bigint) END
 FROM rss_da.deployment_evidence e WHERE e.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND e.registration=p_registration AND e.generation=p_generation
$$;
REVOKE ALL ON FUNCTION rss_da.deployment_valid_until(uuid,bigint,jsonb,uuid,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION rss_da.deployment_valid_until(uuid,bigint,jsonb,uuid,bigint) TO da_access,da_identity_runtime;

CREATE FUNCTION rss_da.platform_session_qualifications(p_source uuid,config jsonb,as_of bigint)
RETURNS TABLE(tenant_id uuid,instance_id uuid,principal_id uuid,binding_id uuid,binding_generation bigint,source_id uuid,source_version bigint,valid_until bigint)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT u.tenant_id,(b.value#>>'{binding,person,instance}')::uuid,
  (b.value#>>'{binding,person,principal}')::uuid,u.binding,(u.document->>'bindingGeneration')::bigint,
  u.id,u.version,least(a.until,(b.value->>'validUntil')::bigint)
 FROM rss_da.psso_sources u
 JOIN rss_da.psso_sources d ON(d.tenant_id,d.id)=(u.tenant_id,u.parent)
 CROSS JOIN LATERAL (SELECT u.document->'object' AS member) o
 CROSS JOIN LATERAL (SELECT rss_da.active_access_binding(u.binding,(u.document->>'bindingGeneration')::bigint,as_of) AS value) b
 CROSS JOIN LATERAL (SELECT rss_da.deployment_valid_until(u.registration,(o.member->>'generation')::bigint,config,(u.document->>'profileUuid')::uuid,as_of) AS until) a
 WHERE config IS NOT NULL AND config<>'null'::jsonb
  AND u.id=p_source
  AND u.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
  AND u.kind='user' AND NOT u.revoked AND u.document->>'id'=u.id::text
  AND u.document->>'kind'='user' AND u.document->>'configuration'=config->>'configuration'
  AND d.kind='device' AND NOT d.revoked AND d.document->>'id'=d.id::text AND d.document->>'kind'='device'
  AND d.version=(u.document->>'parentVersion')::bigint AND d.registration=u.registration
  AND d.document->'object'=u.document->'object' AND d.document->>'configuration'=u.document->>'configuration'
  AND o.member->>'registrationId'=u.registration::text
  AND rss_da.current_da_registration(o.member->>'device') IS NOT NULL
  AND a.until IS NOT NULL AND b.value->>'state'='eligible'
  AND u.document->'loginConfiguration'=b.value#>'{binding,configuration,mac}'
  AND (u.document#>>'{loginConfiguration,authentication}'<>'password' OR EXISTS(
   SELECT FROM rss_da.subjects mapping WHERE mapping.tenant_id=u.tenant_id
    AND mapping.provider=(u.document#>>'{passwordIdentity,provider}')::uuid
    AND (mapping.document#>>'{person,instance}')::uuid=(b.value#>>'{binding,person,instance}')::uuid
    AND mapping.principal=(b.value#>>'{binding,person,principal}')::uuid
    AND mapping.document=u.document->'passwordIdentity' AND mapping.document->>'enabled'='true'
    AND EXISTS(SELECT FROM rss_da.psso_password_providers provider WHERE provider.tenant_id=u.tenant_id
      AND provider.id=mapping.provider AND provider.revision::text=u.document->>'passwordProviderRevision'
      AND provider.fingerprint=u.document->>'passwordProviderFingerprint')))
  AND d.document->'loginConfiguration'=u.document->'loginConfiguration'
  AND d.document->'profileUuid'=u.document->'profileUuid'
  AND o.member->>'registrationId'=b.value#>>'{binding,registration}'
  AND o.member->>'generation'=b.value#>>'{binding,registrationGeneration}' AND o.member->>'device'=b.value#>>'{binding,device}'
  AND u.document->'subject'=jsonb_build_object('instance',b.value#>'{binding,person,instance}',
    'account',jsonb_build_object('tenant',u.tenant_id,'principal',b.value#>'{binding,person,principal}'),
    'bindingId',u.binding,'bindingEpoch',(u.document->>'bindingGeneration')::bigint,
    'sourceId',u.id,'sourceVersion',u.version,'externalIdentity',NULL)
$$;
REVOKE ALL ON FUNCTION rss_da.platform_session_qualifications(uuid,jsonb,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION rss_da.platform_session_qualifications(uuid,jsonb,bigint) TO da_access,da_identity_runtime;

-- Correlate a task observation without a readiness cycle. The caller holds the asset fence.
-- ref: Apple AuthenticationServices/ASAuthorizationProviderExtensionLoginManager.h.
CREATE FUNCTION rss_da.platform_registration_matches(p_source uuid,p_version bigint,p_binding jsonb)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT EXISTS (
  SELECT FROM rss_da.psso_sources u
  JOIN rss_da.psso_sources d ON(d.tenant_id,d.id)=(u.tenant_id,u.parent)
  CROSS JOIN LATERAL (SELECT u.document->'object' AS member) o
  WHERE u.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
   AND u.tenant_id::text=p_binding->>'tenant'
   AND u.id=p_source AND u.version=p_version AND u.kind='user' AND NOT u.revoked
   AND u.binding::text=p_binding->>'id'
   AND u.document->>'bindingGeneration'=p_binding->>'generation'
   AND u.document->'loginConfiguration'=p_binding#>'{configuration,mac}'
   AND d.kind='device' AND NOT d.revoked
   AND d.version=(u.document->>'parentVersion')::bigint
   AND d.registration=u.registration AND d.document->'object'=u.document->'object'
   AND d.document->>'configuration'=u.document->>'configuration'
   AND d.document->'loginConfiguration'=u.document->'loginConfiguration'
   AND d.document->'profileUuid'=u.document->'profileUuid'
   AND o.member->>'registrationId'=u.registration::text
   AND rss_da.current_da_registration(o.member->>'device')=o.member
   AND o.member->>'registrationId'=p_binding->>'registration'
   AND o.member->>'generation'=p_binding->>'registrationGeneration' AND o.member->>'device'=p_binding->>'device'
   AND u.document#>>'{subject,account,principal}'=p_binding#>>'{person,principal}'
   AND u.document#>>'{subject,instance}'=p_binding#>>'{person,instance}'
 )
$$;
REVOKE ALL ON FUNCTION rss_da.platform_registration_matches(uuid,bigint,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION rss_da.platform_registration_matches(uuid,bigint,jsonb) TO da_command_runtime;
