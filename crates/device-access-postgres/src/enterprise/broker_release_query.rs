//! Static owner query composition keeps optional transport out of independent DA SQL.
/// Supply an owner-installed SELECT with tenant_id, installation, device, registration,
/// generation, platform, capabilities and execution_context columns. No request text is accepted.
#[macro_export]
macro_rules! broker_release_query {
    ($agent_sessions:expr) => { concat!("WITH da_agent_sessions AS (", $agent_sessions, ") ", r###"-- Only this joined snapshot authorizes a secret release/current RP session.
SELECT CASE WHEN $7::uuid IS NOT NULL THEN x.sealed END AS sealed,x.document,x.expires_at
FROM rss_da.brokers x
JOIN rss_da.relying_parties rp ON rp.tenant_id=x.tenant_id AND rp.id=$2
JOIN rss_da.subjects sub ON sub.tenant_id=x.tenant_id
 AND sub.provider=$4 AND (sub.document#>>'{person,instance}')::uuid=(x.document#>>'{binding,person,instance}')::uuid
 AND sub.principal=(x.document#>>'{binding,person,principal}')::uuid
JOIN identity_session_references s ON s.tenant_id=x.tenant_id
 AND s.instance_id::text=x.document#>>'{reference,instance}'
 AND s.principal_id::text=x.document#>>'{reference,principal}'
 AND s.session_id::text=x.document#>>'{reference,session}'
 AND s.credential_kind=x.document#>>'{reference,credentialKind}'
LEFT JOIN rss_da.agent_delivery delivery ON delivery.tenant_id=x.tenant_id AND delivery.da_registration=(x.document#>>'{binding,registration}')::uuid AND delivery.da_generation=(x.document#>>'{binding,registrationGeneration}')::bigint AND delivery.enabled
LEFT JOIN da_agent_sessions native ON (native.tenant_id,native.installation,native.device,native.registration,native.generation)=(delivery.tenant_id,delivery.agent_installation,delivery.agent_device,delivery.agent_registration,delivery.agent_generation)
CROSS JOIN LATERAL (SELECT floor(extract(epoch FROM statement_timestamp()))::bigint AS now) clock
CROSS JOIN LATERAL (SELECT rss_da.active_access_binding((x.document#>>'{binding,id}')::uuid,(x.document#>>'{binding,generation}')::bigint,clock.now) AS value) active
WHERE x.tenant_id=$1 AND x.id=$5 AND x.phase='consumed' AND x.document->>'phase'='consumed'
 AND rp.document=x.document->'relyingParty' AND rp.document->>'enabled'='true'
 AND rp.document->>'targetFingerprint'=$3
 AND sub.document=x.document->'subject' AND sub.document->>'enabled'='true'
 AND active.value->>'state'='eligible' AND active.value->'binding'=x.document->'binding'
 AND NOT EXISTS(SELECT FROM rss_da.subject_denials d WHERE d.tenant_id=x.tenant_id
  AND d.instance=s.instance_id AND d.principal=s.principal_id AND d.denied)
 AND s.requires_platform_check AND s.platform_binding_id=x.document#>>'{binding,id}'
 AND s.platform_binding_epoch=x.document#>>'{binding,generation}'
 AND CASE x.document#>>'{localSession,account,platform}' WHEN 'windows' THEN
  ((
  native.platform='windows' AND native.capabilities::jsonb ? 'device_access.v1'
  AND native.execution_context#>>'{interactiveUser,sessionId}'=x.document#>>'{localSession,sessionId}'
  AND native.execution_context#>'{interactiveUser,generatedUid}'='null'::jsonb
  AND native.execution_context#>>'{interactiveUser,identity}'=x.document#>>'{localSession,account,sid}'
  AND native.execution_context#>'{interactiveUser,windowsAuthority}'=x.document#>'{localSession,account,authority}'
  ) OR EXISTS(SELECT FROM rss_da.deployment_evidence e
    WHERE e.tenant_id=x.tenant_id AND e.registration=(x.document#>>'{binding,registration}')::uuid
      AND e.generation=(x.document#>>'{binding,registrationGeneration}')::bigint
    HAVING count(*)>0 AND bool_and(coalesce(
      e.fingerprint=$6#>>ARRAY['authorities',e.authority::text]
      AND e.document->>'installation'=(SELECT instance_id::text FROM rss_da.installation_binding WHERE singleton)
      AND e.document->>'tenant'=e.tenant_id::text AND e.document->>'registration'=e.registration::text
      AND e.document->>'device'=x.document#>>'{binding,device}'
      AND e.document->>'generation'=x.document#>>'{binding,registrationGeneration}'
      AND e.document->>'revoked'='false' AND e.document#>>'{deployment,platform}'='windows'
      AND e.document#>>'{deployment,interactiveBroker}'='true'
      AND e.document->'localSession'=x.document->'localSession'
      AND e.document->>'policy'=x.document#>>'{binding,policy}'
      AND e.document->>'policyVersion'=x.document#>>'{binding,policyVersion}'
      AND (e.document->>'issuedAt')::bigint<=e.received_at AND e.received_at<=clock.now
      AND (e.document->>'expiresAt')::bigint>clock.now
      AND (e.document->>'expiresAt')::bigint-(e.document->>'issuedAt')::bigint BETWEEN 1 AND 86400,false))))
  AND EXISTS(SELECT FROM rss_da.windows_sources w WHERE w.tenant_id=x.tenant_id
   AND w.id::text=s.platform_source_id AND w.version::text=s.platform_source_version
   AND w.binding::text=s.platform_binding_id AND w.document->>'bindingGeneration'=s.platform_binding_epoch
   AND w.document->>'factorGeneration'=x.document#>>'{binding,factorGeneration}'
   AND w.document->>'bindingRevision'=x.document#>>'{binding,revision}'
   AND w.document->'person'=x.document#>'{binding,person}')
 WHEN 'macos' THEN
  EXISTS(SELECT FROM rss_da.platform_session_qualifications(s.platform_source_id::uuid,$6,clock.now) q
   WHERE (q.tenant_id,q.instance_id,q.principal_id,q.binding_id::text,q.binding_generation::text,q.source_id::text,q.source_version::text)
    =(s.tenant_id,s.instance_id,s.principal_id,s.platform_binding_id,s.platform_binding_epoch,s.platform_source_id,s.platform_source_version)
   AND q.valid_until>clock.now)
  AND EXISTS(SELECT FROM rss_da.deployment_evidence e WHERE e.tenant_id=x.tenant_id
   AND e.registration=(x.document#>>'{binding,registration}')::uuid
   AND e.generation=(x.document#>>'{binding,registrationGeneration}')::bigint)
  AND NOT EXISTS(SELECT FROM rss_da.deployment_evidence e WHERE e.tenant_id=x.tenant_id
   AND e.registration=(x.document#>>'{binding,registration}')::uuid
   AND e.generation=(x.document#>>'{binding,registrationGeneration}')::bigint
   AND e.document->'localSession' IS DISTINCT FROM x.document->'localSession')
 ELSE false END
 AND ($7::uuid IS NULL OR (x.document->>'consumeOperation'=$7::text AND x.expires_at>clock.now AND x.sealed IS NOT NULL
  AND x.document->'continuationDigest'=$8::jsonb))
"###) };
}
