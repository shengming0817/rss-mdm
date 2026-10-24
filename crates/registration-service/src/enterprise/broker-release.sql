-- Only this joined snapshot authorizes a secret release/current RP session.
SELECT CASE WHEN $7::uuid IS NOT NULL THEN x.sealed END AS sealed,x.document,x.expires_at
FROM mdm_enterprise.brokers x
JOIN mdm_enterprise.relying_parties rp ON rp.tenant_id=x.tenant_id AND rp.id=$2
JOIN mdm_enterprise.subjects sub ON sub.tenant_id=x.tenant_id
 AND sub.provider=$4 AND (sub.document#>>'{person,instance}')::uuid=(x.document#>>'{binding,person,instance}')::uuid
 AND sub.principal=(x.document#>>'{binding,person,principal}')::uuid
JOIN identity_session_references s ON s.tenant_id=x.tenant_id
 AND s.instance_id::text=x.document#>>'{reference,instance}'
 AND s.principal_id::text=x.document#>>'{reference,principal}'
 AND s.session_id::text=x.document#>>'{reference,session}'
 AND s.credential_kind=x.document#>>'{reference,credentialKind}'
JOIN mdm_agent.bindings native ON native.tenant_id=x.tenant_id AND native.registration=(x.document#>>'{binding,registration}')::uuid
CROSS JOIN LATERAL (SELECT floor(extract(epoch FROM statement_timestamp()))::bigint AS now) clock
CROSS JOIN LATERAL (SELECT mdm_commands.active_access_binding((x.document#>>'{binding,id}')::uuid,(x.document#>>'{binding,generation}')::bigint,clock.now) AS value) active
WHERE x.tenant_id=$1 AND x.id=$5 AND x.phase='consumed' AND x.document->>'phase'='consumed'
 AND rp.document=x.document->'relyingParty' AND rp.document->>'enabled'='true'
 AND rp.document->>'targetFingerprint'=$3
 AND sub.document=x.document->'subject' AND sub.document->>'enabled'='true'
 AND active.value->>'state'='eligible' AND active.value->'binding'=x.document->'binding'
 AND NOT EXISTS(SELECT FROM mdm_access.device_access_subject_denials d WHERE d.tenant_id=x.tenant_id
  AND d.instance=s.instance_id AND d.principal=s.principal_id AND d.denied)
 AND s.requires_platform_check AND s.platform_binding_id=x.document#>>'{binding,id}'
 AND s.platform_binding_epoch=x.document#>>'{binding,generation}'
 AND native.capabilities::jsonb ? 'device_access.v1'
 AND native.execution_context#>>'{interactiveUser,sessionId}'=x.document#>>'{localSession,sessionId}'
 AND CASE native.platform WHEN 'windows' THEN
  native.execution_context#>'{interactiveUser,generatedUid}'='null'::jsonb
  AND native.execution_context#>>'{interactiveUser,identity}'=x.document#>>'{localSession,account,sid}'
  AND native.execution_context#>'{interactiveUser,windowsAuthority}'=x.document#>'{localSession,account,authority}'
  AND EXISTS(SELECT FROM mdm_enterprise.windows_sources w WHERE w.tenant_id=x.tenant_id
   AND w.id::text=s.platform_source_id AND w.version::text=s.platform_source_version
   AND w.binding::text=s.platform_binding_id AND w.document->>'bindingGeneration'=s.platform_binding_epoch
   AND w.document->>'factorGeneration'=x.document#>>'{binding,factorGeneration}'
   AND w.document->>'bindingRevision'=x.document#>>'{binding,revision}'
   AND w.document->'person'=x.document#>'{binding,person}')
 WHEN 'macos' THEN
  native.execution_context#>>'{interactiveUser,generatedUid}'=x.document#>>'{localSession,account,generatedUid}'
  AND EXISTS(SELECT FROM mdm_apple.platform_session_qualifications(s.platform_source_id::uuid,$6,clock.now) q
   WHERE (q.tenant_id,q.instance_id,q.principal_id,q.binding_id::text,q.binding_generation::text,q.source_id::text,q.source_version::text)
    =(s.tenant_id,s.instance_id,s.principal_id,s.platform_binding_id,s.platform_binding_epoch,s.platform_source_id,s.platform_source_version)
   AND q.valid_until>clock.now)
 ELSE false END
 AND ($7::uuid IS NULL OR (x.document->>'consumeOperation'=$7::text AND x.expires_at>clock.now AND x.sealed IS NOT NULL
  AND x.document->'continuationDigest'=$8::jsonb))
