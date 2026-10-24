SELECT input->>'device' AS device,
 jsonb_build_object('tenantId',s.tenant_id,'instanceId',s.instance_id,'principalId',s.principal_id) AS "user"
FROM jsonb_array_elements($1::jsonb) input
JOIN platform_sessions s
 ON s.instance_id=(input->'reference'->>'instance')::uuid
 AND s.tenant_id=(input->'reference'->>'tenant')::uuid
 AND s.principal_id=(input->'reference'->>'principal')::uuid
 AND s.session_id=(input->'reference'->>'session')::uuid
 AND s.credential_kind=input->'reference'->>'credentialKind'
