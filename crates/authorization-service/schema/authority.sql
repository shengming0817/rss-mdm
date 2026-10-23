-- Durable product authorization evidence. Authentication and authority locks remain with callers.
BEGIN;
CREATE FUNCTION mdm_access.operation_authority_valid_until(authority jsonb, requested text, as_of bigint)
RETURNS bigint LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 WITH context AS (
  SELECT authority->'actor' AS actor,authority->'basis' AS basis,authority->'scope' AS scope,
   CASE authority#>>'{actor,kind}' WHEN 'account' THEN authority#>>'{actor,user,tenantId}' ELSE authority#>>'{actor,tenant}' END AS tenant,
   CASE authority#>>'{actor,kind}' WHEN 'account' THEN authority#>>'{actor,user,instanceId}' ELSE authority#>>'{actor,instance}' END AS instance
 ), candidates AS (
  SELECT r.document->'grants' AS grants,r.document->'subject' AS subject,b.value->>'expires_at' AS expires_at,c.*
  FROM context c CROSS JOIN LATERAL jsonb_array_elements(c.basis->'rules') b
  JOIN mdm_access.authorization_rules r ON r.tenant_id=c.tenant::uuid AND r.instance=c.instance::uuid
   AND r.id=(b.value->>'id')::uuid AND r.revision=(b.value->>'revision')::bigint
  WHERE c.actor->>'kind'='account' AND c.basis->>'kind'='account'
   AND (b.value->>'expires_at' IS NULL OR (b.value->>'expires_at')::bigint>as_of)
   AND r.document IS NOT NULL
  UNION ALL
  SELECT k.metadata->'grants',NULL::jsonb,k.expires_at::text,c.* FROM context c
  JOIN mdm_access.api_keys k ON k.tenant_id=c.tenant::uuid AND k.instance=c.instance::uuid AND k.id=(c.actor->>'id')::uuid
   AND k.authority_revision=(c.basis->>'authority_revision')::bigint
  WHERE c.actor->>'kind'='api_key' AND c.basis->>'kind'='api_key'
   AND k.enabled AND NOT k.revoked AND (k.expires_at IS NULL OR k.expires_at>as_of AND to_timestamp(k.expires_at)>statement_timestamp())
   AND requested NOT IN('tenant_create','tenant_read','tenant_update','tenant_delete','tenant_administrator_create',
      'identity_accounts_manage','identity_providers_manage','authorization_read','authorization_write','user_group_read','user_group_write','department_read')
 )
 SELECT max(coalesce(c.expires_at::bigint,9223372036854775807))
  FROM candidates c WHERE authority->>'permission'=requested AND c.tenant=nullif(current_setting('rss.tenant_id',true),'')
  AND EXISTS(SELECT FROM jsonb_array_elements(c.grants) g WHERE g->>'operation'=requested AND
   CASE c.scope->>'kind'
    WHEN 'all_devices' THEN g->'scope'='{"kind":"all_devices"}'::jsonb
    WHEN 'tenant' THEN g->'scope'='{"kind":"tenant"}'::jsonb
    WHEN 'device' THEN g->'scope'='{"kind":"all_devices"}'::jsonb OR g->'scope'=c.scope
    ELSE false END)
  AND (c.actor->>'kind'='api_key' OR CASE c.subject->>'kind'
   WHEN 'user' THEN c.subject->'user'=c.actor->'user'
   WHEN 'idp_group' THEN c.expires_at IS NOT NULL
   WHEN 'department' THEN c.expires_at IS NOT NULL
   WHEN 'user_group' THEN EXISTS(SELECT FROM mdm_access.user_groups u
    WHERE u.tenant_id=c.tenant::uuid AND u.instance=c.instance::uuid AND u.id=(c.subject->>'id')::uuid
     AND (u.document->>'enabled')::boolean AND u.document->'members' @> jsonb_build_array(c.actor->'user'))
   ELSE false END)

$$;
REVOKE ALL ON FUNCTION mdm_access.operation_authority_valid_until(jsonb,text,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mdm_access.operation_authority_valid_until(jsonb,text,bigint)
 TO mdm_access,mdm_flow_runtime,mdm_command_runtime,mdm_software_driver,mdm_identity_runtime;
CREATE FUNCTION mdm_access.operation_authority_valid(authority jsonb,requested text,as_of bigint)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT mdm_access.operation_authority_valid_until(authority,requested,as_of) IS NOT NULL
$$;
REVOKE ALL ON FUNCTION mdm_access.operation_authority_valid(jsonb,text,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mdm_access.operation_authority_valid(jsonb,text,bigint)
 TO mdm_access,mdm_flow_runtime,mdm_command_runtime,mdm_software_driver,mdm_identity_runtime;
COMMIT;
