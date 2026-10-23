-- Identity owns session validity; MDM qualifies the exact native binding generation.
platform_sessions AS NOT MATERIALIZED (
 SELECT s.*,qualified.valid_until AS platform_valid_until
 FROM identity_session_references s
 LEFT JOIN LATERAL (
  SELECT min(q.valid_until) AS valid_until
  FROM mdm_apple.platform_session_qualifications(
   CASE WHEN s.requires_platform_check THEN s.platform_source_id::uuid END,
   (SELECT config FROM platform_configuration),floor(extract(epoch FROM statement_timestamp()))::bigint) q
  WHERE (q.tenant_id,q.instance_id,q.principal_id,q.binding_id::text,q.binding_generation::text,q.source_id::text,q.source_version::text)
   =(s.tenant_id,s.instance_id,s.principal_id,s.platform_binding_id,s.platform_binding_epoch,s.platform_source_id,s.platform_source_version)
 ) qualified ON s.requires_platform_check
 WHERE NOT s.requires_platform_check OR qualified.valid_until IS NOT NULL
)
