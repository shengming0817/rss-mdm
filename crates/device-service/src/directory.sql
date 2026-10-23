visible AS MATERIALIZED (
 SELECT * FROM mdm_access.directory_endpoints WHERE tenant_id=$1::uuid AND ($2::text[] IS NULL OR id=ANY($2))
), paired AS (
 SELECT a.id,array_agg(m.device ORDER BY m.channel) AS devices
 FROM mdm_devices.associations a JOIN mdm_devices.members m ON(m.tenant_id,m.association_id)=(a.tenant_id,a.id)
 JOIN visible v ON v.id=m.device
 WHERE a.tenant_id=$1::uuid AND a.state<>'revoked' AND NOT m.released
 GROUP BY a.id HAVING count(*)=2
), members AS (
 SELECT v.*,coalesce('association:'||p.id::text,'endpoint:'||v.id) AS object_key,
 coalesce(a.state,'active') AS asset_state,u.registration_user,u.session_reference,u.registration_valid,
 u.valid_until,($3::text[] IS NULL OR v.id=ANY($3)) AS sensitive,
 ($4::text[] IS NULL OR v.id=ANY($4)) AS ownership
 FROM visible v LEFT JOIN paired p ON v.id=ANY(p.devices)
 LEFT JOIN mdm_devices.asset_states a ON a.tenant_id=$1::uuid AND a.device=v.id
 LEFT JOIN mdm_access.directory_users u ON u.tenant_id=$1::uuid AND u.device=v.id
), matched AS (
 SELECT m.object_key,m.id,m.valid_until,
 m.asset_state=$10::text
 AND ($7::text IS NULL OR m.status=$7)
 AND ($8::text IS NULL OR EXISTS(SELECT FROM jsonb_array_elements((m.summary->'channels')||(m.summary->'enrollments')) source WHERE source->>'source'=$8))
 AND ($9::text IS NULL OR EXISTS(SELECT FROM jsonb_array_elements((m.summary->'channels')||(m.summary->'enrollments')) source WHERE split_part(source->>'source','.',1)=$9))
 AND ($6::text IS NULL OR EXISTS(SELECT FROM jsonb_array_elements(m.summary->'channels') source WHERE source->>'platform'=$6)
  OR EXISTS(SELECT FROM jsonb_array_elements(m.summary->'enrollments') source WHERE source->>'status'='pending' AND source->>'platform'=$6))
 AND ($5::text IS NULL OR
  EXISTS(
   SELECT FROM (
    (SELECT field,search_values FROM mdm_assets.directory_fields f
     WHERE f.tenant_id=$1::uuid AND f.device=m.id AND (m.sensitive OR f.sensitivity='standard')
      AND f.field<>'device.serial_number' AND (f.state='conflict' OR f.state='known' AND btrim(f.value)<>'')
     ORDER BY CASE f.field WHEN 'device.name' THEN 0 WHEN 'device.network.apple.host_name' THEN 1 ELSE 2 END LIMIT 1)
    UNION ALL
    SELECT field,search_values FROM mdm_assets.directory_fields f
     WHERE f.tenant_id=$1::uuid AND f.device=m.id AND (m.sensitive OR f.sensitivity='standard') AND f.field='device.serial_number'
   ) fields CROSS JOIN LATERAL unnest(fields.search_values) term WHERE strpos(lower(term),$5)>0
  ) OR EXISTS(
   SELECT FROM (
    SELECT (m.registration_user->>'principalId')::uuid AS principal
    WHERE m.ownership AND m.registration_user->>'tenantId'=$1::text AND m.registration_user->>'instanceId'=$14::text
    UNION ALL
    SELECT s.principal_id FROM platform_sessions s
    WHERE m.sensitive AND m.registration_valid
     AND s.instance_id=(m.session_reference->>'instance')::uuid AND s.tenant_id=(m.session_reference->>'tenant')::uuid
     AND s.principal_id=(m.session_reference->>'principal')::uuid AND s.session_id=(m.session_reference->>'session')::uuid
     AND s.credential_kind=m.session_reference->>'credentialKind'
   ) related WHERE strpos(related.principal::text,$5)>0 OR m.sensitive AND $15::boolean AND EXISTS(
    SELECT FROM people p WHERE p.principal_id=related.principal AND p.active
     AND (strpos(lower(p.login),$5)>0 OR p.status='available' AND strpos(lower(p.display_name),$5)>0)
   )
  )
 ) AS matches
 FROM members m
), objects AS (
 SELECT object_key,array_agg(id ORDER BY id COLLATE "C") AS devices FROM matched
 GROUP BY object_key HAVING bool_or(matches)
), page AS (
 SELECT * FROM objects WHERE $11::text IS NULL OR CASE WHEN $12 THEN object_key COLLATE "C"<$11 COLLATE "C" ELSE object_key COLLATE "C">$11 COLLATE "C" END
 ORDER BY CASE WHEN NOT $12 THEN object_key END COLLATE "C",CASE WHEN $12 THEN object_key END COLLATE "C" DESC LIMIT $13
)
SELECT jsonb_build_object(
 'asOf',floor(extract(epoch FROM statement_timestamp()))::bigint,
 'objects',coalesce((SELECT jsonb_agg(jsonb_build_object('key',object_key,'devices',devices)
  ORDER BY CASE WHEN NOT $12 THEN object_key END COLLATE "C",CASE WHEN $12 THEN object_key END COLLATE "C" DESC) FROM page),'[]'::jsonb),
 'statistics',(SELECT jsonb_build_object('deviceViewCount',count(*),'endpointCount',coalesce(sum(cardinality(devices)),0)) FROM objects),
 'validUntil',least((SELECT min(valid_until) FROM members),
  (SELECT min(platform_valid_until) FROM platform_sessions),
  (SELECT min((e->>'expiresAt')::bigint) FROM visible v CROSS JOIN LATERAL jsonb_array_elements(v.summary->'enrollments') e WHERE e->>'status'='pending')),
 'queryRevision',coalesce((SELECT query_revision FROM mdm_devices.checkpoints WHERE tenant_id=$1::uuid),0),
 'watermark',coalesce((SELECT revision FROM mdm.asset_clock WHERE tenant_id=$1::uuid),0),
 'relationRevision',coalesce((SELECT relation_revision FROM mdm_devices.checkpoints WHERE tenant_id=$1::uuid),0)
) AS value
