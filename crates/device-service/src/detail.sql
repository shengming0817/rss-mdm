, selected_objects AS MATERIALIZED (
 SELECT 'endpoint:'||d.id AS object_key,ARRAY[d.id] AS devices FROM mdm_access.directory_endpoints d
 WHERE $5::jsonb->>'kind'='endpoint' AND d.tenant_id=$1::uuid AND d.id=$5::jsonb->>'id' AND ($2::text[] IS NULL OR d.id=ANY($2))
 UNION ALL
 SELECT 'association:'||a.id::text,array_agg(m.device ORDER BY m.channel)
 FROM mdm_devices.associations a JOIN mdm_devices.members m ON(m.tenant_id,m.association_id)=(a.tenant_id,a.id)
 WHERE $5::jsonb->>'kind'='association' AND a.tenant_id=$1::uuid AND a.id::text=$5::jsonb->>'id' AND a.state<>'revoked'
 GROUP BY a.id HAVING count(*)=2 AND bool_and($2::text[] IS NULL OR m.device=ANY($2))
), read_input AS (SELECT NULL::text[] AS fields,false AS more,NULL::jsonb AS budget,$6::text AS instance)
