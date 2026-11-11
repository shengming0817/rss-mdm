source_input AS MATERIALIZED (
 SELECT tenant_id FROM (
  SELECT tenant_id FROM mdm_access.directory_inputs
  UNION ALL SELECT tenant_id FROM mdm_assets.directory_inputs
  UNION ALL SELECT tenant_id FROM mdm_devices.members WHERE tenant_id=$1::uuid
  UNION ALL SELECT tenant_id FROM mdm_devices.associations WHERE tenant_id=$1::uuid
 ) raw WHERE tenant_id=$1::uuid LIMIT ($9::bigint*256+1)
), source_budget AS MATERIALIZED (
 SELECT count(*) AS rows,count(*)<=$9*256 AS ok FROM source_input
), candidate_input AS MATERIALIZED (
 SELECT tenant_id,id,status,channel,source,platform FROM mdm_access.directory_metadata WHERE (SELECT ok FROM source_budget) AND tenant_id=$1::uuid AND ($2::text[] IS NULL OR id=ANY($2)) LIMIT ($9::bigint+1)
), candidate_budget AS MATERIALIZED (
 SELECT count(*) AS rows,coalesce(sum(octet_length(id)+octet_length(status)+16),0)::bigint AS bytes,
 count(*)<=$9 AND coalesce(sum(octet_length(id)+octet_length(status)+16),0)<=$9*512 AS ok FROM candidate_input
), visible AS (
 SELECT c.* FROM candidate_input c WHERE (SELECT ok FROM candidate_budget)
), paired AS (
 SELECT a.id,array_agg(m.device ORDER BY m.channel) AS devices
 FROM mdm_devices.associations a JOIN mdm_devices.members m ON(m.tenant_id,m.association_id)=(a.tenant_id,a.id)
 JOIN visible v ON v.id=m.device
 WHERE a.tenant_id=$1::uuid AND a.state<>'revoked' AND NOT m.released
 GROUP BY a.id HAVING count(*)=2
), members AS (
 SELECT CASE WHEN r.id IS NULL THEN NULL ELSE jsonb_build_object('id',r.id,'version',r.version,'evidence',r.evidence,'confirmedBy',r.confirmed_by,'confirmedAt',r.confirmed_at,'revokedBy',r.revoked_by,'revokedAt',r.revoked_at,'reason',r.reason) END AS association,v.*,coalesce('association:'||p.id::text,'endpoint:'||v.id) AS object_key,
 coalesce(a.state,'active') AS asset_state,u.registration_user,u.session_reference,u.registration_valid,
 u.valid_until,($3::text[] IS NULL OR v.id=ANY($3)) AS sensitive,
 ($4::text[] IS NULL OR v.id=ANY($4)) AS ownership
 FROM visible v LEFT JOIN paired p ON v.id=ANY(p.devices) LEFT JOIN mdm_devices.associations r ON r.tenant_id=$1::uuid AND r.id=p.id
 LEFT JOIN mdm_devices.asset_states a ON a.tenant_id=$1::uuid AND a.device=v.id
 LEFT JOIN mdm_access.directory_users u ON u.tenant_id=$1::uuid AND u.device=v.id
), matched AS (
 SELECT m.object_key,m.id,
 jsonb_path_match(jsonb_build_object('reference',jsonb_build_object('kind',CASE WHEN left(m.object_key,12)='association:' THEN 'association' ELSE 'endpoint' END,'id',substring(m.object_key FROM position(':' IN m.object_key)+1)),'association',m.association,'key',m.object_key,'status',m.status,'assetState',m.asset_state,
 'channel',jsonb_build_array(m.channel),
 'source',jsonb_build_array(m.source),
 'platform',jsonb_build_array(m.platform),
 'search',CASE WHEN $8::boolean THEN coalesce((SELECT jsonb_agg(term) FROM (
  SELECT unnest(search_values) AS term FROM (
   (SELECT search_values FROM mdm_assets.directory_fields f WHERE f.tenant_id=$1::uuid AND f.device=m.id AND (m.sensitive OR f.sensitivity='standard') AND f.field<>'device.serial_number' AND (f.state='conflict' OR f.state='known' AND btrim(f.value)<>'') ORDER BY CASE f.field WHEN 'device.name' THEN 0 WHEN 'device.network.apple.host_name' THEN 1 ELSE 2 END LIMIT 1)
   UNION ALL SELECT search_values FROM mdm_assets.directory_fields f WHERE f.tenant_id=$1::uuid AND f.device=m.id AND (m.sensitive OR f.sensitivity='standard') AND f.field='device.serial_number'
  ) fields
  UNION ALL
  SELECT term FROM (
   SELECT (m.registration_user->>'principalId')::uuid AS principal WHERE m.ownership AND m.registration_user->>'tenantId'=$1::text AND m.registration_user->>'instanceId'=$6::text
   UNION
   SELECT s.principal_id FROM platform_sessions s WHERE m.sensitive AND m.registration_valid
    AND s.instance_id=(m.session_reference->>'instance')::uuid AND s.tenant_id=(m.session_reference->>'tenant')::uuid
    AND s.principal_id=(m.session_reference->>'principal')::uuid AND s.session_id=(m.session_reference->>'session')::uuid AND s.credential_kind=m.session_reference->>'credentialKind'
  ) related CROSS JOIN LATERAL (
   SELECT related.principal::text AS term
   UNION ALL SELECT login FROM people p WHERE m.sensitive AND p.principal_id=related.principal AND p.active
   UNION ALL SELECT display_name FROM people p WHERE m.sensitive AND p.principal_id=related.principal AND p.active AND p.status='available'
  ) names
 ) terms),'[]'::jsonb) ELSE '[]'::jsonb END), $5::jsonpath) AS matches
 FROM members m
), objects AS (
 SELECT object_key,array_agg(id ORDER BY id COLLATE "C") AS devices FROM matched
 GROUP BY object_key HAVING bool_or(matches)
