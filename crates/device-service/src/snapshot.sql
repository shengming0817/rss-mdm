, selected_devices AS MATERIALIZED (
 SELECT DISTINCT unnest(devices) AS device FROM selected_objects
), world AS MATERIALIZED (
 SELECT mdm_devices.read_world(
  ARRAY(SELECT substring(object_key FROM 13)::uuid FROM selected_objects WHERE object_key LIKE 'association:%'),
  ARRAY(SELECT device FROM selected_devices ORDER BY device COLLATE "C"),(SELECT fields FROM read_input)) AS document
), related AS MATERIALIZED (
 SELECT d.device,coalesce(u.registration_revision,0) AS registration_revision,u.registration_user,
 coalesce(u.current_revision,0) AS current_revision,u.session_reference,u.confirmed_at,
 ($3::text[] IS NULL OR d.device=ANY($3)) AS sensitive,($4::text[] IS NULL OR d.device=ANY($4)) AS ownership,
 CASE WHEN s.session_id IS NOT NULL THEN jsonb_build_object('tenantId',s.tenant_id,'instanceId',s.instance_id,'principalId',s.principal_id) END AS current_user
 FROM selected_devices d LEFT JOIN mdm_access.directory_users u ON u.tenant_id=$1::uuid AND u.device=d.device
 LEFT JOIN platform_sessions s ON u.registration_valid
  AND s.instance_id=(u.session_reference->>'instance')::uuid AND s.tenant_id=(u.session_reference->>'tenant')::uuid
  AND s.principal_id=(u.session_reference->>'principal')::uuid AND s.session_id=(u.session_reference->>'session')::uuid AND s.credential_kind=u.session_reference->>'credentialKind'
), people_targets AS (
 SELECT (registration_user->>'principalId')::uuid AS id FROM related WHERE ownership AND sensitive
 UNION SELECT (current_user->>'principalId')::uuid FROM related WHERE sensitive
), displays AS (
 SELECT principal_id,jsonb_build_object('login',max(login),'profiles',coalesce(jsonb_agg(jsonb_build_object(
  'source',CASE WHEN source='local' THEN jsonb_build_object('kind','identity_local') ELSE jsonb_build_object('kind','idp','provider',source) END,
  'status',status,'displayName',CASE WHEN btrim(display_name)<>'' THEN display_name END,'username',CASE WHEN btrim(username)<>'' THEN username END
 ) ORDER BY source) FILTER(WHERE source IS NOT NULL),'[]'::jsonb)) AS display
 FROM people_display WHERE active AND principal_id IN(SELECT id FROM people_targets) GROUP BY principal_id
)
SELECT jsonb_build_object('world',(SELECT document FROM world),
 'objects',coalesce((SELECT jsonb_agg(jsonb_build_object('key',object_key,'devices',devices) ORDER BY object_key COLLATE "C") FROM selected_objects),'[]'::jsonb),
 'relationships',coalesce((SELECT jsonb_agg(jsonb_build_object('device',device,
  'registrationUser',CASE WHEN ownership THEN jsonb_build_object('revision',registration_revision,'user',registration_user,'display',NULL) END,
  'currentUser',CASE WHEN sensitive THEN jsonb_build_object('revision',current_revision,'state',CASE WHEN current_user IS NOT NULL THEN 'active' WHEN session_reference IS NOT NULL THEN 'invalidated' ELSE 'unbound' END,'user',current_user,'confirmedAt',confirmed_at,'display',NULL) END)) FROM related),'[]'::jsonb),
 'displays',coalesce((SELECT jsonb_object_agg(principal_id,display) FROM displays),'{}'::jsonb),
 'budget',(SELECT budget FROM read_input),'more',(SELECT more FROM read_input),
 'asOf',floor(extract(epoch FROM statement_timestamp()))::bigint) AS value
