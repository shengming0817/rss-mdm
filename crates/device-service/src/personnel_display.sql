SELECT principal_id, jsonb_build_object('login',max(login), 'profiles',
 coalesce(jsonb_agg(jsonb_build_object(
  'source',CASE WHEN source='local' THEN jsonb_build_object('kind','identity_local')
    ELSE jsonb_build_object('kind','idp','provider',source) END,
  'status',status,'displayName',CASE WHEN btrim(display_name)<>'' THEN display_name END,'username',CASE WHEN btrim(username)<>'' THEN username END
 ) ORDER BY source) FILTER(WHERE source IS NOT NULL),'[]'::jsonb)) AS display
FROM identity_personnel
WHERE principal_id=ANY($1::uuid[]) AND active
GROUP BY principal_id
