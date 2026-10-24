), page AS (
 SELECT * FROM objects WHERE $10::text IS NULL OR CASE WHEN $11 THEN object_key COLLATE "C"<$10 COLLATE "C" ELSE object_key COLLATE "C">$10 COLLATE "C" END
 ORDER BY CASE WHEN NOT $11 THEN object_key END COLLATE "C",CASE WHEN $11 THEN object_key END COLLATE "C" DESC LIMIT $12
)
SELECT CASE WHEN (SELECT ok FROM source_budget) THEN jsonb_build_object(
 'budget',(SELECT jsonb_build_object('rows',rows,'bytes',bytes,'ok',ok,'inputRows',(SELECT rows FROM source_budget)) FROM candidate_budget),
 'asOf',floor(extract(epoch FROM statement_timestamp()))::bigint,
 'objects',coalesce((SELECT jsonb_agg(jsonb_build_object('key',object_key,'devices',devices)
 ORDER BY CASE WHEN NOT $11 THEN object_key END COLLATE "C",CASE WHEN $11 THEN object_key END COLLATE "C" DESC) FROM page),'[]'::jsonb),
 'validUntil',least((SELECT min(valid_until) FROM members),
  (SELECT min(s.platform_valid_until) FROM platform_sessions s JOIN members m ON s.session_id=(m.session_reference->>'session')::uuid AND s.principal_id=(m.session_reference->>'principal')::uuid),
  (SELECT floor(extract(epoch FROM min(expires_at)))::bigint FROM mdm_access.requests WHERE tenant_id=$1::uuid AND state='pending' AND expires_at>statement_timestamp())),
 'queryRevision',coalesce((SELECT query_revision FROM mdm_devices.checkpoints WHERE tenant_id=$1::uuid),0),
 'watermark',coalesce((SELECT revision FROM mdm.asset_clock WHERE tenant_id=$1::uuid),0),
 'relationRevision',coalesce((SELECT relation_revision FROM mdm_devices.checkpoints WHERE tenant_id=$1::uuid),0)
) ELSE jsonb_build_object('budget',jsonb_build_object('rows',0,'bytes',0,'ok',false,'inputRows',(SELECT rows FROM source_budget))) END AS value
