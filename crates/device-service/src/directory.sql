), page AS (
 SELECT * FROM objects WHERE $9::text IS NULL OR CASE WHEN $10 THEN object_key COLLATE "C"<$9 COLLATE "C" ELSE object_key COLLATE "C">$9 COLLATE "C" END
 ORDER BY CASE WHEN NOT $10 THEN object_key END COLLATE "C",CASE WHEN $10 THEN object_key END COLLATE "C" DESC LIMIT $11
)
SELECT jsonb_build_object(
 'asOf',floor(extract(epoch FROM statement_timestamp()))::bigint,
 'objects',coalesce((SELECT jsonb_agg(jsonb_build_object('key',object_key,'devices',devices)
 ORDER BY CASE WHEN NOT $10 THEN object_key END COLLATE "C",CASE WHEN $10 THEN object_key END COLLATE "C" DESC) FROM page),'[]'::jsonb),
 'validUntil',least((SELECT min(valid_until) FROM members),
  (SELECT min(platform_valid_until) FROM platform_sessions),
  (SELECT floor(extract(epoch FROM min(expires_at)))::bigint FROM mdm_access.requests WHERE tenant_id=$1::uuid AND state='pending' AND expires_at>statement_timestamp())),
 'queryRevision',coalesce((SELECT query_revision FROM mdm_devices.checkpoints WHERE tenant_id=$1::uuid),0),
 'watermark',coalesce((SELECT revision FROM mdm.asset_clock WHERE tenant_id=$1::uuid),0),
 'relationRevision',coalesce((SELECT relation_revision FROM mdm_devices.checkpoints WHERE tenant_id=$1::uuid),0)
) AS value
