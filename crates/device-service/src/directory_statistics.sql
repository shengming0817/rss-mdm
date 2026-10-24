)
SELECT CASE WHEN (SELECT ok FROM source_budget) THEN jsonb_build_object('budget',(SELECT jsonb_build_object('rows',rows,'bytes',bytes,'ok',ok,'inputRows',(SELECT rows FROM source_budget)) FROM candidate_budget),'statistics',(SELECT jsonb_build_object('deviceViewCount',count(*),'endpointCount',coalesce(sum(cardinality(devices)),0)) FROM objects),
'asOf',floor(extract(epoch FROM statement_timestamp()))::bigint,
'queryRevision',coalesce((SELECT query_revision FROM mdm_devices.checkpoints WHERE tenant_id=$1::uuid),0),
'watermark',coalesce((SELECT revision FROM mdm.asset_clock WHERE tenant_id=$1::uuid),0),
'relationRevision',coalesce((SELECT relation_revision FROM mdm_devices.checkpoints WHERE tenant_id=$1::uuid),0)) ELSE jsonb_build_object('budget',jsonb_build_object('rows',0,'bytes',0,'ok',false,'inputRows',(SELECT rows FROM source_budget))) END AS value
