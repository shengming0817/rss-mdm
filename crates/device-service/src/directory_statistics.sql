)
SELECT jsonb_build_object('statistics',jsonb_build_object('deviceViewCount',count(*),'endpointCount',coalesce(sum(cardinality(devices)),0)),
'asOf',floor(extract(epoch FROM statement_timestamp()))::bigint,
'queryRevision',coalesce((SELECT query_revision FROM mdm_devices.checkpoints WHERE tenant_id=$1::uuid),0),
'watermark',coalesce((SELECT revision FROM mdm.asset_clock WHERE tenant_id=$1::uuid),0),
'relationRevision',coalesce((SELECT relation_revision FROM mdm_devices.checkpoints WHERE tenant_id=$1::uuid),0)) AS value FROM objects
