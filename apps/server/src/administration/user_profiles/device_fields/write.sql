WITH candidates AS (
 SELECT * FROM jsonb_to_recordset($2) AS d(device uuid,field text,field_version bigint,subject uuid,value jsonb,valid_until bigint,fingerprint jsonb)
), changed AS MATERIALIZED (
 SELECT d.* FROM candidates d
 LEFT JOIN LATERAL (SELECT * FROM mdm_assets.personnel_history h
  WHERE h.tenant_id=$1::uuid AND h.device=d.device AND h.field=d.field ORDER BY revision DESC LIMIT 1) h ON true
 WHERE (h.revision IS NULL AND d.value IS NOT NULL)
 OR (h.revision IS NOT NULL AND ((d.field_version,d.subject,d.value,d.fingerprint) IS DISTINCT FROM (h.field_version,h.subject,h.value,h.fingerprint)
 OR d.valid_until<h.valid_until OR ((d.valid_until IS NULL)<>(h.valid_until IS NULL))
 OR (d.valid_until>h.valid_until AND h.valid_until<extract(epoch FROM statement_timestamp())+25)))
), changes AS MATERIALIZED (
 SELECT device,mdm.record_asset_change($1::uuid,'derived',jsonb_build_object('device',device,'fact',device,'operation','updated'),array_agg(field ORDER BY field)) AS revision
 FROM changed GROUP BY device ORDER BY device
)
INSERT INTO mdm_assets.personnel_history(tenant_id,device,field,revision,field_version,subject,value,observed_at,valid_until,fingerprint)
 SELECT $1::uuid,d.device,d.field,e.revision,d.field_version,d.subject,d.value,floor(extract(epoch FROM statement_timestamp())),d.valid_until,d.fingerprint
 FROM changed d JOIN changes e USING (device)
