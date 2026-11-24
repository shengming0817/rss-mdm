-- All pages of a calculation use its captured evaluation time.
WITH latest AS (
 SELECT DISTINCT ON(device,field) device,field,subject,revision,observed_at,valid_until,value,field_version
 FROM mdm_assets.personnel_history WHERE tenant_id=$1::uuid AND device=ANY($2) AND field=ANY($3) AND mdm.asset_visible($4,revision)
 ORDER BY device,field,revision DESC
)
SELECT h.device,h.field,h.subject,h.revision,h.observed_at,
 CASE WHEN h.valid_until IS NULL OR h.valid_until>$5::bigint THEN h.value END AS value
FROM latest h JOIN LATERAL (
 SELECT version,revision,definition FROM mdm.field_versions v WHERE v.tenant_id=$1::uuid AND v.field=h.field AND mdm.asset_visible($4,v.revision) ORDER BY version DESC LIMIT 1
) v ON v.definition IS NOT NULL AND v.version=h.field_version
WHERE NOT $6::boolean OR (
 NOT EXISTS(SELECT FROM mdm_assets.personnel_history n WHERE n.tenant_id=$1::uuid AND n.device=h.device AND n.field=h.field AND n.revision>h.revision)
 AND NOT EXISTS(SELECT FROM mdm.field_versions n WHERE n.tenant_id=$1::uuid AND n.field=h.field AND n.version>h.field_version)
)
ORDER BY h.device,h.field
