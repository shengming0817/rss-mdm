-- Seek the next distinct key and its latest version through the catalog primary key.
WITH RECURSIVE keys(field) AS (
 (SELECT field FROM mdm.field_versions WHERE tenant_id=$1::uuid ORDER BY field LIMIT 1)
 UNION ALL
 SELECT n.field FROM keys k CROSS JOIN LATERAL
  (SELECT field FROM mdm.field_versions WHERE tenant_id=$1::uuid AND field>k.field ORDER BY field LIMIT 1) n
), definitions AS (
 SELECT v.definition FROM keys k CROSS JOIN LATERAL
  (SELECT definition FROM mdm.field_versions WHERE tenant_id=$1::uuid AND field=k.field ORDER BY version DESC LIMIT 1) v
 WHERE k.field<>ALL($2) AND v.definition IS NOT NULL
 UNION ALL
 SELECT value FROM jsonb_array_elements($3)
)
SELECT count(*)<=$4 AND coalesce(sum(octet_length(definition::text)),0)<=$5 FROM definitions
