-- Current scalar source facts and canonical hardware keys, owned by Inventory.
BEGIN;
CREATE VIEW mdm_assets.directory_sources WITH (security_barrier=true) AS
WITH catalog AS (
 SELECT field,definition FROM (
  SELECT DISTINCT ON(field) field,definition FROM mdm.field_versions
  WHERE tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid
   AND field IN ('device.name','device.network.apple.host_name','device.network.apple.local_host_name','device.serial_number','device.hardware_uuid','device.manufacturer')
  ORDER BY field,version DESC
 ) latest WHERE definition IS NOT NULL
), facts AS (
 SELECT r.tenant_id,r.device,r.purpose='primary' AS primary_registration,i.field,c.definition->>'sensitivity' AS sensitivity,
  (c.definition->'sources'->>i.source)::integer AS priority,i.state,
  i.value::jsonb->>'value' AS text_value
 FROM mdm.inventory i
 JOIN mdm_access.registrations r ON r.tenant_id=i.tenant_id AND r.id::text=i.registration AND r.state='active'
 JOIN mdm_access.report_sources s ON (s.tenant_id,s.registration,s.source)=(r.tenant_id,r.id,i.source) AND s.epoch::text=i.epoch AND s.enabled
 JOIN mdm.collection_definitions d ON (d.tenant_id,d.coverage,d.source)=(i.tenant_id,i.coverage,i.source)
 JOIN catalog c ON c.field=i.field AND c.definition->'sources' ? i.source
 WHERE i.tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid
  AND i.journal='mdm.observation.v1' AND i.generation='inventory-projection-v1'
  AND EXISTS(SELECT FROM mdm_access.credentials k WHERE (k.tenant_id,k.registration)=(r.tenant_id,r.id) AND k.state='active')
  AND i.field_scope::jsonb='{"kind":"device"}'::jsonb
  AND i.scope::jsonb->>'tenant'=i.tenant_id::text
  AND i.scope::jsonb->>'registration'=i.registration
  AND i.scope::jsonb->>'source'=i.source AND i.scope::jsonb->>'epoch'=i.epoch
  AND i.scope::jsonb->>'dataset'=d.dataset
  AND i.scope::jsonb->>'object'=CASE WHEN d.dataset='inventory' THEN i.registration ELSE i.registration||':'||d.dataset END
  AND EXISTS(SELECT FROM jsonb_array_elements(d.definition->'fields') f WHERE f->'definition'->>'key'=i.field AND f->'scope'='{"kind":"device"}'::jsonb)
)
SELECT * FROM facts
UNION ALL
SELECT m.tenant_id,m.device,false,m.field,c.definition->>'sensitivity',
 (c.definition->'sources'->>'manual')::integer,
 CASE WHEN m.fact#>>'{state,kind}'='unknown' THEN 'unknown_manual' ELSE m.fact#>>'{state,kind}' END,
 m.fact#>>'{state,value,value}'
FROM mdm.manual_assignments m JOIN catalog c ON c.field=m.field
WHERE m.tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid
 AND (c.definition->>'manual')::boolean AND c.definition->'sources' ? 'manual'
 AND m.fact#>'{evidence,scope}'='{"kind":"device"}'::jsonb;
REVOKE ALL ON mdm_assets.directory_sources FROM PUBLIC;

CREATE VIEW mdm_assets.hardware_keys WITH (security_barrier=true) AS
SELECT DISTINCT tenant_id,device,CASE field WHEN 'device.serial_number' THEN 'serial' ELSE 'uuid' END AS kind,text_value AS value
FROM mdm_assets.directory_sources WHERE primary_registration AND state='known' AND field IN('device.serial_number','device.hardware_uuid');
REVOKE ALL ON mdm_assets.hardware_keys FROM PUBLIC;
GRANT SELECT ON mdm_assets.hardware_keys TO mdm_access;
COMMIT;
