-- Scalar directory projection over the permanent source-facts relation.
BEGIN;
-- Raw narrow source rows, before deduplication or value decoding. UNION ALL
-- allows the caller's overflow probe to stop at its explicit source-row budget.
CREATE VIEW mdm_assets.directory_inputs WITH (security_barrier=true) AS
SELECT tenant_id FROM mdm.inventory WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
UNION ALL
SELECT tenant_id FROM mdm.manual_assignments WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
UNION ALL
SELECT tenant_id FROM mdm.field_versions WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
UNION ALL
SELECT tenant_id FROM mdm.collection_definitions WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid;
REVOKE ALL ON mdm_assets.directory_inputs FROM PUBLIC;
GRANT SELECT ON mdm_assets.directory_inputs TO mdm_access,mdm_identity_runtime;
CREATE VIEW mdm_assets.directory_fields WITH (security_barrier=true) AS
WITH facts AS (
 SELECT * FROM mdm_assets.directory_sources
 WHERE field IN ('device.name','device.network.apple.host_name','device.network.apple.local_host_name','device.serial_number')
), priorities AS (
 SELECT tenant_id,device,field,sensitivity,min(priority) FILTER(WHERE state IN('known','null') OR state LIKE 'unknown_%') AS priority
 FROM facts GROUP BY tenant_id,device,field,sensitivity
), resolved AS (
 SELECT p.tenant_id,p.device,p.field,p.sensitivity,
  CASE WHEN bool_or(f.state LIKE 'unknown_%') FILTER(WHERE f.priority=p.priority) THEN 'unknown'
   WHEN count(DISTINCT jsonb_build_array(f.state,f.text_value)) FILTER(WHERE f.priority=p.priority AND f.state IN('known','null'))>1 THEN 'conflict'
   WHEN bool_or(f.state='known') FILTER(WHERE f.priority=p.priority) THEN 'known' ELSE 'other' END AS state,
  min(f.text_value) FILTER(WHERE f.priority=p.priority AND f.state='known') AS value,
  array_agg(DISTINCT f.text_value) FILTER(WHERE f.state='known') AS source_values
 FROM priorities p JOIN facts f USING(tenant_id,device,field,sensitivity)
 GROUP BY p.tenant_id,p.device,p.field,p.sensitivity,p.priority
)
SELECT tenant_id,device,field,sensitivity,state,value,
 CASE WHEN state='known' THEN ARRAY[value] WHEN state='conflict' THEN source_values ELSE ARRAY[]::text[] END AS search_values
FROM resolved;
REVOKE ALL ON mdm_assets.directory_fields FROM PUBLIC;
GRANT SELECT ON mdm_assets.directory_fields TO mdm_access,mdm_identity_runtime;
GRANT USAGE ON SCHEMA mdm_assets TO mdm_identity_runtime;
-- The same-connection registration projection reads only manual-fact presence.
GRANT SELECT(tenant_id,device) ON mdm.manual_assignments TO mdm_access,mdm_command_runtime;
GRANT SELECT ON mdm.inventory_presence TO mdm_access,mdm_command_runtime;
COMMIT;

-- One current-source definition of device inventory presence, shared by return/filter/sort/count.
BEGIN;
CREATE VIEW mdm_assets.device_inventory_presence WITH (security_barrier=true) AS
WITH catalog AS (
 SELECT field FROM (SELECT DISTINCT ON(field) field,definition FROM mdm.field_versions
 WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid ORDER BY field,version DESC) latest
 WHERE definition IS NOT NULL
), datasets AS (
 SELECT DISTINCT source,dataset FROM mdm.collection_definitions
 WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
 AND EXISTS(SELECT FROM jsonb_array_elements(definition->'fields') f
 WHERE f->'scope'='{"kind":"device"}'::jsonb AND f->'definition'->>'key' IN(SELECT field FROM catalog))
)
SELECT DISTINCT p.tenant_id,r.id AS device
FROM mdm.inventory_presence p
JOIN mdm_access.devices r ON r.tenant_id=p.tenant_id AND r.id=p.scope::jsonb->>'registration' AND r.state='active'
JOIN mdm_access.report_sources s ON s.tenant_id=r.tenant_id AND s.device=r.id AND s.enabled
 AND s.source=p.scope::jsonb->>'source' AND s.epoch::text=p.scope::jsonb->>'epoch'
JOIN datasets d ON d.source=s.source AND d.dataset=p.scope::jsonb->>'dataset'
WHERE p.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
 AND p.journal='mdm.observation.v1' AND p.generation='inventory-projection-v1'
 AND p.scope::jsonb->>'tenant'=p.tenant_id::text
 AND p.scope::jsonb->>'object'=CASE WHEN d.dataset='inventory' THEN r.id ELSE r.id||':'||d.dataset END
 AND r.channel=CASE WHEN s.source IN('mdm.windows','mdm.apple') THEN 'mdm' WHEN s.source IN('agent.builtin','agent.script','agent.osquery','agent.native') THEN 'agent' END
 AND EXISTS(SELECT FROM mdm_access.credentials k WHERE k.tenant_id=r.tenant_id AND k.device=r.id AND k.state='active')
UNION
SELECT tenant_id,device FROM mdm.manual_assignments WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid;
REVOKE ALL ON mdm_assets.device_inventory_presence FROM PUBLIC;
GRANT SELECT ON mdm_assets.device_inventory_presence TO mdm_access,mdm_command_runtime;
COMMIT;
