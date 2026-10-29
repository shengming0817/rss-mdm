-- Bounded raw facts only. Rust retains field validation, provenance decoding and resolution.
CREATE FUNCTION mdm_assets.read_snapshot(p_devices text[],p_fields text[],p_watermark bigint,p_scope jsonb)
RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
WITH context AS (
 SELECT nullif(current_setting('rss.tenant_id',true),'')::uuid AS tenant
 WHERE cardinality(p_devices)<=1000 AND cardinality(p_fields)<=1024 AND p_watermark>=0
), catalog AS MATERIALIZED (
 SELECT field,definition FROM (
  SELECT DISTINCT ON(field) field,definition FROM mdm.field_versions
  WHERE tenant_id=(SELECT tenant FROM context) AND field=ANY(p_fields) AND revision<=p_watermark
  ORDER BY field,version DESC
 ) latest WHERE definition IS NOT NULL AND definition->>'sensitivity'<>'secret'
), datasets AS MATERIALIZED (
 SELECT DISTINCT source,dataset FROM mdm.collection_definitions
 WHERE tenant_id=(SELECT tenant FROM context) AND EXISTS(
  SELECT FROM jsonb_array_elements(definition->'fields') f WHERE f->'scope'=p_scope AND f->'definition'->>'key'=ANY(p_fields)
 ) ORDER BY source,dataset LIMIT 4097
), sources AS MATERIALIZED (
 SELECT DISTINCT r.device,r.registration,r.generation,r.channel,r.source,r.epoch,d.dataset,
 format('{"tenant":%s,"object":%s,"registration":%s,"source":%s,"dataset":%s,"epoch":%s}',
  to_json((SELECT tenant::text FROM context)),to_json(CASE WHEN d.dataset='inventory' THEN r.registration ELSE r.registration||':'||d.dataset END),
  to_json(r.registration),to_json(r.source),to_json(d.dataset),to_json(r.epoch)) AS scope
 FROM mdm_access.asset_sources_at(p_devices,p_watermark) r JOIN datasets d USING(source)
 LIMIT 2001
), latest AS MATERIALIZED (
 SELECT DISTINCT ON(h.scope_digest,h.field,h.field_scope) h.scope_digest,h.field,h.field_scope,h.document
 FROM sources s JOIN mdm.inventory_history h ON h.scope_digest=sha256(convert_to(jsonb_build_array('mdm.observation.v1'::text,'inventory-projection-v1'::text,s.scope)::text,'UTF8'))
 WHERE h.tenant_id=(SELECT tenant FROM context) AND h.revision<=p_watermark AND h.field IN(SELECT field FROM catalog)
 ORDER BY h.scope_digest,h.field,h.field_scope,h.revision DESC
), observed AS MATERIALIZED (
 SELECT DISTINCT ON(r.scope,r.field,r.field_scope) to_jsonb(r)||jsonb_build_object('definition',d.definition::text) AS document
 FROM latest h CROSS JOIN LATERAL jsonb_populate_record(NULL::mdm.inventory,h.document) r
 JOIN mdm.collection_definitions d ON(d.tenant_id,d.coverage,d.source)=(r.tenant_id,r.coverage,r.source)
 WHERE h.document IS NOT NULL AND r.journal='mdm.observation.v1' AND r.generation='inventory-projection-v1'
  AND r.scope IN(SELECT scope FROM sources) AND r.field_scope::jsonb=p_scope
 ORDER BY r.scope,r.field,r.field_scope,r.collection_sequence DESC LIMIT 131073
), manual AS MATERIALIZED (
 SELECT document||jsonb_build_object('array',c.definition->'valueType'->>'kind'='array') AS document
 FROM (
  SELECT DISTINCT ON(device,field) field,document FROM mdm.manual_history
  WHERE tenant_id=(SELECT tenant FROM context) AND device=ANY(p_devices) AND revision<=p_watermark
   AND field IN(SELECT field FROM catalog) AND p_scope='{"kind":"device"}'::jsonb
  ORDER BY device,field,revision DESC
 ) h JOIN catalog c USING(field) WHERE document IS NOT NULL LIMIT 131073
), versions AS MATERIALIZED (
 SELECT version,format,jsonb_build_object('version',version,'field',field,'definitionDigest',definition_digest,'count',item_count,'bytes',canonical_bytes,'digest',digest) AS document
 FROM mdm.array_versions WHERE tenant_id=(SELECT tenant FROM context) AND version IN(
  SELECT document->>'value_version' FROM observed UNION SELECT document->>'last_known_version' FROM observed
  UNION SELECT document->>'value_version' FROM manual UNION SELECT document->>'last_known_version' FROM manual
 )
), quality_history AS MATERIALIZED (
 SELECT DISTINCT ON(h.scope,h.run) h.scope,h.sequence,h.run,h.document
 FROM sources s JOIN mdm_access.collection_history h ON h.scope=s.scope
 WHERE h.tenant_id=(SELECT tenant FROM context) AND h.revision<=p_watermark
 ORDER BY h.scope,h.run,h.revision DESC
), quality_fields AS MATERIALIZED (
 SELECT DISTINCT ON(h.scope,f->'definition'->>'key') h.scope,h.sequence,h.run,h.document,f->'definition'->>'key' AS field
 FROM quality_history h JOIN mdm_access.collection_versions v ON v.tenant_id=(SELECT tenant FROM context) AND v.version=h.document->>'progress_version'
 CROSS JOIN LATERAL jsonb_array_elements(v.metadata->'definition'->'fields') f
 WHERE h.document IS NOT NULL AND f->'scope'=p_scope AND f->'definition'->>'key'=ANY(p_fields)
  AND (h.document->>'result'<>'pending' OR f->'definition'->>'key' NOT IN('channel.agent.installation','channel.mdm.enrollment'))
 ORDER BY h.scope,f->'definition'->>'key',h.sequence DESC,h.run DESC
), quality AS MATERIALIZED (
 SELECT jsonb_build_object('scope',h.scope,'sequence',h.sequence,'id',h.run,'result',h.document->>'result',
  'metadata',CASE WHEN v.metadata_bytes<=67108864 THEN v.metadata::text END,
  'delivery_pending',(h.document->>'delivery_pending')::boolean,'selected_fields',jsonb_agg(h.field ORDER BY h.field)) AS document
 FROM quality_fields h JOIN mdm_access.collection_versions v ON v.tenant_id=(SELECT tenant FROM context) AND v.version=h.document->>'progress_version'
 GROUP BY h.scope,h.sequence,h.run,h.document,v.metadata,v.metadata_bytes LIMIT 131073
), budget AS (
 SELECT (SELECT count(*) FROM context)=1 AND (SELECT count(*) FROM sources)<=2000 AND (SELECT count(*) FROM datasets)<=4096
  AND (SELECT count(*) FROM observed)<=131072 AND (SELECT count(*) FROM manual)<=131072 AND (SELECT count(*) FROM quality)<=131072
  AND coalesce((SELECT sum(octet_length(document::text)) FROM (
   SELECT document FROM observed UNION ALL SELECT document FROM manual UNION ALL SELECT document FROM quality UNION ALL SELECT document FROM versions
  ) bytes),0)<=16777216 AND NOT EXISTS(SELECT FROM versions WHERE format<>1) AS ok
)
SELECT CASE WHEN (SELECT ok FROM budget) THEN jsonb_build_object('ok',true,
 'catalog',coalesce((SELECT jsonb_agg(definition ORDER BY field) FROM catalog),'[]'::jsonb),
 'sources',coalesce((SELECT jsonb_agg(to_jsonb(s) ORDER BY scope) FROM sources s),'[]'::jsonb),
 'observed',coalesce((SELECT jsonb_agg(document) FROM observed),'[]'::jsonb),
 'manual',coalesce((SELECT jsonb_agg(document) FROM manual),'[]'::jsonb),
 'versions',coalesce((SELECT jsonb_object_agg(version,document) FROM versions),'{}'::jsonb),
 'quality',coalesce((SELECT jsonb_agg(document) FROM quality),'[]'::jsonb))
 ELSE jsonb_build_object('ok',false) END
$$;
REVOKE ALL ON FUNCTION mdm_assets.read_snapshot(text[],text[],bigint,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mdm_assets.read_snapshot(text[],text[],bigint,jsonb) TO mdm_access,mdm_identity_runtime,mdm_inventory_runtime,mdm_scope_runtime,mdm_policy_runtime,mdm_telemetry_runtime,mdm_command_runtime;
GRANT USAGE ON SCHEMA mdm_assets TO mdm_command_runtime;
