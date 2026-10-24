-- Fixed owner relationships. Merge paths before authorization and keyset admission.
WITH RECURSIVE walk(id,path) AS (
 SELECT $2::uuid,ARRAY[$2::uuid]
 UNION ALL
 (SELECT DISTINCT ON(g.id) g.id,w.path||g.id FROM walk w
 JOIN mdm_assets.group_selections s ON s.tenant_id=$1::uuid AND s.group_ids @> ARRAY[w.id]
 JOIN mdm_group.groups g ON (g.tenant_id,g.id,g.rule_version)=(s.tenant_id,s.group_id,s.rule_version)
 WHERE NOT g.deleted AND NOT g.id=ANY(w.path) AND cardinality(w.path)<=16
 ORDER BY g.id,w.path||g.id)
), paths AS MATERIALIZED (
 SELECT DISTINCT ON(id,cardinality(path)=2) id,path
 FROM walk ORDER BY id,cardinality(path)=2,cardinality(path),path
), scope_paths AS (
 SELECT s.id,s.revision,sv.definition,p.path||s.id AS path,
   ARRAY(SELECT role FROM (VALUES
    ('target',sv.definition->'targets'),('limitation',sv.definition->'limitations'),('exclusion',sv.definition->'exclusions')
   ) x(role,refs) WHERE refs @> jsonb_build_array(jsonb_build_object('kind','group','id',p.id))) AS roles
 FROM paths p JOIN mdm_planning.scope_sources e ON e.tenant_id=$1::uuid AND e.kind='group' AND e.target=p.id::text
 JOIN mdm_planning.scopes s ON (s.tenant_id,s.id)=(e.tenant_id,e.scope) AND NOT s.deleted
 JOIN mdm_planning.scope_versions sv ON (sv.tenant_id,sv.id,sv.revision)=(s.tenant_id,s.id,s.revision)
), scopes AS MATERIALIZED (
 SELECT DISTINCT ON(id,cardinality(path)=2) id,revision,definition,path FROM scope_paths
 WHERE cardinality(roles)>0 ORDER BY id,cardinality(path)=2,cardinality(path),path
), candidates AS (
 SELECT 0 AS kind,g.id,g.revision,CASE WHEN cardinality(p.path)=2 THEN 0 ELSE 1 END AS relation,p.path,'active'::text AS state
 FROM paths p JOIN mdm_group.groups g ON g.tenant_id=$1::uuid AND g.id=p.id WHERE cardinality(p.path)>1
 UNION ALL
 SELECT 1,s.id,s.revision,CASE WHEN cardinality(s.path)=2 THEN 0 ELSE 1 END,s.path,'active' FROM scopes s
 UNION ALL
 SELECT 2,p.id,p.revision,1,s.path||p.id,p.state FROM scopes s JOIN mdm_policy.policies p
 ON p.tenant_id=$1::uuid AND (p.definition->>'scope'=s.id::text OR EXISTS(
  SELECT FROM jsonb_array_elements(coalesce(p.definition#>'{action,rollout,stages}','[]')) stage WHERE stage->>'scope'=s.id::text))
 UNION ALL
 SELECT 3,r.id,r.revision,CASE WHEN cardinality(p.path)=1 THEN 0 ELSE 1 END,p.path||r.id,
  CASE WHEN r.enabled THEN 'enabled' ELSE 'disabled' END
 FROM paths p JOIN mdm_compliance.groups e ON e.tenant_id=$1::uuid AND e.group_id=p.id
 JOIN mdm_compliance.rules r ON (r.tenant_id,r.id)=(e.tenant_id,e.rule_id)
), merged AS (
 -- For one source kind and path length, intermediate kind positions are identical.
 SELECT DISTINCT ON(kind,id,relation) * FROM candidates ORDER BY kind,id,relation,cardinality(path),path
), page AS MATERIALIZED (
 SELECT * FROM merged WHERE ($3::integer IS NULL OR kind=$3) AND ($4::integer IS NULL OR relation=$4)
 AND kind=ANY($5::integer[]) AND (kind<>2 OR 1=ANY($5::integer[]))
 AND ($6::integer IS NULL OR (kind,id,relation)>($6,$7::uuid,$8::integer))
 ORDER BY kind,id,relation LIMIT $9
), needed_groups AS (
 SELECT id FROM page WHERE kind=0
 UNION
 SELECT e.group_id FROM page p JOIN mdm_compliance.groups e ON e.tenant_id=$1::uuid AND e.rule_id=p.id
 JOIN paths x ON x.id=e.group_id WHERE p.kind=3 AND p.relation=CASE WHEN cardinality(x.path)=1 THEN 0 ELSE 1 END
), group_status AS MATERIALIZED (
 SELECT g.id,
   (b.input_version IS NULL OR b.input_version NOT LIKE 'objects:%' OR b.input_version ~ '^objects:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}:[0-9]+:[0-9a-fA-F]{64}$')
   AND EXISTS(SELECT FROM mdm_planning.source_heads WHERE tenant_id=g.tenant_id AND id='group-definition.'||g.id::text)
   AND EXISTS(SELECT FROM mdm_planning.source_heads WHERE tenant_id=g.tenant_id AND id='group-authority.'||g.id::text) AS valid,
   mdm_planning.group_current(g.id) AND CASE WHEN b.input_version LIKE 'objects:%' THEN
   EXISTS(SELECT FROM mdm_devices.input_snapshots s WHERE s.tenant_id=g.tenant_id
    AND s.id=split_part(b.input_version,':',2)::uuid AND s.phase='sealed'
    AND s.watermark=split_part(b.input_version,':',3)::bigint AND s.version=split_part(b.input_version,':',4)
    AND s.watermark=coalesce((SELECT revision FROM mdm.asset_clock WHERE tenant_id=g.tenant_id),0)
    AND s.version=encode(sha256(convert_to(s.watermark::text||':'||coalesce((SELECT relation_revision FROM mdm_devices.checkpoints WHERE tenant_id=g.tenant_id),0)::text,'UTF8')),'hex'))
   ELSE true END AS current
 FROM needed_groups n JOIN mdm_group.groups g ON g.tenant_id=$1::uuid AND g.id=n.id
 LEFT JOIN mdm_group.member_runs b ON (b.tenant_id,b.id)=(g.tenant_id,g.member_set)
), details AS (
 SELECT p.*,
 CASE p.kind
  WHEN 0 THEN (SELECT current FROM group_status WHERE id=p.id)
  WHEN 1 THEN mdm_planning.scope_admission(p.id,NULL)->>'state'='fresh'
  WHEN 2 THEN NOT EXISTS(SELECT FROM mdm_policy.policies pol
    CROSS JOIN LATERAL (SELECT (pol.definition->>'scope')::uuid AS id UNION SELECT (stage->>'scope')::uuid FROM jsonb_array_elements(coalesce(pol.definition#>'{action,rollout,stages}','[]')) stage) refs
    LEFT JOIN mdm_planning.scopes s ON s.tenant_id=pol.tenant_id AND s.id=refs.id
    WHERE pol.tenant_id=$1::uuid AND pol.id=p.id AND (s.id IS NULL OR s.deleted OR mdm_planning.scope_admission(s.id,NULL)->>'state'<>'fresh'))
  WHEN 3 THEN (SELECT bool_and(g.current) FROM mdm_compliance.groups e JOIN paths x ON x.id=e.group_id JOIN group_status g ON g.id=e.group_id
    WHERE e.tenant_id=$1::uuid AND e.rule_id=p.id AND p.relation=CASE WHEN cardinality(x.path)=1 THEN 0 ELSE 1 END)
 END AS current,
 CASE p.kind
  WHEN 0 THEN ARRAY(SELECT DISTINCT CASE WHEN (n->>'negated')::boolean THEN 'not_member_of' ELSE 'member_of' END
    FROM mdm_group.groups g JOIN mdm_group.rules r ON (r.tenant_id,r.group_id,r.version)=(g.tenant_id,g.id,g.rule_version)
    CROSS JOIN LATERAL jsonb_array_elements(convert_from(r.document,'UTF8')::jsonb->'nodes') n
    WHERE g.tenant_id=$1::uuid AND g.id=p.id AND n->>'kind'='membership'
      AND (p.relation=0 AND n->>'group'=$2::text OR p.relation=1 AND n->>'group'<>$2::text AND EXISTS(SELECT FROM paths x WHERE x.id::text=n->>'group')) ORDER BY 1)
  WHEN 1 THEN ARRAY(SELECT DISTINCT role FROM scope_paths s CROSS JOIN LATERAL unnest(s.roles) role WHERE s.id=p.id AND p.relation=CASE WHEN cardinality(s.path)=2 THEN 0 ELSE 1 END ORDER BY role)
  WHEN 2 THEN ARRAY(SELECT DISTINCT role FROM mdm_policy.policies pol CROSS JOIN scopes s
    CROSS JOIN LATERAL (SELECT 'policy_scope' AS role WHERE pol.definition->>'scope'=s.id::text UNION SELECT 'rollout_stage' WHERE EXISTS(SELECT FROM jsonb_array_elements(coalesce(pol.definition#>'{action,rollout,stages}','[]')) stage WHERE stage->>'scope'=s.id::text)) roles
    WHERE pol.tenant_id=$1::uuid AND pol.id=p.id ORDER BY role)
  WHEN 3 THEN ARRAY['compliance_target']::text[] END AS roles
 FROM page p
), related_scopes AS (
 SELECT id FROM scopes
 UNION
 SELECT (p.definition->>'scope')::uuid FROM mdm_policy.policies p
 WHERE p.tenant_id=$1::uuid AND EXISTS(SELECT FROM merged m WHERE m.kind=2 AND m.id=p.id)
 UNION
 SELECT (stage->>'scope')::uuid FROM mdm_policy.policies p
 CROSS JOIN LATERAL jsonb_array_elements(coalesce(p.definition#>'{action,rollout,stages}','[]')) stage
 WHERE p.tenant_id=$1::uuid AND EXISTS(SELECT FROM merged m WHERE m.kind=2 AND m.id=p.id)
), related_group_seeds AS (
 SELECT id FROM paths
 UNION
 SELECT e.target::uuid FROM related_scopes s JOIN mdm_planning.scope_sources e
 ON e.tenant_id=$1::uuid AND e.scope=s.id AND e.kind='group'
), related_groups(id) AS (
 SELECT id FROM related_group_seeds
 UNION
 SELECT unnest(e.group_ids) FROM related_groups r
 JOIN mdm_group.groups g ON g.tenant_id=$1::uuid AND g.id=r.id
 JOIN mdm_assets.group_selections e ON(e.tenant_id,e.group_id,e.rule_version)=(g.tenant_id,g.id,g.rule_version)
), meta AS (
 SELECT encode(sha256(convert_to(jsonb_build_array(
  (SELECT jsonb_agg(jsonb_build_array(g.id,g.revision,g.rule_version,g.deleted,g.member_set,g.member_version,g.calculation_revision,b.phase,b.input_version,s.phase) ORDER BY g.id)
    FROM mdm_group.groups g LEFT JOIN mdm_group.member_runs b ON (b.tenant_id,b.id)=(g.tenant_id,g.member_set)
    LEFT JOIN mdm_devices.input_snapshots s ON s.tenant_id=g.tenant_id AND s.id::text=CASE WHEN b.input_version LIKE 'objects:%' THEN split_part(b.input_version,':',2) END WHERE g.tenant_id=$1::uuid AND EXISTS(SELECT FROM related_groups p WHERE p.id=g.id)),
  (SELECT jsonb_agg(jsonb_build_array(s.id,s.revision,s.deleted,s.resolution,s.resolution_revision,s.calculation_revision,r.phase) ORDER BY s.id)
    FROM mdm_planning.scopes s LEFT JOIN mdm_planning.scope_runs r ON (r.tenant_id,r.id)=(s.tenant_id,s.resolution) WHERE s.tenant_id=$1::uuid AND EXISTS(SELECT FROM related_scopes r WHERE r.id=s.id)),
  (SELECT jsonb_agg(jsonb_build_array(id,revision,state) ORDER BY id) FROM mdm_policy.policies p WHERE tenant_id=$1::uuid AND EXISTS(SELECT FROM merged m WHERE m.kind=2 AND m.id=p.id)),
  (SELECT jsonb_agg(jsonb_build_array(id,revision,enabled) ORDER BY id) FROM mdm_compliance.rules r WHERE tenant_id=$1::uuid AND EXISTS(SELECT FROM merged m WHERE m.kind=3 AND m.id=r.id)),
  (SELECT jsonb_agg(jsonb_build_array(id,revision,required_input,observed_input) ORDER BY id COLLATE "C") FROM mdm_planning.source_heads h WHERE tenant_id=$1::uuid AND (EXISTS(SELECT FROM related_groups p WHERE h.id IN ('group-definition.'||p.id::text,'group-authority.'||p.id::text,'group-members.'||p.id::text)) OR EXISTS(SELECT FROM related_scopes s WHERE h.id='scope-definition.'||s.id::text))),
  (SELECT revision FROM mdm.asset_clock WHERE tenant_id=$1::uuid),
  (SELECT relation_revision FROM mdm_devices.checkpoints WHERE tenant_id=$1::uuid)
 )::text,'UTF8')),'hex') AS generation,
 (EXISTS(SELECT FROM mdm_group.groups g JOIN mdm_assets.group_selections s ON(s.tenant_id,s.group_id,s.rule_version)=(g.tenant_id,g.id,g.rule_version) WHERE g.tenant_id=$1::uuid AND NOT g.deleted AND s.group_ids @> ARRAY[$2::uuid])
  OR EXISTS(SELECT FROM mdm_planning.scope_sources e JOIN mdm_planning.scopes s ON(s.tenant_id,s.id)=(e.tenant_id,e.scope) WHERE e.tenant_id=$1::uuid AND NOT s.deleted AND e.kind='group' AND e.target=$2::text)
  OR EXISTS(SELECT FROM mdm_compliance.groups e JOIN mdm_compliance.rules r ON(r.tenant_id,r.id)=(e.tenant_id,e.rule_id) WHERE e.tenant_id=$1::uuid AND e.group_id=$2::uuid)) AS blocked
)
SELECT meta.generation,meta.blocked,(EXISTS(SELECT FROM group_status WHERE NOT valid)
 OR EXISTS(SELECT FROM page p JOIN mdm_group.groups g ON g.tenant_id=$1::uuid AND g.id=p.id
 LEFT JOIN mdm_group.rules r ON(r.tenant_id,r.group_id,r.version)=(g.tenant_id,g.id,g.rule_version)
 WHERE p.kind=0 AND (r.version IS NULL OR r.digest<>sha256(r.document)
  OR convert_from(r.document,'UTF8')::jsonb->>'v'<>'1'
  OR convert_from(r.document,'UTF8')::jsonb->>'tenant'<>$1::text
  OR convert_from(r.document,'UTF8')::jsonb->>'version'<>r.version))) AS invalid,coalesce((SELECT jsonb_agg(jsonb_build_object(
 'source',jsonb_build_object('kind',(ARRAY['group','scope','policy','compliance_rule'])[d.kind+1],'id',d.id),
 'revision',d.revision,'relation',CASE WHEN d.relation=0 THEN 'direct' ELSE 'indirect' END,
 'roles',d.roles,'via',(SELECT jsonb_agg(jsonb_build_object('kind',CASE WHEN ordinal=cardinality(d.path) THEN (ARRAY['group','scope','policy','compliance_rule'])[d.kind+1] WHEN d.kind=2 AND ordinal=cardinality(d.path)-1 THEN 'scope' ELSE 'group' END,'id',id) ORDER BY ordinal) FROM unnest(d.path) WITH ORDINALITY x(id,ordinal)),
 'lifecycleState',d.state,'freshness',CASE WHEN d.current THEN 'current' ELSE 'pending' END,
 'effective',d.current AND d.state IN('active','enabled'),'blocksDeletion',true
 ) ORDER BY d.kind,d.id,d.relation) FROM details d),'[]'::jsonb)::text AS items FROM meta
