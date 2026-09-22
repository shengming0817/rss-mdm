SELECT EXISTS(
 SELECT 1 FROM mdm_commands.plan_executions e
 JOIN mdm_management.previews p ON (p.tenant_id,p.id)=(e.tenant_id,e.plan)
 JOIN mdm_policy.aggregates a ON (a.tenant_id,a.id,a.revision)=(e.tenant_id,e.policy,e.policy_revision)
 JOIN mdm_management.scopes sc ON (sc.tenant_id,sc.id,sc.revision)=(p.tenant_id,p.scope,p.scope_revision)
 WHERE e.tenant_id=$1::uuid AND e.plan=$2::uuid AND NOT sc.deleted
 AND NOT EXISTS(
  SELECT 1 FROM jsonb_array_elements(p.document->'sources') source
  WHERE CASE source->'reference'->>'kind'
   WHEN 'group' THEN NOT EXISTS(
    SELECT 1 FROM mdm_group.groups g WHERE g.tenant_id=e.tenant_id
     AND g.id=(source->'reference'->>'id')::uuid AND NOT g.deleted
     AND g.revision=(source->>'revision')::bigint AND g.member_version=(source->>'member_version')::bigint)
   WHEN 'device' THEN (SELECT max(r.generation) FROM mdm_access.registrations r
    WHERE r.tenant_id=e.tenant_id AND r.device=source->'reference'->>'id' AND r.state='active') IS DISTINCT FROM (source->>'revision')::bigint
   ELSE true END))
