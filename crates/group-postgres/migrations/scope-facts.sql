-- Shared Group facts; values are always scoped by the caller's existing tenant transaction.
BEGIN;
CREATE FUNCTION mdm_group.scope_dependencies(p_group uuid) RETURNS SETOF uuid
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT unnest(r.group_ids) FROM mdm_group.groups g JOIN mdm_group.rules r
 ON(r.tenant_id,r.group_id,r.version)=(g.tenant_id,g.id,g.rule_version)
 WHERE g.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND g.id=p_group;
$$;
CREATE FUNCTION mdm_group.lock_scope_dependencies(p_groups uuid[]) RETURNS void
 LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT g.id FROM mdm_group.groups g WHERE g.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
 AND g.id=ANY(p_groups) ORDER BY g.id FOR SHARE NOWAIT;
$$;
CREATE FUNCTION mdm_group.scope_source(p_group uuid) RETURNS TABLE(id uuid,deleted boolean,definition_version bigint)
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT g.id,g.deleted,h.definition_version FROM mdm_group.groups g
 LEFT JOIN mdm_group.source_state h ON(h.tenant_id,h.group_id)=(g.tenant_id,g.id)
 WHERE g.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND g.id=p_group;
$$;
REVOKE ALL ON FUNCTION mdm_group.scope_dependencies(uuid),mdm_group.lock_scope_dependencies(uuid[]),mdm_group.scope_source(uuid) FROM PUBLIC;
COMMIT;
