WITH execution_roles AS (
 SELECT oid FROM pg_roles WHERE rolname=current_user OR pg_has_role(session_user,oid,'SET')
), reachable AS (
 SELECT r.* FROM pg_roles r WHERE EXISTS(SELECT 1 FROM execution_roles e WHERE pg_has_role(e.oid,r.oid,'USAGE'))
), owned AS (
 SELECT c.* FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='mdm_scope' AND c.relkind='r' AND c.relname<>'group_changes'
)
SELECT current_setting('transaction_isolation')='read committed'
AND (SELECT array_agg(relname::text ORDER BY relname) FROM owned)=ARRAY['asset_dispatch','scope_results','scope_runs','scope_source_members','scope_sources','scope_versions','scopes','tasks']
AND NOT EXISTS(SELECT 1 FROM reachable WHERE rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication OR oid IN(SELECT relowner FROM owned))
AND NOT EXISTS(SELECT 1 FROM owned t WHERE NOT relrowsecurity OR NOT relforcerowsecurity
 OR NOT has_table_privilege(current_user,t.oid,'SELECT') OR NOT has_table_privilege(current_user,t.oid,'INSERT')
 OR has_table_privilege(current_user,t.oid,'TRUNCATE') OR has_table_privilege(current_user,t.oid,'TRIGGER')
 OR has_table_privilege(current_user,t.oid,'REFERENCES')
 OR has_table_privilege(current_user,t.oid,'DELETE')<>(t.relname='scope_sources')
 OR (SELECT count(*) FROM pg_policy p WHERE p.polrelid=t.oid)<>1
 OR NOT EXISTS(SELECT 1 FROM pg_policy p WHERE p.polrelid=t.oid AND p.polname='tenant' AND p.polcmd='*' AND p.polroles=ARRAY[0::oid]
  AND p.polpermissive
  AND lower(replace(regexp_replace(pg_get_expr(p.polqual,p.polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'
  AND pg_get_expr(p.polwithcheck,p.polrelid)=pg_get_expr(p.polqual,p.polrelid)))
AND NOT EXISTS(SELECT 1 FROM owned t JOIN pg_attribute a ON a.attrelid=t.oid AND a.attnum>0 AND NOT a.attisdropped
 WHERE has_column_privilege(current_user,t.oid,a.attnum,'UPDATE') <>
 ((t.relname='scopes' AND a.attname IN('revision','deleted','resolution','resolution_revision','calculation_revision'))
 OR (t.relname='scope_runs' AND a.attname IN('phase','source_index','source_cursor','evaluation_cursor','object_count','member_count'))
 OR (t.relname='tasks' AND a.attname IN('completed','failure','failure_detail','replacement_task'))
 OR (t.relname='asset_dispatch' AND a.attname IN('from_cut','to_cut','event_after','page_through','cursor','relation_consumed','relation_watermark','relation_position','relation_cursor'))))
AND has_function_privilege(current_user,'mdm_scope.scope_admission(uuid,text)','EXECUTE')
AND has_function_privilege(current_user,'mdm_scope.scope_state(uuid,text)','EXECUTE')

AND NOT EXISTS(SELECT 1 FROM owned t WHERE NOT EXISTS(
 SELECT 1 FROM pg_constraint k WHERE k.conrelid=t.oid AND k.contype='p' AND k.convalidated AND NOT k.condeferrable
 AND (SELECT array_agg(a.attname::text ORDER BY key.n) FROM unnest(k.conkey) WITH ORDINALITY key(attnum,n) JOIN pg_attribute a ON a.attrelid=t.oid AND a.attnum=key.attnum)=
 CASE t.relname WHEN 'scope_results' THEN ARRAY['tenant_id','run','device'] WHEN 'scope_source_members' THEN ARRAY['tenant_id','run','source','device'] WHEN 'scope_sources' THEN ARRAY['tenant_id','scope','kind','target'] WHEN 'scope_versions' THEN ARRAY['tenant_id','id','revision'] WHEN 'asset_dispatch' THEN ARRAY['tenant_id'] ELSE ARRAY['tenant_id','id'] END))
AND NOT EXISTS(SELECT 1 FROM owned t,LATERAL aclexplode(coalesce(t.relacl,acldefault('r',t.relowner))) a WHERE a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable))
AND NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid IN(SELECT oid FROM owned) AND NOT tgisinternal)
-- Required rights are checked on current_user above. Every role reachable by the
-- original login must also remain within the write capability, even without INHERIT.
AND NOT EXISTS(SELECT 1 FROM owned t CROSS JOIN reachable r WHERE
 has_table_privilege(r.oid,t.oid,'UPDATE,TRUNCATE,REFERENCES,TRIGGER')
 OR (has_table_privilege(r.oid,t.oid,'DELETE') AND t.relname<>'scope_sources')
 OR EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=t.oid AND a.attnum>0 AND NOT a.attisdropped
  AND (has_column_privilege(r.oid,t.oid,a.attnum,'REFERENCES')
   OR (has_column_privilege(r.oid,t.oid,a.attnum,'UPDATE') AND NOT (
    (t.relname='scopes' AND a.attname IN('revision','deleted','resolution','resolution_revision','calculation_revision'))
    OR (t.relname='scope_runs' AND a.attname IN('phase','source_index','source_cursor','evaluation_cursor','object_count','member_count'))
    OR (t.relname='tasks' AND a.attname IN('completed','failure','failure_detail','replacement_task'))
    OR (t.relname='asset_dispatch' AND a.attname IN('from_cut','to_cut','event_after','page_through','cursor','relation_consumed','relation_watermark','relation_position','relation_cursor')))))))
AND NOT EXISTS(SELECT 1 FROM owned t JOIN pg_attribute col ON col.attrelid=t.oid
 CROSS JOIN LATERAL aclexplode(col.attacl) a WHERE a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable))
