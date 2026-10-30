WITH execution_roles AS (
 SELECT oid FROM pg_roles WHERE rolname=current_user OR pg_has_role(session_user,oid,'SET')
), reachable AS (
 SELECT r.* FROM pg_roles r WHERE EXISTS(SELECT 1 FROM execution_roles e WHERE pg_has_role(e.oid,r.oid,'USAGE'))
), expected(name,updates,keys) AS (VALUES
 ('scope_projection_runs',ARRAY['phase','source_cursor','projection_cursor','channel_hashes','agent_revision','mdm_revision']::text[],ARRAY['tenant_id','id']::text[]),
 ('scope_channel_results',ARRAY['matched','pending','target','entry_revision']::text[],ARRAY['tenant_id','run','channel','device']::text[])
), relations AS (
 SELECT e.*,c.oid,c.relowner,c.relrowsecurity,c.relforcerowsecurity,c.relacl FROM expected e
 JOIN pg_class c ON c.oid=to_regclass('mdm_commands.'||e.name) AND c.relkind='r'
)
SELECT (SELECT count(*) FROM relations)=2
AND NOT EXISTS(SELECT 1 FROM reachable WHERE rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication OR oid IN(SELECT relowner FROM relations))
AND NOT EXISTS(SELECT 1 FROM relations t WHERE NOT relrowsecurity OR NOT relforcerowsecurity
 OR NOT has_table_privilege(current_user,t.oid,'SELECT') OR has_table_privilege(current_user,t.oid,'INSERT')<>$1
 OR has_table_privilege(current_user,t.oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
 OR EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=t.oid AND a.attnum>0 AND NOT a.attisdropped
    AND (has_column_privilege(current_user,t.oid,a.attnum,'UPDATE')<>($1 AND a.attname=ANY(t.updates)) OR has_column_privilege(current_user,t.oid,a.attnum,'REFERENCES')))
 OR (SELECT count(*) FROM pg_policy WHERE polrelid=t.oid)<>1
 OR NOT EXISTS(SELECT 1 FROM pg_policy p WHERE p.polrelid=t.oid AND p.polname='tenant' AND p.polcmd='*' AND p.polpermissive AND p.polroles=ARRAY[0::oid]
  AND lower(replace(regexp_replace(pg_get_expr(p.polqual,p.polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'
  AND pg_get_expr(p.polqual,p.polrelid)=pg_get_expr(p.polwithcheck,p.polrelid))
 OR NOT EXISTS(SELECT 1 FROM pg_constraint k WHERE k.conrelid=t.oid AND k.contype='p' AND k.convalidated AND NOT k.condeferrable
   AND (SELECT array_agg(a.attname::text ORDER BY key.n) FROM unnest(k.conkey) WITH ORDINALITY key(attnum,n) JOIN pg_attribute a ON a.attrelid=t.oid AND a.attnum=key.attnum)=t.keys)
 OR EXISTS(SELECT 1 FROM aclexplode(coalesce(t.relacl,acldefault('r',t.relowner))) a WHERE a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable)))
AND NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid IN(SELECT oid FROM relations) AND NOT tgisinternal AND NOT(
 (tgname='scope_channel_result_guard' AND tgrelid='mdm_commands.scope_channel_results'::regclass AND tgfoid='mdm_commands.guard_scope_channel_result()'::regprocedure AND tgenabled='O')))
AND EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='mdm_commands.scope_channel_results'::regclass AND tgname='scope_channel_result_guard' AND tgenabled='O')
AND NOT EXISTS(SELECT 1 FROM relations t CROSS JOIN reachable r WHERE
 has_table_privilege(r.oid,t.oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
 OR EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=t.oid AND a.attnum>0 AND NOT a.attisdropped
  AND (has_column_privilege(r.oid,t.oid,a.attnum,'REFERENCES')
   OR (has_column_privilege(r.oid,t.oid,a.attnum,'UPDATE') AND NOT ($1 AND a.attname=ANY(t.updates))))))
AND NOT EXISTS(SELECT 1 FROM relations t JOIN pg_attribute col ON col.attrelid=t.oid
 CROSS JOIN LATERAL aclexplode(col.attacl) a WHERE a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable))
