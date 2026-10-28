WITH expected(name,updates,deletable,keys) AS (VALUES
 ('group_tasks',ARRAY['completed','cursor','replacement_task','authority_revision','failure'],false,ARRAY['tenant_id','id']),
 ('group_evaluations',ARRAY['binding'],true,ARRAY['tenant_id','task']),
 ('group_evaluation_arrays',ARRAY['state'],true,ARRAY['tenant_id','task','version']),
 ('group_dispatch',ARRAY['consumed','watermark','cursor','relation_revision','relation_cursor','relation_pending_revision'],false,ARRAY['tenant_id'])
), reachable AS (
 SELECT oid FROM pg_roles WHERE rolname=current_user OR pg_has_role(current_user,oid,'MEMBER')
), owned AS (
 SELECT e.*,c.oid,c.relowner,c.relrowsecurity,c.relforcerowsecurity
 FROM expected e JOIN pg_class c ON c.oid=to_regclass('mdm_assets.'||e.name) AND c.relkind='r'
)
SELECT (SELECT count(*)=4 FROM owned)
 AND NOT EXISTS(SELECT FROM pg_roles WHERE oid IN(SELECT oid FROM reachable) AND (rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication))
 AND NOT EXISTS(SELECT FROM owned o WHERE NOT o.relrowsecurity OR NOT o.relforcerowsecurity OR o.relowner IN(SELECT oid FROM reachable)
  OR NOT has_table_privilege(current_user,o.oid,'SELECT') OR NOT has_table_privilege(current_user,o.oid,'INSERT')
  OR has_table_privilege(current_user,o.oid,'UPDATE,TRUNCATE,REFERENCES,TRIGGER')
  OR has_table_privilege(current_user,o.oid,'DELETE')<>o.deletable
  OR EXISTS(SELECT FROM pg_attribute a WHERE a.attrelid=o.oid AND a.attnum>0 AND NOT a.attisdropped
    AND (has_column_privilege(current_user,o.oid,a.attnum,'UPDATE')<>(a.attname=ANY(o.updates))
      OR has_column_privilege(current_user,o.oid,a.attnum,'REFERENCES')))
  OR EXISTS(SELECT FROM aclexplode(coalesce(o.relacl,acldefault('r',o.relowner))) a WHERE a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable))
  OR EXISTS(SELECT FROM pg_attribute col CROSS JOIN LATERAL aclexplode(col.attacl) a WHERE col.attrelid=o.oid AND (a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable)))
  OR (SELECT count(*) FROM pg_policy WHERE polrelid=o.oid)<>1
  OR NOT EXISTS(SELECT FROM pg_policy p WHERE p.polrelid=o.oid AND p.polname='tenant' AND p.polcmd='*' AND p.polpermissive AND p.polroles=ARRAY[0::oid]
    AND lower(replace(regexp_replace(pg_get_expr(p.polqual,p.polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'
    AND pg_get_expr(p.polqual,p.polrelid)=pg_get_expr(p.polwithcheck,p.polrelid))
  OR NOT EXISTS(SELECT FROM pg_index i WHERE i.indrelid=o.oid AND i.indisunique AND i.indisvalid AND i.indisready AND i.indislive AND i.indimmediate AND i.indpred IS NULL AND i.indexprs IS NULL
    AND (SELECT array_agg(a.attname::text ORDER BY k.n) FROM unnest(i.indkey::smallint[]) WITH ORDINALITY k(num,n) JOIN pg_attribute a ON a.attrelid=o.oid AND a.attnum=k.num WHERE k.n<=i.indnkeyatts)=o.keys))
