WITH tables AS (
 SELECT c.* FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='mdm_group' AND c.relkind='r'
), reachable AS (
 SELECT * FROM pg_roles WHERE oid=(SELECT oid FROM pg_roles WHERE rolname=current_user)
 OR pg_has_role(current_user,oid,'MEMBER')
)
SELECT
 (SELECT array_agg(relname::text ORDER BY relname)=ARRAY['groups','member_changes','member_pages','member_rows','member_runs','operations','rules'] FROM tables)
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='mdm_group' AND c.relkind NOT IN('r','i'))
 AND NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
 WHERE n.nspname='mdm_group')
 AND NOT EXISTS(SELECT 1 FROM reachable WHERE rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication
 OR oid IN (SELECT relowner FROM tables) OR has_schema_privilege(oid,'mdm_group','CREATE'))
 AND has_schema_privilege(current_user,'mdm_group','USAGE')
 AND NOT EXISTS(SELECT 1 FROM tables t WHERE NOT t.relrowsecurity OR NOT t.relforcerowsecurity
 OR NOT has_table_privilege(current_user,t.oid,'SELECT')
 OR NOT has_table_privilege(current_user,t.oid,'INSERT')
 OR has_table_privilege(current_user,t.oid,'TRUNCATE,REFERENCES,TRIGGER,UPDATE')
 OR has_table_privilege(current_user,t.oid,'DELETE')
 OR (SELECT count(*) FROM pg_policy WHERE polrelid=t.oid)<>1
 OR NOT EXISTS(SELECT 1 FROM pg_policy WHERE polrelid=t.oid AND polname='tenant' AND polcmd='*' AND polpermissive AND polroles=ARRAY[0::oid]
 AND lower(replace(regexp_replace(pg_get_expr(polqual,polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'
 AND lower(replace(regexp_replace(pg_get_expr(polwithcheck,polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'))
 AND NOT EXISTS(SELECT 1 FROM tables t, LATERAL aclexplode(coalesce(t.relacl,acldefault('r',t.relowner))) a
 WHERE a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable))
 AND NOT EXISTS(SELECT 1 FROM pg_namespace n,LATERAL aclexplode(coalesce(n.nspacl,acldefault('n',n.nspowner))) a
 WHERE n.nspname='mdm_group' AND (a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable)))
 AND NOT EXISTS(SELECT 1 FROM tables t JOIN pg_attribute a ON a.attrelid=t.oid WHERE a.attnum>0 AND NOT a.attisdropped
 AND (has_column_privilege(current_user,t.oid,a.attnum,'UPDATE') <>
  (t.relname='groups' AND a.attname IN('presentation','revision','member_version','member_count','rule_version','deleted','member_set','calculation_revision')
  OR t.relname='member_runs' AND a.attname IN('phase','cursor','diff_cursor','object_count','processed_count','member_count','added','removed','receipt'))
 OR has_column_privilege(current_user,t.oid,a.attnum,'REFERENCES')))
 AND NOT EXISTS(SELECT 1 FROM tables t JOIN pg_attribute a ON a.attrelid=t.oid,
 LATERAL aclexplode(a.attacl) acl WHERE acl.grantee=0
 OR (acl.grantee IN(SELECT oid FROM reachable) AND acl.is_grantable))
 -- These keys are required by tenant-addressed reads, conflict handling and replay.
 AND NOT EXISTS(SELECT 1 FROM (VALUES
 ('mdm_group.groups',ARRAY['tenant_id','id']::text[]),
 ('mdm_group.rules',ARRAY['tenant_id','group_id','version']::text[]),
 ('mdm_group.operations',ARRAY['tenant_id','id']::text[]),
 ('mdm_group.member_runs',ARRAY['tenant_id','id']::text[]),
 ('mdm_group.member_rows',ARRAY['tenant_id','run_id','object_id']::text[]),
 ('mdm_group.member_pages',ARRAY['tenant_id','run_id','first_id']::text[]),
 ('mdm_group.member_changes',ARRAY['tenant_id','run_id','object_id']::text[])
 ) required(relation,columns) WHERE NOT EXISTS(
 SELECT 1 FROM pg_index i WHERE i.indrelid=to_regclass(required.relation)
 AND i.indisunique AND i.indisvalid AND i.indisready AND i.indislive AND i.indimmediate
 AND i.indpred IS NULL AND i.indexprs IS NULL
 AND (SELECT array_agg(a.attname::text ORDER BY k.ordinality)
 FROM unnest(i.indkey::smallint[]) WITH ORDINALITY k(num,ordinality)
 JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.num
 WHERE k.ordinality<=i.indnkeyatts)=required.columns))

 -- An operation receipt always carries its original request.
 AND EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='mdm_group.operations'::regclass
 AND attname='request' AND NOT attisdropped AND attnotnull AND atttypid='bytea'::regtype)
 AND NOT EXISTS(SELECT 1 FROM (VALUES('mdm_group.member_rows'),('mdm_group.member_pages'),('mdm_group.member_changes')) required(relation)
 WHERE NOT EXISTS(SELECT 1 FROM pg_constraint c WHERE c.conrelid=to_regclass(required.relation)
 AND c.contype='f' AND c.convalidated AND c.confrelid='mdm_group.member_runs'::regclass
 AND (SELECT array_agg(a.attname::text ORDER BY k.n) FROM unnest(c.conkey) WITH ORDINALITY k(num,n)
 JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.num)=ARRAY['tenant_id','run_id']
 AND (SELECT array_agg(a.attname::text ORDER BY k.n) FROM unnest(c.confkey) WITH ORDINALITY k(num,n)
 JOIN pg_attribute a ON a.attrelid=c.confrelid AND a.attnum=k.num)=ARRAY['tenant_id','id']))
