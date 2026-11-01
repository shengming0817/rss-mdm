-- Recovery owns the credential command write contract.
WITH reachable AS (
 SELECT r.* FROM pg_roles r WHERE r.rolname=current_user OR pg_has_role(session_user,r.oid,'MEMBER')
), required(relation,insertable,deletable) AS (VALUES
 ('mdm_recovery_tasks.operations',true,false),('mdm_recovery_tasks.requests',true,false)
), updates(relation,col) AS (VALUES
 ('mdm_recovery_tasks.operations','authority'),('mdm_recovery_tasks.operations','revision'),('mdm_recovery_tasks.operations','observed_command_version'),('mdm_recovery_tasks.operations','gateway_accepted'),('mdm_recovery_tasks.operations','dispatch_failure'),('mdm_recovery_tasks.operations','request')
)
SELECT current_setting('transaction_isolation')='read committed'
 AND current_user='mdm_command_runtime'
 AND NOT EXISTS(SELECT FROM reachable WHERE rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication)
 AND NOT EXISTS(SELECT FROM required r LEFT JOIN pg_class c ON c.oid=to_regclass(r.relation)
 WHERE c.oid IS NULL OR c.relkind<>'r' OR NOT c.relrowsecurity OR NOT c.relforcerowsecurity
 OR c.relowner IN(SELECT oid FROM reachable)
 OR has_table_privilege(current_user,c.oid,'SELECT')<>true
 OR has_table_privilege(current_user,c.oid,'INSERT')<>r.insertable
 OR has_table_privilege(current_user,c.oid,'DELETE')<>r.deletable
 OR has_table_privilege(current_user,c.oid,'UPDATE,TRUNCATE,REFERENCES,TRIGGER')
 OR (SELECT count(*) FROM pg_policy WHERE polrelid=c.oid)<>1
 OR NOT EXISTS(SELECT FROM pg_policy p WHERE p.polrelid=c.oid AND p.polname='tenant' AND p.polcmd='*' AND p.polpermissive AND p.polroles=ARRAY[0::oid]
 AND lower(replace(regexp_replace(pg_get_expr(p.polqual,p.polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'
 AND pg_get_expr(p.polqual,p.polrelid)=pg_get_expr(p.polwithcheck,p.polrelid)))
 AND NOT EXISTS(SELECT FROM required r JOIN pg_attribute a ON a.attrelid=to_regclass(r.relation) AND a.attnum>0 AND NOT a.attisdropped
 WHERE has_column_privilege(current_user,a.attrelid,a.attnum,'UPDATE')<>EXISTS(SELECT FROM updates u WHERE u.relation=r.relation AND u.col=a.attname)
 OR has_column_privilege(current_user,a.attrelid,a.attnum,'REFERENCES'))
 AND NOT EXISTS(SELECT FROM required r JOIN pg_class c ON c.oid=to_regclass(r.relation),LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
 WHERE a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable))
 AND NOT EXISTS(SELECT FROM required r JOIN pg_attribute col ON col.attrelid=to_regclass(r.relation),LATERAL aclexplode(col.attacl) a
 WHERE a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable))
;
