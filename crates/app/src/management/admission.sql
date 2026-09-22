WITH tables AS (
 SELECT c.* FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='mdm_management' AND c.relkind='r'
), reachable AS (
 SELECT * FROM pg_roles WHERE rolname=current_user OR pg_has_role(current_user,oid,'MEMBER')
)
SELECT
 current_setting('transaction_isolation')='serializable'
 AND (SELECT array_agg(relname::text ORDER BY relname)=ARRAY['operations','plan_references','previews','resource_references','saved_queries','scope_versions','scopes'] FROM tables)
 AND NOT EXISTS(SELECT 1 FROM reachable WHERE rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication
 OR oid IN(SELECT relowner FROM tables))
 AND NOT EXISTS(SELECT 1 FROM tables t WHERE NOT relrowsecurity OR NOT relforcerowsecurity
 OR NOT has_table_privilege(current_user,t.oid,'SELECT') OR NOT has_table_privilege(current_user,t.oid,'INSERT')
 OR has_table_privilege(current_user,t.oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
 OR (SELECT count(*) FROM pg_policy WHERE polrelid=t.oid)<>1
 OR NOT EXISTS(SELECT 1 FROM pg_policy WHERE polrelid=t.oid AND polname='tenant' AND polcmd='*' AND polpermissive AND polroles=ARRAY[0::oid]
 AND lower(replace(regexp_replace(pg_get_expr(polqual,polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'
 AND lower(replace(regexp_replace(pg_get_expr(polwithcheck,polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'))
 AND NOT EXISTS(SELECT 1 FROM tables t JOIN pg_attribute a ON a.attrelid=t.oid WHERE a.attnum>0 AND NOT a.attisdropped
 AND (has_column_privilege(current_user,t.oid,a.attnum,'UPDATE') <> ((t.relname='scopes' AND a.attname IN('revision','deleted')) OR (t.relname='saved_queries' AND a.attname IN('revision','document'))) OR has_column_privilege(current_user,t.oid,a.attnum,'REFERENCES')))
 AND NOT EXISTS(SELECT 1 FROM pg_namespace n WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema' AND has_schema_privilege(current_user,n.oid,'CREATE'))
 AND has_schema_privilege(current_user,'mdm_management','USAGE')
 AND has_table_privilege(current_user,'mdm_access.audit','INSERT')
 AND NOT has_table_privilege(current_user,'mdm_access.audit','SELECT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema' AND c.relkind IN('r','v','m','f')
 AND n.nspname NOT IN('mdm_management','mdm_group','mdm_policy','mdm_resource')
 AND (n.nspname,c.relname) NOT IN(('mdm','asset_clock'),('mdm','asset_changes'),('mdm','inventory_history'),('mdm','manual_history'),('mdm_access','asset_authority_history'),('rss_reconcile','targets'),('mdm_access','audit'),('mdm_access','devices'),('mdm_access','registrations'),('mdm_access','report_sources'),('mdm_access','collection_runs'),('mdm','inventory'),('mdm','manual_assignments'),('mdm_access','credentials'),('mdm_software_composition','subjects'),('rss_transactional_messaging','policy'),('rss_transactional_messaging','outbox'))
 AND (has_table_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,REFERENCES')))
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE (n.nspname,c.relname) IN(('mdm_access','devices'),('mdm_access','registrations'),('mdm_access','report_sources'),('mdm_access','collection_runs'),('mdm','inventory'),('mdm_software_composition','subjects'))
 AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity OR c.relowner IN(SELECT oid FROM reachable) OR NOT has_table_privilege(current_user,c.oid,'SELECT') OR has_table_privilege(current_user,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege(current_user,c.oid,'INSERT,UPDATE,REFERENCES')))
 AND NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema' AND p.oid NOT IN ('rss_reconcile.assert_tenant(uuid)'::regprocedure,'rss_reconcile.wake(uuid,text,text)'::regprocedure,'rss_reconcile.claim_due(uuid,text,integer,bigint)'::regprocedure,'rss_reconcile.lock_claim(uuid,text,text,uuid,bigint)'::regprocedure,'rss_reconcile.renew(uuid,text,text,uuid,bigint,bigint)'::regprocedure,'rss_reconcile.finish(uuid,text,text,uuid,bigint,bigint,text,bigint,bigint)'::regprocedure,'rss_reconcile.release(uuid,text,text,uuid,bigint)'::regprocedure,'rss_reconcile.mark_applied(uuid,text,text,uuid,bigint)'::regprocedure,'rss_transactional_messaging.check_execution()'::regprocedure,'rss_transactional_messaging.prepare_outbox_partitions(jsonb)'::regprocedure,'rss_transactional_messaging.append_outbox(bytea,jsonb)'::regprocedure) AND has_function_privilege(current_user,p.oid,'EXECUTE'))
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind='S' AND n.nspname NOT LIKE 'pg_%' AND has_sequence_privilege(current_user,c.oid,'SELECT,USAGE,UPDATE'))
 AND NOT EXISTS(SELECT 1 FROM tables t,LATERAL aclexplode(coalesce(t.relacl,acldefault('r',t.relowner))) a WHERE a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable))
 AND NOT EXISTS(SELECT 1 FROM tables t JOIN pg_attribute c ON c.attrelid=t.oid,LATERAL aclexplode(c.attacl) a WHERE a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable))

 AND EXISTS(SELECT 1 FROM pg_class c WHERE c.oid='mdm.manual_assignments'::regclass AND c.relrowsecurity AND c.relforcerowsecurity AND c.relowner NOT IN(SELECT oid FROM reachable)

 AND (SELECT jsonb_agg(jsonb_build_array(attname,format_type(atttypid,atttypmod),attnotnull) ORDER BY attnum)
 FROM pg_attribute WHERE attrelid=c.oid AND attnum>0 AND NOT attisdropped)='[["tenant_id","uuid",true],["device","text",true],["field","text",true],["revision","bigint",true],["fact","jsonb",true]]'::jsonb
 AND (SELECT count(*)=3 AND bool_and(convalidated AND pg_get_constraintdef(oid)=CASE conname
 WHEN 'manual_assignments_field_check' THEN 'CHECK ((field = ANY (ARRAY[''custom.asset_tag''::text, ''custom.office_floor''::text, ''custom.is_loaner''::text, ''custom.purchase_date''::text])))'
 WHEN 'manual_assignments_revision_check' THEN 'CHECK ((revision > 0))'
 WHEN 'manual_assignments_fact_check' THEN 'CHECK ((octet_length((fact)::text) <= 4096))' ELSE '' END)
 FROM pg_constraint WHERE conrelid=c.oid AND contype='c')
 AND has_table_privilege(current_user,c.oid,'SELECT') AND has_table_privilege(current_user,c.oid,'INSERT')
 AND NOT has_table_privilege(current_user,c.oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
 AND has_column_privilege(current_user,c.oid,'revision','UPDATE') AND has_column_privilege(current_user,c.oid,'fact','UPDATE')
 AND (SELECT count(*) FROM pg_policy WHERE polrelid=c.oid)=1
 AND EXISTS(SELECT 1 FROM pg_policy p WHERE p.polrelid=c.oid AND p.polname='tenant' AND p.polcmd='*' AND p.polpermissive AND p.polroles=ARRAY[0::oid]
 AND lower(replace(regexp_replace(pg_get_expr(p.polqual,p.polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'
 AND pg_get_expr(p.polqual,p.polrelid)=pg_get_expr(p.polwithcheck,p.polrelid))
 AND EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=c.oid AND contype='p' AND convalidated AND pg_get_constraintdef(oid)='PRIMARY KEY (tenant_id, device, field)')
 AND NOT EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped AND (has_column_privilege(current_user,c.oid,a.attnum,'UPDATE')<>(a.attname IN('revision','fact')) OR has_column_privilege(current_user,c.oid,a.attnum,'REFERENCES')))
 AND NOT EXISTS(SELECT 1 FROM aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a WHERE a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable))
 AND NOT EXISTS(SELECT 1 FROM pg_attribute c,LATERAL aclexplode(c.attacl) a WHERE c.attrelid='mdm.manual_assignments'::regclass AND (a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable)))
 )

 AND EXISTS(SELECT 1 FROM pg_class c WHERE c.oid='mdm_access.credentials'::regclass
 AND c.relrowsecurity AND c.relforcerowsecurity AND c.relowner NOT IN(SELECT oid FROM reachable)
 AND NOT has_table_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
 AND NOT has_any_column_privilege(current_user,c.oid,'INSERT,UPDATE,REFERENCES')
 AND NOT EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped
 AND has_column_privilege(current_user,c.oid,a.attnum,'SELECT')<>(a.attname IN('tenant_id','registration','state'))))
