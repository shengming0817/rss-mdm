WITH tables AS (SELECT c.* FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='mdm_telemetry' AND c.relkind='r'),
execution_roles AS (SELECT oid FROM pg_roles WHERE rolname=current_user OR pg_has_role(session_user,oid,'SET')),
reachable AS (SELECT r.* FROM pg_roles r WHERE EXISTS(SELECT 1 FROM execution_roles e WHERE pg_has_role(e.oid,r.oid,'USAGE'))),
trust_tables AS (
 SELECT c.*,expected.columns FROM (VALUES
  ('mdm_task_signing.heads',ARRAY['tenant_id','revision']),
  ('mdm_task_signing.versions',ARRAY['tenant_id','revision','body','digest']),
  ('mdm_task_signing.acknowledgements',ARRAY['tenant_id','registration','generation','revision','digest'])
 ) expected(name,columns) JOIN pg_class c ON c.oid=expected.name::regclass
), collection_columns AS (SELECT
 ARRAY['tenant_id','registration','source','epoch','id','scope','sequence','started_at','sealed_at','attempts','result','reason','batch','digest','input_digest'] AS reads,
 ARRAY['tenant_id','registration','source','epoch','id','scope','sequence','started_at','sealed_at','attempts','result','reason','batch','digest','input_digest','delivery_pending'] AS inserts
), isolated AS (SELECT oid FROM tables UNION SELECT oid FROM trust_tables UNION SELECT 'mdm_access.collection_runs'::regclass)
SELECT
 (SELECT array_agg(relname::text ORDER BY relname)=ARRAY['batches','definition_progress','gap_reports','maintenance','observation_receipts','rate_windows','resources','retention_targets','storage_binding'] FROM tables)
 AND NOT EXISTS(SELECT 1 FROM reachable WHERE rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication OR oid IN(SELECT relowner FROM tables))
 AND NOT EXISTS(SELECT 1 FROM tables t WHERE NOT relrowsecurity OR NOT relforcerowsecurity OR NOT has_table_privilege(current_user,t.oid,'SELECT') OR NOT has_table_privilege(current_user,t.oid,'INSERT')
 OR (has_table_privilege(current_user,t.oid,'DELETE')<>(t.relname='gap_reports'))
 OR EXISTS(SELECT 1 FROM reachable r WHERE has_table_privilege(r.oid,t.oid,'TRUNCATE,REFERENCES,TRIGGER') OR (t.relname<>'gap_reports' AND has_table_privilege(r.oid,t.oid,'DELETE')) OR (t.relname<>'rate_windows' AND has_table_privilege(r.oid,t.oid,'UPDATE'))))
 AND NOT EXISTS(SELECT 1 FROM tables t JOIN pg_attribute a ON a.attrelid=t.oid WHERE a.attnum>0 AND NOT a.attisdropped
 AND (has_column_privilege(current_user,t.oid,a.attnum,'UPDATE') <> (t.relname='rate_windows' OR (t.relname='batches' AND a.attname IN('delivery','current_assets')) OR (t.relname='maintenance' AND a.attname='result') OR (t.relname='definition_progress' AND a.attname IN('version','digest','retired_through')) OR (t.relname='retention_targets' AND a.attname IN('due_at','next_check','phase','result')))
 OR EXISTS(SELECT 1 FROM reachable r WHERE has_column_privilege(r.oid,t.oid,a.attnum,'REFERENCES') OR (has_column_privilege(r.oid,t.oid,a.attnum,'UPDATE') AND NOT (t.relname='rate_windows' OR (t.relname='batches' AND a.attname IN('delivery','current_assets')) OR (t.relname='maintenance' AND a.attname='result') OR (t.relname='definition_progress' AND a.attname IN('version','digest','retired_through')) OR (t.relname='retention_targets' AND a.attname IN('due_at','next_check','phase','result')))))))
 AND NOT EXISTS(SELECT 1 FROM isolated t WHERE (SELECT count(*) FROM pg_policy p WHERE p.polrelid=t.oid)<>1 OR NOT EXISTS(SELECT 1 FROM pg_policy p WHERE p.polrelid=t.oid AND p.polname='tenant' AND p.polcmd='*' AND p.polpermissive AND p.polroles=ARRAY[0::oid]
 AND lower(replace(regexp_replace(pg_get_expr(p.polqual,p.polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'
 AND pg_get_expr(p.polqual,p.polrelid)=pg_get_expr(p.polwithcheck,p.polrelid)))
 AND NOT EXISTS(SELECT 1 FROM tables t,LATERAL aclexplode(coalesce(t.relacl,acldefault('r',t.relowner))) a WHERE a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable))
 AND NOT EXISTS(SELECT 1 FROM tables t JOIN pg_attribute c ON c.attrelid=t.oid,LATERAL aclexplode(c.attacl) a WHERE a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable))
 AND has_schema_privilege(current_user,'mdm_telemetry','USAGE')
 AND NOT has_schema_privilege(current_user,'mdm_telemetry','CREATE')

 AND NOT EXISTS(SELECT 1 FROM reachable r WHERE has_table_privilege(r.oid,'mdm_access.agent_issuances','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'))
 AND NOT EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid='mdm_access.agent_issuances'::regclass AND a.attnum>0 AND NOT a.attisdropped
 AND (has_column_privilege(current_user,a.attrelid,a.attnum,'SELECT')<>(a.attname IN('tenant_id','credential','not_after'))
 OR EXISTS(SELECT 1 FROM reachable r WHERE has_column_privilege(r.oid,a.attrelid,a.attnum,'INSERT,UPDATE,REFERENCES')
 OR (has_column_privilege(r.oid,a.attrelid,a.attnum,'SELECT') AND a.attname NOT IN('tenant_id','credential','not_after')))))

 AND NOT EXISTS(SELECT 1 FROM reachable r WHERE has_table_privilege(r.oid,'mdm_commands.action_polls','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'))
 AND NOT EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid='mdm_commands.action_polls'::regclass AND a.attnum>0 AND NOT a.attisdropped
 AND (has_column_privilege(current_user,a.attrelid,a.attnum,'SELECT')<>(a.attname IN('tenant_id','registration','profiles'))
 OR EXISTS(SELECT 1 FROM reachable r WHERE has_column_privilege(r.oid,a.attrelid,a.attnum,'INSERT,UPDATE,REFERENCES')
 OR (has_column_privilege(r.oid,a.attrelid,a.attnum,'SELECT') AND a.attname NOT IN('tenant_id','registration','profiles')))))

 AND has_schema_privilege(current_user,'mdm_task_signing','USAGE')
 AND NOT EXISTS(SELECT 1 FROM reachable r WHERE has_schema_privilege(r.oid,'mdm_task_signing','CREATE'))
 AND NOT EXISTS(SELECT 1 FROM trust_tables t WHERE NOT relrowsecurity OR NOT relforcerowsecurity)
 AND NOT EXISTS(SELECT 1 FROM trust_tables t CROSS JOIN reachable r
  WHERE has_table_privilege(r.oid,t.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'))
 AND NOT EXISTS(SELECT 1 FROM trust_tables t JOIN pg_attribute a ON a.attrelid=t.oid
  WHERE a.attnum>0 AND NOT a.attisdropped AND (
   has_column_privilege(current_user,t.oid,a.attnum,'SELECT')<>(a.attname=ANY(t.columns))
   OR EXISTS(SELECT 1 FROM reachable r WHERE has_column_privilege(r.oid,t.oid,a.attnum,'INSERT,UPDATE,REFERENCES')
    OR (has_column_privilege(r.oid,t.oid,a.attnum,'SELECT') AND NOT a.attname=ANY(t.columns)))))
 AND NOT EXISTS(SELECT 1 FROM reachable r
  WHERE has_table_privilege(r.oid,'mdm_task_signing.keys','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
  OR has_any_column_privilege(r.oid,'mdm_task_signing.keys','SELECT,INSERT,UPDATE,REFERENCES'))

 AND (SELECT relrowsecurity AND relforcerowsecurity FROM pg_class WHERE oid='mdm_access.collection_runs'::regclass)
 AND NOT EXISTS(SELECT 1 FROM reachable r WHERE has_table_privilege(r.oid,'mdm_access.collection_runs','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'))
 AND NOT EXISTS(SELECT 1 FROM pg_attribute a CROSS JOIN collection_columns c
  WHERE a.attrelid='mdm_access.collection_runs'::regclass AND a.attnum>0 AND NOT a.attisdropped AND (
   has_column_privilege(current_user,a.attrelid,a.attnum,'SELECT')<>(a.attname=ANY(c.reads))
   OR has_column_privilege(current_user,a.attrelid,a.attnum,'INSERT')<>(a.attname=ANY(c.inserts))
   OR EXISTS(SELECT 1 FROM reachable r WHERE has_column_privilege(r.oid,a.attrelid,a.attnum,'UPDATE,REFERENCES')
    OR (has_column_privilege(r.oid,a.attrelid,a.attnum,'SELECT') AND NOT a.attname=ANY(c.reads))
    OR (has_column_privilege(r.oid,a.attrelid,a.attnum,'INSERT') AND NOT a.attname=ANY(c.inserts)))))
