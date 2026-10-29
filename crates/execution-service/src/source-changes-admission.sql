WITH expected_columns(name,type,required) AS (VALUES
 ('tenant_id','uuid',true),('consumed','bigint',true),('watermark','bigint',true),('cursor','text',false),
 ('relation_consumed','bigint',true),('relation_watermark','bigint',true),('relation_cursor','bigint',false),
 ('failure','text',false),('failure_generation','bigint',true)
), execution_roles AS (
 SELECT oid FROM pg_roles WHERE rolname=current_user OR pg_has_role(session_user,oid,'SET')
), reachable AS (
 SELECT r.* FROM pg_roles r WHERE EXISTS(SELECT 1 FROM execution_roles e WHERE pg_has_role(e.oid,r.oid,'USAGE'))
)
SELECT EXISTS(SELECT 1 FROM pg_class c WHERE c.oid=to_regclass('mdm_commands.device_source_dispatch')
 AND c.relkind='r' AND c.relrowsecurity AND c.relforcerowsecurity
 AND c.relowner NOT IN(SELECT oid FROM reachable)
 AND (SELECT count(*) FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped)=(SELECT count(*) FROM expected_columns)
 AND NOT EXISTS(SELECT 1 FROM expected_columns e LEFT JOIN pg_attribute a ON a.attrelid=c.oid AND a.attname=e.name AND a.attnum>0 AND NOT a.attisdropped
  WHERE a.attname IS NULL OR a.atttypid<>to_regtype(e.type) OR a.attnotnull<>e.required OR (e.name='cursor' AND a.attcollation<>'pg_catalog."C"'::regcollation))
 AND EXISTS(SELECT 1 FROM pg_constraint k WHERE k.conrelid=c.oid AND k.contype='p' AND k.convalidated AND NOT k.condeferrable
  AND k.conkey=ARRAY[(SELECT attnum FROM pg_attribute WHERE attrelid=c.oid AND attname='tenant_id')])
 AND has_table_privilege(current_user,c.oid,'SELECT') AND has_table_privilege(current_user,c.oid,'INSERT')
 AND NOT has_table_privilege(current_user,c.oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
 AND NOT EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped
  AND has_column_privilege(current_user,c.oid,a.attnum,'UPDATE')<>(a.attname IN('consumed','watermark','cursor','relation_consumed','relation_watermark','relation_cursor','failure','failure_generation')))
 AND (SELECT count(*) FROM pg_policy p WHERE p.polrelid=c.oid)=1
 AND EXISTS(SELECT 1 FROM pg_policy p WHERE p.polrelid=c.oid AND p.polname='tenant' AND p.polcmd='*' AND p.polpermissive AND p.polroles=ARRAY[0::oid]
  AND lower(replace(regexp_replace(pg_get_expr(p.polqual,p.polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'
  AND pg_get_expr(p.polqual,p.polrelid)=pg_get_expr(p.polwithcheck,p.polrelid)))
AND NOT EXISTS(SELECT 1 FROM reachable WHERE rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication)
AND NOT EXISTS(SELECT 1 FROM reachable r WHERE has_table_privilege(r.oid,'mdm_commands.device_source_dispatch','UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
 OR EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid='mdm_commands.device_source_dispatch'::regclass AND a.attnum>0 AND NOT a.attisdropped
  AND (has_column_privilege(r.oid,a.attrelid,a.attnum,'REFERENCES')
   OR (has_column_privilege(r.oid,a.attrelid,a.attnum,'UPDATE') AND a.attname NOT IN('consumed','watermark','cursor','relation_consumed','relation_watermark','relation_cursor','failure','failure_generation')))))
