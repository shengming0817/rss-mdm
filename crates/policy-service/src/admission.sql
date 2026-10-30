SELECT NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='mdm_policy' AND c.relkind='r' AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity OR c.relowner=(SELECT oid FROM pg_roles WHERE rolname=current_user)))

 AND (SELECT relrowsecurity AND relforcerowsecurity FROM pg_class WHERE oid='mdm_access.collection_runs'::regclass)
 AND NOT has_table_privilege(current_user,'mdm_access.collection_runs','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
 AND NOT has_any_column_privilege(current_user,'mdm_access.collection_runs','INSERT,UPDATE,REFERENCES')
 AND NOT EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid='mdm_access.collection_runs'::regclass AND a.attnum>0 AND NOT a.attisdropped
  AND has_column_privilege(current_user,a.attrelid,a.attnum,'SELECT')<>(a.attname IN('tenant_id','scope','id','result','attempts','evidence','sequence','sealed_at')))
