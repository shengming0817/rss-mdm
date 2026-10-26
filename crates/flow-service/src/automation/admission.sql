SELECT NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='mdm_automation' AND c.relkind='r' AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity OR c.relowner=(SELECT oid FROM pg_roles WHERE rolname=current_user)))
-- This contract is also inspected by the management host, which does not own
-- automation schema access. Resolve through pg_catalog and check the actual worker.
AND NOT EXISTS(
 SELECT 1 FROM unnest(ARRAY['inventory_evaluations','inventory_evaluation_arrays']) expected(name)
 LEFT JOIN (pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace AND n.nspname='mdm_automation') ON c.relname=expected.name
 CROSS JOIN unnest(ARRAY['SELECT','INSERT','DELETE']) p(privilege)
 WHERE c.oid IS NULL OR NOT has_table_privilege('mdm_flow_runtime',c.oid,p.privilege)
)
AND NOT EXISTS(
 SELECT 1 FROM (VALUES('inventory_evaluations','binding'),('inventory_evaluation_arrays','state')) expected(name,column_name)
 LEFT JOIN (pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace AND n.nspname='mdm_automation') ON c.relname=expected.name
 WHERE c.oid IS NULL OR NOT has_column_privilege('mdm_flow_runtime',c.oid,expected.column_name,'UPDATE')
)
