SELECT NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='mdm_automation' AND c.relkind='r' AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity OR c.relowner=(SELECT oid FROM pg_roles WHERE rolname=current_user)))
AND to_regclass('mdm_automation.inventory_evaluations') IS NOT NULL
AND to_regclass('mdm_automation.inventory_evaluation_arrays') IS NOT NULL
AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['mdm_automation.inventory_evaluations','mdm_automation.inventory_evaluation_arrays']) t(name) CROSS JOIN unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE']) p(privilege) WHERE NOT has_table_privilege(current_user,t.name,p.privilege))
