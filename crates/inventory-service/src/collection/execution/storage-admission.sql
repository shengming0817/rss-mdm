WITH expected(name) AS (VALUES ('mdm_inventory.collection_tasks'),('mdm_inventory.collection_admission'),('mdm_inventory.collection_output_chunks'),('mdm_inventory.collection_policy_recovery'),('mdm_inventory.collection_native_checkins')), tables AS (SELECT c.* FROM expected e JOIN pg_class c ON c.oid=to_regclass(e.name))
SELECT (SELECT count(*) FROM tables)=5 AND NOT EXISTS(
 SELECT FROM tables t WHERE t.relkind<>'r' OR t.relpersistence<>'p' OR NOT t.relrowsecurity OR NOT t.relforcerowsecurity
 OR t.relowner=(SELECT oid FROM pg_roles WHERE rolname=current_user)
 OR (SELECT count(*) FROM pg_policy p WHERE p.polrelid=t.oid)<>1
 OR NOT EXISTS(SELECT 1 FROM pg_policy p WHERE p.polrelid=t.oid AND p.polname='tenant'
 AND p.polcmd='*' AND p.polpermissive AND p.polroles=ARRAY[0::oid]
 AND lower(replace(regexp_replace(pg_get_expr(p.polqual,p.polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'
 AND pg_get_expr(p.polqual,p.polrelid)=pg_get_expr(p.polwithcheck,p.polrelid))
 OR EXISTS(SELECT FROM pg_trigger WHERE tgrelid=t.oid AND NOT tgisinternal)
 OR EXISTS(SELECT FROM pg_rewrite WHERE ev_class=t.oid))
 AND NOT EXISTS(SELECT 1 FROM pg_namespace n JOIN pg_roles r ON r.oid=n.nspowner WHERE n.nspname='mdm_inventory' AND (r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication))
