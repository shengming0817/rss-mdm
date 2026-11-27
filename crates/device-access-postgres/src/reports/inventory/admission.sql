-- Check effective privileges for both product consumers. Provider admission checks its own schema.
WITH worker AS (SELECT * FROM pg_roles WHERE rolname=current_user),
assets AS (SELECT 'rss_da.inventory_assets'::regclass AS oid),
history AS (SELECT 'rss_da.report_history'::regclass AS oid),
columns AS (
    SELECT a.attrelid,a.attname,a.attnum FROM pg_attribute a,assets,history
    WHERE a.attrelid IN (assets.oid,history.oid) AND a.attnum>0 AND NOT a.attisdropped
)
SELECT current_user='da_report_projection' AND current_user=session_user
  AND NOT EXISTS (SELECT FROM worker WHERE rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication)
  AND NOT EXISTS (SELECT FROM pg_auth_members m,worker w WHERE m.member=w.oid OR m.roleid=w.oid)
  AND has_schema_privilege(current_user,'rss_da','USAGE')
  AND NOT has_schema_privilege(current_user,'rss_da','CREATE')
  AND has_function_privilege(current_user,'rss_transactional_messaging.check_execution()','EXECUTE')
  AND NOT EXISTS (SELECT FROM pg_proc p WHERE p.pronamespace='rss_da'::regnamespace AND has_function_privilege(current_user,p.oid,'EXECUTE'))
  AND NOT EXISTS (SELECT FROM pg_class r,assets,history WHERE r.relnamespace='rss_da'::regnamespace
       AND r.relkind IN ('r','v','p') AND r.oid NOT IN (assets.oid,history.oid)
       AND (has_any_column_privilege(current_user,r.oid,'SELECT,INSERT,UPDATE,REFERENCES') OR has_table_privilege(current_user,r.oid,'DELETE,TRUNCATE,TRIGGER')))
  AND has_table_privilege(current_user,assets.oid,'SELECT') AND has_table_privilege(current_user,assets.oid,'INSERT')
  AND has_table_privilege(current_user,history.oid,'SELECT') AND NOT has_any_column_privilege(current_user,history.oid,'INSERT')
  AND NOT EXISTS (SELECT FROM columns c WHERE
      has_column_privilege(current_user,c.attrelid,c.attnum,'UPDATE') IS DISTINCT FROM
      (CASE WHEN c.attrelid=history.oid THEN c.attname='delivery_pending' ELSE c.attname IN ('sequence','position','received_at','facts') END)
      OR has_column_privilege(current_user,c.attrelid,c.attnum,'REFERENCES'))
  AND NOT has_table_privilege(current_user,assets.oid,'UPDATE,DELETE,TRUNCATE,TRIGGER,MAINTAIN')
  AND NOT has_table_privilege(current_user,history.oid,'UPDATE,DELETE,TRUNCATE,TRIGGER,MAINTAIN')
  AND has_table_privilege('da_identity_runtime',assets.oid,'SELECT')
  AND NOT has_any_column_privilege('da_identity_runtime',assets.oid,'INSERT,UPDATE,REFERENCES')
  AND NOT has_table_privilege('da_identity_runtime',assets.oid,'DELETE,TRUNCATE,TRIGGER,MAINTAIN')
  AND (SELECT relrowsecurity AND relforcerowsecurity AND relowner<>current_user::regrole FROM pg_class WHERE oid=assets.oid)
  AND (SELECT count(*)=1 AND bool_and(polcmd='*' AND polpermissive AND polroles=ARRAY[0::oid] AND
    replace(lower(regexp_replace(pg_get_expr(polqual,polrelid),'[[:space:]()]','','g')),'::text','')='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'
    AND pg_get_expr(polqual,polrelid)=pg_get_expr(polwithcheck,polrelid)) FROM pg_policy WHERE polrelid=assets.oid)
FROM assets,history