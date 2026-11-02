WITH owned(relation) AS(VALUES('rss_da.access_runs'),('rss_da.access_policy_recovery'))
SELECT current_user IN('mdm_command_runtime','da_command_runtime') AND session_user=current_user
 AND current_setting('transaction_isolation')='read committed'
 AND NOT EXISTS(SELECT FROM owned o LEFT JOIN pg_class c ON c.oid=to_regclass(o.relation)
 WHERE c.oid IS NULL OR c.relkind<>'r' OR NOT c.relrowsecurity OR NOT c.relforcerowsecurity
 OR NOT has_table_privilege(current_user,c.oid,'SELECT,INSERT') OR has_table_privilege(current_user,c.oid,'DELETE,TRUNCATE,REFERENCES,TRIGGER')
 OR c.relowner=(SELECT oid FROM pg_roles WHERE rolname=current_user))
 AND has_column_privilege(current_user,'rss_da.access_runs','state','UPDATE') AND has_column_privilege(current_user,'rss_da.access_runs','result','UPDATE')
 AND has_column_privilege(current_user,'rss_da.access_policy_recovery','input_revision','UPDATE')
