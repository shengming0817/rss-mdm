WITH owned(relation) AS(VALUES('mdm_access_tasks.runs'),('mdm_access_tasks.policy_recovery'))
SELECT current_user IN('mdm_command_runtime','mdm_policy_runtime') AND session_user=current_user
 AND current_setting('transaction_isolation')='read committed'
 AND NOT EXISTS(SELECT FROM owned o LEFT JOIN pg_class c ON c.oid=to_regclass(o.relation)
 WHERE c.oid IS NULL OR c.relkind<>'r' OR NOT c.relrowsecurity OR NOT c.relforcerowsecurity
 OR NOT has_table_privilege(current_user,c.oid,'SELECT,INSERT') OR has_table_privilege(current_user,c.oid,'DELETE,TRUNCATE,REFERENCES,TRIGGER')
 OR c.relowner=(SELECT oid FROM pg_roles WHERE rolname=current_user))
 AND has_column_privilege(current_user,'mdm_access_tasks.runs','state','UPDATE') AND has_column_privilege(current_user,'mdm_access_tasks.runs','result','UPDATE')
 AND has_column_privilege(current_user,'mdm_access_tasks.policy_recovery','input_revision','UPDATE')
