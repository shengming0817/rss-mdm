-- Configuration participates in the initiating Policy or Command transaction.
WITH reachable AS (
 SELECT r.* FROM pg_roles r WHERE r.rolname=current_user OR pg_has_role(session_user,r.oid,'MEMBER')
), required(relation,insertable,deletable) AS (VALUES
 ('mdm_planning.configuration_claims',true,true),
 ('mdm_planning.configuration_devices',true,false),
 ('mdm_planning.configuration_objects',true,false),
 ('mdm_planning.configuration_operations',true,false),
 ('mdm_planning.configuration_receipts',true,false),
 ('mdm_planning.configuration_recovery',true,false),
 ('mdm_apple.native_commands',true,false),
 ('mdm_windows.native_commands',true,false),
 ('mdm_access.command_authorities',true,false),
 ('mdm_flow.native_protection',true,false)
), updates(relation,col) AS (VALUES
 ('mdm_planning.configuration_claims','version'),
 ('mdm_planning.configuration_claims','operation'),
 ('mdm_planning.configuration_devices','input_revision'),
 ('mdm_planning.configuration_devices','observed_revision'),
 ('mdm_planning.configuration_objects','operation'),
 ('mdm_planning.configuration_objects','digest'),
 ('mdm_planning.configuration_objects','diagnosis'),
 ('mdm_planning.configuration_operations','dispatch_failure'),
 ('mdm_planning.configuration_operations','gateway_accepted'),
 ('mdm_planning.configuration_operations','revision'),
 ('mdm_planning.configuration_operations','observed_command_version'),
 ('mdm_planning.configuration_recovery','authority_epoch'),
 ('mdm_planning.configuration_recovery','recovery_after'),
 ('mdm_access.command_authorities','epoch'),
 ('mdm_access.command_authorities','registration'),
 ('mdm_access.command_authorities','registration_generation')
)
SELECT current_setting('transaction_isolation')='read committed'
 AND current_user IN('mdm_policy_runtime','mdm_command_runtime') AND session_user=current_user
 AND NOT EXISTS(SELECT FROM pg_auth_members WHERE member=(SELECT oid FROM pg_roles WHERE rolname=current_user))
 AND NOT EXISTS(SELECT FROM reachable WHERE rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication)
 AND NOT EXISTS(SELECT FROM required r LEFT JOIN pg_class c ON c.oid=to_regclass(r.relation)
 WHERE c.oid IS NULL OR c.relkind<>'r' OR NOT c.relrowsecurity OR NOT c.relforcerowsecurity
 OR c.relowner IN(SELECT oid FROM reachable)
 OR NOT has_schema_privilege(current_user,c.relnamespace,'USAGE')
 OR NOT has_table_privilege(current_user,c.oid,'SELECT')
 OR has_table_privilege(current_user,c.oid,'INSERT')<>r.insertable
 OR has_table_privilege(current_user,c.oid,'DELETE')<>r.deletable
 OR has_table_privilege(current_user,c.oid,'UPDATE,TRUNCATE,REFERENCES,TRIGGER')
 OR (SELECT count(*) FROM pg_policy WHERE polrelid=c.oid)<>1
 OR NOT EXISTS(SELECT FROM pg_policy p WHERE p.polrelid=c.oid AND p.polname='tenant' AND p.polcmd='*' AND p.polpermissive AND p.polroles=ARRAY[0::oid]
 AND lower(replace(regexp_replace(pg_get_expr(p.polqual,p.polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'
 AND pg_get_expr(p.polqual,p.polrelid)=pg_get_expr(p.polwithcheck,p.polrelid)))
 AND NOT EXISTS(SELECT FROM required r JOIN pg_attribute a ON a.attrelid=to_regclass(r.relation) AND a.attnum>0 AND NOT a.attisdropped
 WHERE has_column_privilege(current_user,a.attrelid,a.attnum,'UPDATE')<>EXISTS(SELECT FROM updates u WHERE u.relation=r.relation AND u.col=a.attname)
 OR has_column_privilege(current_user,a.attrelid,a.attnum,'REFERENCES'))
 AND NOT EXISTS(SELECT FROM required r JOIN pg_class c ON c.oid=to_regclass(r.relation),LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
 WHERE a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable))
 AND NOT EXISTS(SELECT FROM required r JOIN pg_attribute col ON col.attrelid=to_regclass(r.relation),LATERAL aclexplode(col.attacl) a
 WHERE a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable));
