-- Policy accepts intents and observes their original progress; protocol workers remain Command-owned.
WITH reachable AS (
 SELECT r.* FROM pg_roles r WHERE r.rolname=current_user OR pg_has_role(session_user,r.oid,'MEMBER')
), required(relation,insertable,deletable) AS (VALUES
 ('mdm_access.agent_bootstraps',true,false),('mdm_commands.devices',true,false),('mdm_commands.operations',true,false),
 ('mdm_commands.requests',true,false),('mdm_commands.action_runs',true,false),
 ('mdm_commands.action_receipts',true,false),('mdm_commands.policy_recovery',true,false),
 ('mdm_planning.configuration_claims',true,true),('mdm_planning.configuration_devices',true,false),
 ('mdm_planning.configuration_objects',true,false),('mdm_flow.native_protection',true,false),
 ('mdm_agent.bindings',false,false),('mdm_access.device_access_bindings',false,false),
 ('mdm_access.requests',false,false)
), updates(relation,col) AS (VALUES
 ('mdm_access.agent_bootstraps','active'),('mdm_access.agent_bootstraps','cleanup'),('mdm_access.agent_bootstraps','cleanup_complete'),('mdm_access.agent_bootstraps','cleanup_retry_at'),('mdm_commands.devices','generation'),('mdm_commands.devices','epoch'),('mdm_commands.devices','registration'),('mdm_commands.devices','registration_generation'),('mdm_commands.devices','recovery_after'),
 ('mdm_commands.operations','authority'),('mdm_commands.operations','revision'),('mdm_commands.operations','request'),
 ('mdm_commands.action_runs','access_binding'),('mdm_commands.action_runs','state'),('mdm_commands.action_runs','result'),('mdm_commands.action_runs','invocation'),('mdm_commands.action_runs','source_objects'),('mdm_commands.action_runs','software_effect'),
 ('mdm_commands.policy_recovery','input_revision'),
 ('mdm_planning.configuration_claims','version'),('mdm_planning.configuration_claims','operation'),
 ('mdm_planning.configuration_devices','input_revision'),('mdm_planning.configuration_devices','observed_revision'),
 ('mdm_planning.configuration_objects','operation'),('mdm_planning.configuration_objects','digest'),('mdm_planning.configuration_objects','diagnosis'),
 ('mdm_agent.bindings','execution_context'),
 ('mdm_access.device_access_bindings','instance'),('mdm_access.device_access_bindings','principal'),('mdm_access.device_access_bindings','generation'),('mdm_access.device_access_bindings','revision'),('mdm_access.device_access_bindings','state'),('mdm_access.device_access_bindings','account'),('mdm_access.device_access_bindings','document')
)
SELECT current_setting('transaction_isolation')='read committed'
 AND NOT pg_has_role(current_user,'mdm_command_runtime','MEMBER')
 AND NOT EXISTS(SELECT FROM reachable WHERE rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication)
 AND NOT EXISTS(SELECT FROM required r LEFT JOIN pg_class c ON c.oid=to_regclass(r.relation)
 WHERE c.oid IS NULL OR c.relkind<>'r' OR NOT c.relrowsecurity OR NOT c.relforcerowsecurity
 OR c.relowner IN(SELECT oid FROM reachable)
 OR has_table_privilege(current_user,c.oid,'SELECT')<>(r.relation<>'mdm_access.requests')
 OR has_table_privilege(current_user,c.oid,'INSERT')<>r.insertable
 OR has_table_privilege(current_user,c.oid,'DELETE')<>r.deletable
 OR has_table_privilege(current_user,c.oid,'UPDATE,TRUNCATE,REFERENCES,TRIGGER')
 OR (SELECT count(*) FROM pg_policy WHERE polrelid=c.oid)<>1
 OR NOT EXISTS(SELECT FROM pg_policy p WHERE p.polrelid=c.oid AND p.polname='tenant' AND p.polcmd='*' AND p.polpermissive AND p.polroles=ARRAY[0::oid]
 AND lower(replace(regexp_replace(pg_get_expr(p.polqual,p.polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'
 AND pg_get_expr(p.polqual,p.polrelid)=pg_get_expr(p.polwithcheck,p.polrelid)))
 AND NOT EXISTS(SELECT FROM required r JOIN pg_attribute a ON a.attrelid=to_regclass(r.relation) AND a.attnum>0 AND NOT a.attisdropped
 WHERE has_column_privilege(current_user,a.attrelid,a.attnum,'UPDATE')<>EXISTS(SELECT FROM updates u WHERE u.relation=r.relation AND u.col=a.attname)
 OR has_column_privilege(current_user,a.attrelid,a.attnum,'REFERENCES')
 OR (r.relation='mdm_access.requests' AND (
   has_column_privilege(current_user,a.attrelid,a.attnum,'SELECT')<>(a.attname IN ('tenant_id','id','source','windows_profile'))
   OR has_column_privilege(current_user,a.attrelid,a.attnum,'INSERT'))))
 AND NOT EXISTS(SELECT FROM required r JOIN pg_class c ON c.oid=to_regclass(r.relation),LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
 WHERE a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable))
 AND NOT EXISTS(SELECT FROM required r JOIN pg_attribute col ON col.attrelid=to_regclass(r.relation),LATERAL aclexplode(col.attacl) a
 WHERE a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable))
 AND NOT EXISTS(SELECT FROM (VALUES('mdm_commands.attempts'),('mdm_commands.attempt_items'),('mdm_commands.attempt_frames'),('mdm_commands.action_attempts'),('mdm_commands.action_polls')) worker(relation),reachable r
 WHERE has_table_privilege(r.oid,worker.relation,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege(r.oid,worker.relation,'INSERT,UPDATE,REFERENCES'))

 AND (
-- Exact host authority for borrowed execution handoff and current authorization.
WITH capabilities(name,append) AS (VALUES
 ('mdm_access.authorization_rules',false),('mdm_access.user_groups',false),('mdm_access.api_keys',false)
), objects AS (
 SELECT name,append,to_regclass(name) AS oid FROM capabilities
), reachable AS (
 SELECT oid FROM pg_roles WHERE rolname=current_user OR pg_has_role(current_user,oid,'MEMBER')
)
SELECT
 (SELECT count(*)=3 AND bool_and(o.oid IS NOT NULL AND c.relkind='r' AND c.relrowsecurity AND c.relforcerowsecurity
  AND has_schema_privilege(current_user,c.relnamespace,'USAGE')
  AND has_table_privilege(current_user,c.oid,'SELECT')
  AND (NOT o.append OR has_table_privilege(current_user,c.oid,'INSERT')))
  FROM objects o LEFT JOIN pg_class c ON c.oid=o.oid)
 AND NOT EXISTS(SELECT 1 FROM objects o JOIN pg_class c ON c.oid=o.oid CROSS JOIN reachable r
  WHERE c.relowner=r.oid
   OR has_table_privilege(r.oid,c.oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
   OR has_any_column_privilege(r.oid,c.oid,'UPDATE,REFERENCES')
   OR (NOT o.append AND (has_table_privilege(r.oid,c.oid,'INSERT') OR has_any_column_privilege(r.oid,c.oid,'INSERT'))))
 AND NOT EXISTS(SELECT 1 FROM objects o JOIN pg_class c ON c.oid=o.oid,
  LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
  WHERE a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable)
   AND (a.is_grantable OR a.privilege_type NOT IN('SELECT','INSERT') OR (a.privilege_type='INSERT' AND NOT o.append))))
 AND NOT EXISTS(SELECT 1 FROM objects o JOIN pg_attribute c ON c.attrelid=o.oid,
  LATERAL aclexplode(c.attacl) a WHERE a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable)
   AND (a.is_grantable OR a.privilege_type NOT IN('SELECT','INSERT') OR (a.privilege_type='INSERT' AND NOT o.append))))

)
