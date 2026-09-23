WITH tables AS (
 SELECT c.* FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='mdm_commands' AND c.relkind='r'
), update_columns(relation, col) AS (VALUES
 ('mdm_commands.firewall_owners','version'),('mdm_commands.firewall_owners','operation'),('mdm_commands.attempts','receipt_accepted'),('mdm_commands.attempts','status'),
 ('mdm_commands.attempts','value'),
 ('mdm_commands.attempts','received_at'),
 ('mdm_commands.capabilities','generation'),
 ('mdm_commands.capabilities','os_version'),
 ('mdm_commands.capabilities','edition'),
 ('mdm_commands.capabilities','session'),
 ('mdm_commands.capabilities','observed_at'),
 ('mdm_commands.capability_queries','os_version'),
 ('mdm_commands.capability_queries','edition'),
 ('mdm_commands.capability_queries','version_status'),
 ('mdm_commands.capability_queries','edition_status'),
 ('mdm_commands.devices','generation'),('mdm_commands.devices','epoch'),('mdm_commands.devices','registration'),('mdm_commands.devices','registration_generation'),('mdm_commands.devices','recovery_after'),
 ('mdm_commands.operations','approval'),('mdm_commands.operations','revision'),('mdm_commands.operations','gateway_accepted'),
 ('mdm_access.report_sources','next_sequence'),('mdm_access.report_sources','next_command'),('mdm_access.enrollment_certificates','server_nonce'),
 ('mdm_access.management_sessions','state'),('mdm_access.management_sessions','last_message'),('mdm_access.management_sessions','client_authenticated'),('mdm_access.management_sessions','correlation'),('mdm_access.management_sessions','nonce'),('mdm_access.management_sessions','run_id'),
 ('mdm_access.collection_runs','attempts'),('mdm_access.collection_runs','result'),('mdm_access.collection_runs','reason'),('mdm_access.collection_runs','batch'),('mdm_access.collection_runs','digest'),('mdm_access.collection_runs','sealed_at'),('mdm_access.collection_runs','delivery_pending')
,
 ('mdm_apple.attempts','state'),('mdm_apple.attempts','response'),('mdm_apple.attempts','response_digest'),('mdm_apple.attempts','received_at'),('mdm_apple.attempts','next_attempt'),
 ('mdm_apple.profiles','profile'),('mdm_apple.profiles','operation'),('mdm_apple.profiles','registration'),('mdm_apple.profiles','version'),('mdm_apple.profiles','enabled'),
 ('mdm_apple.devices','token'),('mdm_apple.devices','magic'),('mdm_apple.devices','state'),('mdm_apple.devices','push_id'),('mdm_apple.devices','push_lease_until'),('mdm_apple.devices','next_push'),('mdm_apple.devices','push_status'),('mdm_apple.devices','push_outcome'),('mdm_apple.devices','push_configuration'),('mdm_apple.devices','push_failures')
), allowed(relation,sel,ins,del) AS (VALUES
 ('mdm_apple.attempts',true,true,false),('mdm_apple.profiles',true,true,false),('mdm_apple.devices',true,false,false),('mdm_access.requests',true,false,false),
('mdm_commands.firewall_owners',true,true,true),('mdm_commands.attempt_history',true,false,false),
('mdm_commands.capabilities',true,true,false),
('mdm_commands.capability_queries',true,true,false),
('mdm_commands.plan_executions',true,true,false),
 ('mdm_commands.devices',true,true,false),('mdm_commands.operations',true,true,false),('mdm_commands.requests',true,true,false),('mdm_commands.attempts',true,true,false),
 ('mdm_access.devices',true,false,false),('mdm_access.registrations',true,false,false),('mdm_access.credentials',true,false,false),('mdm_access.report_sources',true,false,false),('mdm_access.enrollment_intents',true,false,false),('mdm_access.enrollment_certificates',true,false,false),('mdm_access.authorization_rules',true,false,false),('mdm_access.user_groups',true,false,false),
 ('mdm_access.management_sessions',true,true,false),('mdm_access.management_messages',true,true,false),('mdm_access.collection_runs',true,true,false),('mdm_access.audit',false,true,false),
 ('rss_device_command.commands',true,false,false),('rss_device_command.authorities',true,false,false),
 ('rss_reconcile.targets',true,false,false),
 ('rss_transactional_messaging.policy',true,false,false),('rss_transactional_messaging.outbox',true,false,false),('rss_transactional_messaging.inbox',true,true,true)
)
SELECT current_user='mdm_command_runtime' AND session_user=current_user
 AND current_setting('transaction_isolation')='read committed'
 AND NOT EXISTS(SELECT 1 FROM pg_namespace n JOIN pg_roles r ON r.oid=n.nspowner
  WHERE n.nspname IN('mdm_access','mdm_commands','rss_device_command','rss_reconcile')
   AND (r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication))
 AND NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND (rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication))
 AND NOT EXISTS(SELECT 1 FROM pg_auth_members WHERE member=(SELECT oid FROM pg_roles WHERE rolname=current_user) OR roleid=(SELECT oid FROM pg_roles WHERE rolname=current_user))
 AND NOT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname NOT LIKE 'pg_temp_%' AND has_schema_privilege(current_user,oid,'CREATE'))
 AND NOT has_database_privilege(current_user,current_database(),'CREATE')
 AND (SELECT array_agg(relname::text ORDER BY relname)=ARRAY['attempt_history','attempts','capabilities','capability_queries','devices','firewall_owners','operations','plan_executions','requests'] FROM tables)
 AND NOT EXISTS(SELECT 1 FROM tables t WHERE relkind<>'r' OR relpersistence<>'p' OR NOT relrowsecurity OR NOT relforcerowsecurity OR relowner=(SELECT oid FROM pg_roles WHERE rolname=current_user)
  OR (SELECT count(*) FROM pg_policy WHERE polrelid=t.oid)<>1
  OR NOT EXISTS(SELECT 1 FROM pg_policy WHERE polrelid=t.oid AND polname='tenant' AND polcmd='*' AND polpermissive AND polroles=ARRAY[0::oid]
   AND lower(replace(regexp_replace(pg_get_expr(polqual,polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'
   AND pg_get_expr(polqual,polrelid)=pg_get_expr(polwithcheck,polrelid)))
 AND NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid IN(SELECT oid FROM tables) AND NOT tgisinternal)
 AND NOT EXISTS(SELECT 1 FROM pg_rewrite WHERE ev_class IN(SELECT oid FROM tables))
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace LEFT JOIN allowed a ON a.relation=n.nspname||'.'||c.relname
  WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema' AND c.relkind IN('r','v','m','f')
  AND (has_table_privilege(current_user,c.oid,'SELECT')<>coalesce(a.sel,false)
   OR has_table_privilege(current_user,c.oid,'INSERT')<>coalesce(a.ins,false)
   OR has_table_privilege(current_user,c.oid,'DELETE')<>coalesce(a.del,false)
   OR has_table_privilege(current_user,c.oid,'TRUNCATE,REFERENCES,TRIGGER')
   OR (has_table_privilege(current_user,c.oid,'UPDATE') AND a.relation IS DISTINCT FROM 'rss_transactional_messaging.inbox')))
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_attribute a ON a.attrelid=c.oid
  WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema' AND c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped
  AND has_column_privilege(current_user,c.oid,a.attnum,'UPDATE')<>(n.nspname||'.'||c.relname='rss_transactional_messaging.inbox' OR EXISTS(SELECT 1 FROM update_columns u WHERE u.relation=n.nspname||'.'||c.relname AND u.col=a.attname)))

 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_attribute col ON col.attrelid=c.oid LEFT JOIN allowed a ON a.relation=n.nspname||'.'||c.relname
  WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema' AND c.relkind IN('r','v','m','f') AND col.attnum>0 AND NOT col.attisdropped
  AND (has_column_privilege(current_user,c.oid,col.attnum,'SELECT')<>coalesce(a.sel,false)
    OR has_column_privilege(current_user,c.oid,col.attnum,'INSERT')<>coalesce(a.ins,false)
    OR has_column_privilege(current_user,c.oid,col.attnum,'REFERENCES')))
 AND NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
  WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname NOT IN('information_schema','rss_device_command','rss_reconcile')
  AND p.oid NOT IN('mdm_management.plan_execution_admission(uuid)'::regprocedure,'rss_transactional_messaging.check_execution()'::regprocedure,'rss_transactional_messaging.prepare_outbox_partitions(jsonb)'::regprocedure,'rss_transactional_messaging.append_outbox(bytea,jsonb)'::regprocedure,'rss_transactional_messaging.claim_outbox(uuid,text,integer,bigint)'::regprocedure,'rss_transactional_messaging.outbox_lease(uuid,bigint,uuid,bigint,bigint,uuid)'::regprocedure,'rss_transactional_messaging.settle_outbox(uuid,bigint,uuid,bigint,text,uuid)'::regprocedure)
  AND has_function_privilege(current_user,p.oid,'EXECUTE'))
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind='S' AND n.nspname NOT LIKE 'pg_%' AND has_sequence_privilege(current_user,c.oid,'SELECT,USAGE,UPDATE'))
