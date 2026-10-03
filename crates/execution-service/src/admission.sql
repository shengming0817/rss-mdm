WITH tables AS (
 SELECT c.* FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='mdm_commands' AND c.relkind='r'
), update_columns(relation, col) AS (VALUES
 ('mdm_windows.collections','channel_state'),
 ('mdm_windows.push_channels','generation'),('mdm_windows.push_channels','revision'),('mdm_windows.push_channels','configuration'),('mdm_windows.push_channels','uri'),('mdm_windows.push_channels','digest'),('mdm_windows.push_channels','expires_at'),('mdm_windows.push_channels','next_push'),('mdm_windows.push_channels','lease_id'),('mdm_windows.push_channels','lease_until'),('mdm_windows.push_channels','settled_id'),('mdm_windows.push_channels','failures'),('mdm_windows.push_channels','status'),('mdm_windows.push_channels','outcome'),
 ('mdm_windows.push_queries','results'),
 ('mdm_agent.bindings','execution_context'),
 ('mdm_planning.remote_operations','cancelled'),('mdm_planning.remote_operations','staged'),('mdm_planning.remote_operations','cursor'),('mdm_planning.remote_operations','run_after'),
 ('mdm_commands.policy_recovery','target_after'),('mdm_commands.policy_recovery','recovery_after'),('mdm_commands.action_polls','policy_after'),
 ('mdm_planning.configuration_claims','version'),('mdm_planning.configuration_claims','operation'),
 ('mdm_planning.configuration_devices','input_revision'),('mdm_planning.configuration_devices','observed_revision'),('mdm_planning.configuration_objects','operation'),('mdm_planning.configuration_objects','digest'),('mdm_planning.configuration_objects','diagnosis'),
 ('mdm_commands.action_polls','cancellation_after'),('mdm_commands.action_runs','state'),('mdm_commands.action_runs','result'),('mdm_commands.action_runs','gateway_accepted'),('mdm_commands.action_attempts','permit'),
 ('mdm_commands.attempt_frames','status'),('mdm_commands.attempt_frames','accepted'),('mdm_commands.attempt_frames','received_at'),
 ('mdm_commands.attempt_items','receipt_accepted'),('mdm_commands.attempt_items','result_accepted'),('mdm_commands.attempt_items','result_received_at'),('mdm_commands.attempt_items','status'),
 ('mdm_commands.attempt_items','value'),
 ('mdm_commands.attempt_items','received_at'),
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
 ('mdm_commands.operations','dispatch_failure'),('mdm_commands.operations','approval'),('mdm_commands.operations','revision'),('mdm_commands.operations','gateway_accepted'),
 ('mdm_access.report_sources','next_sequence'),('mdm_access.report_sources','next_command'),('mdm_access.enrollment_certificates','server_nonce'),
 ('mdm_access.management_sessions','state'),('mdm_access.management_sessions','last_message'),('mdm_access.management_sessions','client_authenticated'),('mdm_access.management_sessions','nonce'),('mdm_access.management_sessions','run_id'),
 ('mdm_access.collection_runs','evidence'),('mdm_access.collection_runs','attempts'),('mdm_access.collection_runs','result'),('mdm_access.collection_runs','reason'),('mdm_access.collection_runs','batch'),('mdm_access.collection_runs','digest'),('mdm_access.collection_runs','sealed_at'),('mdm_access.collection_runs','delivery_pending')
,
 ('mdm_apple.attempts','native_outcome'),('mdm_apple.attempts','accepted'),('mdm_apple.attempts','state'),('mdm_apple.attempts','response'),('mdm_apple.attempts','response_digest'),('mdm_apple.attempts','received_at'),('mdm_apple.attempts','next_attempt'),
 ('mdm_apple.declarations','retired_at'),('mdm_apple.declarations','legacy_released_at'),('mdm_apple.declarations','projection'),('mdm_apple.profiles','manifest'),('mdm_apple.profiles','dispatched_at'),('mdm_apple.profiles','observed_at'),('mdm_apple.profiles','retired_at'),('mdm_apple.devices','state'),('mdm_apple.channels','state'),('mdm_apple.channels','material'),('mdm_apple.channels','material_digest'),('mdm_apple.channels','push_id'),('mdm_apple.channels','push_lease_until'),('mdm_apple.channels','next_push'),('mdm_apple.channels','push_status'),('mdm_apple.channels','push_outcome'),('mdm_apple.channels','push_configuration'),('mdm_apple.channels','push_failures')
), allowed(relation,sel,ins,del) AS (VALUES
 ('mdm_flow.native_protection',true,true,false),
 ('mdm.inventory',true,false,false),
 ('mdm.field_versions',true,false,false),('mdm.collection_definitions',true,true,false),('mdm.collection_results',true,true,false),
 ('mdm_software_composition.subjects',true,false,false),('mdm_software_composition.targets',true,false,false),('mdm_software_composition.projections',true,false,false),('mdm_software_release.aggregates',true,false,false),
 ('mdm_planning.operations',true,true,false),('mdm_planning.remote_operations',true,true,false),('mdm_planning.remote_operation_targets',true,true,false),('mdm_commands.policy_recovery',true,true,false),('mdm_policy.policies',true,false,false),('mdm_policy.versions',true,false,false),('mdm_policy.triggers',true,false,false),('mdm_planning.configuration_claims',true,true,true),('mdm_planning.configuration_devices',true,true,false),
 ('mdm_commands.output_chunks',true,true,false),('mdm_commands.action_polls',true,true,false),('mdm_commands.action_runs',true,true,false),('mdm_commands.action_receipts',true,true,false),('mdm_commands.action_attempts',true,true,false),('mdm_resource.aggregates',true,false,false),('mdm_resource.immutable',true,false,false),('mdm_agent.bindings',true,false,false),
 ('mdm_planning.scopes',true,false,false),('mdm_planning.scope_results',true,false,false),
 ('mdm_software.sources',true,false,false),('mdm_software.approvals',true,false,false),('mdm_software.materials',true,false,false),
 ('mdm_apple.declarations',true,true,false),('mdm_apple.status_reports',true,true,false),('mdm_apple.attempts',true,true,false),('mdm_apple.profiles',true,true,false),('mdm_apple.devices',true,false,false),('mdm_apple.channels',true,false,false),('mdm_access.requests',true,false,false),

('mdm_commands.capabilities',true,true,false),
('mdm_commands.capability_queries',true,true,false),

 ('mdm_commands.devices',true,true,false),('mdm_commands.operations',true,true,false),('mdm_commands.requests',true,true,false),('mdm_commands.attempts',true,true,false),('mdm_commands.attempt_items',true,true,false),('mdm_commands.attempt_frames',true,true,false),('mdm_planning.configuration_objects',true,true,false),
 ('mdm_access.devices',true,false,false),('mdm_access.registrations',true,false,false),('mdm_access.credentials',true,false,false),('mdm_access.report_sources',true,false,false),('mdm_access.enrollment_intents',true,false,false),('mdm_access.enrollment_certificates',true,false,false),('mdm_access.authorization_rules',true,false,false),('mdm_access.user_groups',true,false,false),
 ('mdm_access.management_sessions',true,true,false),('mdm_access.management_messages',true,true,false),('mdm_access.collection_runs',true,true,false),('mdm_windows.collections',true,true,false),('mdm_windows.push_channels',true,true,false),('mdm_windows.push_queries',true,true,false),('rss_audit.heads',true,false,false),('rss_audit.records',true,false,false),('rss_ledger.heads',true,false,false),('rss_ledger.entries',true,false,false),('mdm_audit.receipts',true,true,false),
 ('rss_device_command.commands',true,false,false),('rss_device_command.authorities',true,false,false),
 ('rss_reconcile.targets',true,false,false),
 ('rss_transactional_messaging.policy',true,false,false),('rss_transactional_messaging.outbox',true,false,false),('rss_transactional_messaging.inbox',true,true,true)
)
SELECT current_user='mdm_command_runtime' AND session_user=current_user
 AND has_schema_privilege(current_user,'mdm_flow','USAGE')
 AND current_setting('transaction_isolation')='read committed'
 AND NOT EXISTS(SELECT 1 FROM pg_namespace n JOIN pg_roles r ON r.oid=n.nspowner
  WHERE n.nspname IN('mdm_access','mdm_commands','mdm_resource','rss_device_command','rss_reconcile')
   AND (r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication))
 AND NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND (rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication))
 AND NOT EXISTS(SELECT 1 FROM pg_auth_members WHERE member=(SELECT oid FROM pg_roles WHERE rolname=current_user) OR roleid=(SELECT oid FROM pg_roles WHERE rolname=current_user))
 AND NOT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname NOT LIKE 'pg_temp_%' AND has_schema_privilege(current_user,oid,'CREATE'))
 AND NOT has_database_privilege(current_user,current_database(),'CREATE')
 AND (SELECT array_agg(relname::text ORDER BY relname)=ARRAY['action_attempts','action_polls','action_receipts','action_runs','attempt_frames','attempt_items','attempts','capabilities','capability_queries','devices','operations','output_chunks','policy_recovery','requests'] FROM tables)
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
  AND p.oid NOT IN('rss_audit.reserve(uuid)'::regprocedure,'rss_audit.append(uuid,text,text,bigint,bytea,bigint)'::regprocedure,'rss_ledger.prepare_append(uuid,text,text,smallint)'::regprocedure,'rss_ledger.insert_entry(uuid,text,text,bigint,bytea,bytea,bytea,text,smallint)'::regprocedure,'mdm_planning.scope_admission(uuid,text)'::regprocedure,'mdm_planning.policy_lock(uuid)'::regprocedure,'rss_transactional_messaging.check_execution()'::regprocedure,'rss_transactional_messaging.prepare_outbox_partitions(jsonb)'::regprocedure,'rss_transactional_messaging.append_outbox(bytea,jsonb)'::regprocedure,'rss_transactional_messaging.claim_outbox(uuid,text,integer,bigint)'::regprocedure,'rss_transactional_messaging.outbox_lease(uuid,bigint,uuid,bigint,bigint,uuid)'::regprocedure,'rss_transactional_messaging.settle_outbox(uuid,bigint,uuid,bigint,text,uuid)'::regprocedure)
  AND has_function_privilege(current_user,p.oid,'EXECUTE'))
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind='S' AND n.nspname NOT LIKE 'pg_%' AND has_sequence_privilege(current_user,c.oid,'SELECT,USAGE,UPDATE'))
