WITH tables AS (
 SELECT c.* FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='mdm_commands' AND c.relkind='r'
), update_columns(relation, col) AS (VALUES
 ('mdm_access.devices','retirement'),
 ('mdm_planning.event_members','decision'),('mdm_automation.automation_jobs','completed'),('mdm_automation.automation_jobs','failure'),
 ('mdm_apple.psso_password_providers','revision'),('mdm_apple.psso_password_providers','fingerprint'),
 ('mdm_access.device_access_bindings','instance'),('mdm_access.device_access_bindings','principal'),('mdm_access.device_access_bindings','generation'),('mdm_access.device_access_bindings','revision'),('mdm_access.device_access_bindings','state'),('mdm_access.device_access_bindings','account'),('mdm_access.device_access_bindings','document'),('mdm_commands.action_runs','access_binding'),
 ('mdm_webhook.key_heads','revision'),('mdm_webhook.key_heads','active_revision'),('mdm_webhook.key_heads','retiring_revision'),('mdm_webhook.key_materials','revoked'),
 ('mdm_webhook.subscriptions','revision'),('mdm_webhook.subscriptions','target_version'),('mdm_webhook.subscriptions','enabled'),('mdm_webhook.subscriptions','deleted'),('mdm_webhook.subscriptions','settings'),('mdm_webhook.versions','retired'),('mdm_webhook.compliance_sources','cursor'),('mdm_webhook.compliance_sources','complete'),('mdm_webhook.fanout','cursor'),('mdm_webhook.fanout','complete'),('mdm_webhook.deliveries','attempts'),('mdm_webhook.deliveries','last_outcome'),('mdm_webhook.deliveries','last_stage'),('mdm_webhook.deliveries','last_reason'),
 ('mdm_devices.retirement_channels','blocking_execution'),('mdm_devices.retirement_channels','stage'),('mdm_devices.retirement_channels','effect'),('mdm_devices.retirement_channels','execution'),('mdm_devices.retirement_channels','reason'),
 ('mdm_recovery.filevault_sources','association'),('mdm_recovery.filevault_sources','association_version'),
 ('mdm_recovery.filevault_custodies','active'),('mdm_recovery.filevault_custodies','revision'),('mdm_recovery.filevault_custodies','enabled'),('mdm_recovery.filevault_custodies','recipient'),('mdm_recovery.filevault_sources','custody'),('mdm_recovery.filevault_sources','epoch'),('mdm_recovery.filevault_sources','active'),('mdm_recovery.native_actions','coordinates'),
 ('mdm_recovery.entries','revision'),('mdm_recovery.entries','current_version'),('mdm_recovery.entries','retired'),('mdm_recovery.versions','validity'),('mdm_recovery.versions','key_id'),('mdm_recovery.versions','sealed'),('mdm_recovery.versions','invalidated_at'),('mdm_recovery.versions','pending'),('mdm_recovery.versions','cleanup_checked_at'),
 ('mdm_recovery.native_actions','inputs_purged'),('mdm_commands.operations','request'),('mdm_apple.attempts','request'),
 ('mdm_access.agent_bootstraps','active'),('mdm_access.agent_bootstraps','cleanup'),('mdm_access.agent_bootstraps','cleanup_complete'),('mdm_access.agent_bootstraps','cleanup_retry_at'),
 ('mdm_pki.installations','revision'),('mdm_pki.installations','digest'),('mdm_pki.installations','body'),('mdm_pki.installations','confirmed_at'),
 ('mdm_pki.acknowledgements','revision'),('mdm_pki.acknowledgements','digest'),('mdm_pki.acknowledgements','confirmed_at'),
 ('mdm_windows.trust_deliveries','results'),('mdm_windows.trust_deliveries','confirmed'),
 ('mdm_windows.collections','channel_state'),('mdm_windows.collections','template_state'),
 ('mdm_windows.push_channels','generation'),('mdm_windows.push_channels','revision'),('mdm_windows.push_channels','configuration'),('mdm_windows.push_channels','uri'),('mdm_windows.push_channels','digest'),('mdm_windows.push_channels','expires_at'),('mdm_windows.push_channels','next_push'),('mdm_windows.push_channels','lease_id'),('mdm_windows.push_channels','lease_until'),('mdm_windows.push_channels','settled_id'),('mdm_windows.push_channels','failures'),('mdm_windows.push_channels','status'),('mdm_windows.push_channels','outcome'),
 ('mdm_windows.push_queries','results'),
 ('mdm_agent.bindings','execution_context'),

 ('mdm_commands.software_stage_stats','generation'),('mdm_commands.software_stage_stats','membership_complete'),('mdm_commands.software_stats_members','generation'),('mdm_commands.software_stats_members','target'),('mdm_commands.software_stats_members','counts'),('mdm_commands.software_stats_members','waiting_until'),('mdm_commands.software_stage_stats','input'),('mdm_commands.software_stage_stats','cursor'),('mdm_commands.software_stage_stats','ready'),('mdm_commands.software_stage_stats','counts'),('mdm_commands.policy_recovery','target_after'),('mdm_commands.policy_recovery','recovery_after'),('mdm_commands.action_polls','policy_after'),
 ('mdm_planning.configuration_claims','version'),('mdm_planning.configuration_claims','operation'),
 ('mdm_planning.configuration_devices','input_revision'),('mdm_planning.configuration_devices','observed_revision'),('mdm_planning.configuration_objects','operation'),('mdm_planning.configuration_objects','digest'),('mdm_planning.configuration_objects','diagnosis'),
 ('mdm_commands.native_checkins','active_event'),('mdm_commands.native_checkins','active_at'),('mdm_commands.native_checkins','policy_after'),('mdm_commands.native_checkins','pending_event'),('mdm_commands.native_checkins','pending_at'),('mdm_commands.action_polls','cancellation_after'),('mdm_commands.action_polls','profiles'),('mdm_commands.action_runs','invocation'),('mdm_commands.action_runs','source_objects'),('mdm_commands.action_runs','software_effect'),('mdm_commands.action_runs','state'),('mdm_commands.action_runs','result'),('mdm_commands.action_runs','gateway_accepted'),('mdm_commands.action_attempts','permit'),('mdm_commands.action_attempts','execution_material'),
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
 ('mdm_commands.operations','dispatch_failure'),('mdm_commands.operations','authority'),('mdm_commands.operations','revision'),('mdm_commands.operations','gateway_accepted'),
 ('mdm_access.report_sources','next_sequence'),('mdm_access.registrations','next_command'),('mdm_access.registrations','ready'),('mdm_access.registrations','first_authenticated_at'),('mdm_access.registrations','last_communication_received_at'),('mdm_access.enrollment_certificates','server_nonce'),
 ('mdm_access.management_sessions','state'),('mdm_access.management_sessions','last_message'),('mdm_access.management_sessions','client_authenticated'),('mdm_access.management_sessions','nonce'),('mdm_access.management_sessions','run_id'),
 ('mdm_access.collection_runs','evidence'),('mdm_access.collection_runs','attempts'),('mdm_access.collection_runs','result'),('mdm_access.collection_runs','reason'),('mdm_access.collection_runs','batch'),('mdm_access.collection_runs','digest'),('mdm_access.collection_runs','sealed_at'),('mdm_access.collection_runs','delivery_pending')
,
 ('mdm_apple.attempts','native_outcome'),('mdm_apple.attempts','accepted'),('mdm_apple.attempts','state'),('mdm_apple.attempts','response'),('mdm_apple.attempts','response_digest'),('mdm_apple.attempts','received_at'),('mdm_apple.attempts','next_attempt'),
 ('mdm_apple.declarations','retired_at'),('mdm_apple.declarations','legacy_released_at'),('mdm_apple.declarations','projection'),('mdm_apple.profiles','verification'),('mdm_apple.profiles','verification_evidence'),('mdm_apple.profiles','manifest_digest'),('mdm_apple.profiles','manifest_cipher_digest'),('mdm_apple.profiles','manifest'),('mdm_apple.profiles','dispatched_at'),('mdm_apple.profiles','observed_at'),('mdm_apple.profiles','retired_at'),('mdm_apple.devices','state'),('mdm_apple.channels','state'),('mdm_apple.channels','material'),('mdm_apple.channels','material_digest'),('mdm_apple.channels','push_id'),('mdm_apple.channels','push_lease_until'),('mdm_apple.channels','next_push'),('mdm_apple.channels','push_status'),('mdm_apple.channels','push_outcome'),('mdm_apple.channels','push_configuration'),('mdm_apple.channels','push_failures')
), read_columns(relation,col) AS (VALUES
 ('mdm_access.agent_configuration_keys','tenant_id'),('mdm_access.agent_configuration_keys','public_key'),
 ('public.mdm_installation','instance_id'),('public.mdm_installation','management_tenant_id'),
 ('mdm_access.agent_issuances','tenant_id'),('mdm_access.agent_issuances','credential'),('mdm_access.agent_issuances','not_after')
), allowed(relation,sel,ins,del) AS (VALUES
 ('mdm_planning.event_batches',true,true,false),('mdm_planning.event_members',true,true,false),('mdm_automation.automation_jobs',true,true,false),
 ('mdm_apple.psso_password_providers',true,true,false),
 ('mdm_commands.query_revisions',true,false,false),('mdm.asset_clock',true,false,false),
 ('mdm_access.device_access_bindings',true,false,false),('mdm_access.device_access_results',true,true,false),('mdm_recovery.rss_login_uses',true,true,false),
 ('mdm_webhook.key_heads',true,true,false),('mdm_webhook.key_materials',true,true,false),
 ('mdm_webhook.subscriptions',true,true,false),('mdm_webhook.versions',true,true,false),('mdm_webhook.events',true,true,false),('mdm_webhook.compliance_sources',true,true,false),('mdm_webhook.fanout',true,true,false),('mdm_webhook.deliveries',true,true,false),('mdm_webhook.operations',true,true,false),
 ('mdm_group.groups',true,false,false),('mdm_group.member_runs',true,false,false),('mdm_group.member_changes',true,false,false),('mdm_compliance.results',true,false,false),
 ('mdm_devices.retirement_policies',true,true,false),('mdm_devices.retirements',true,true,false),('mdm_devices.retirement_channels',true,true,false),('mdm_devices.retirement_work',true,true,false),('mdm_devices.associations',true,false,false),('mdm_devices.members',true,false,false),
 ('mdm_recovery.filevault_custodies',true,true,false),('mdm_recovery.filevault_sources',true,true,false),('mdm_recovery.filevault_receipts',true,true,false),
 ('mdm_recovery.agent_guards',true,true,true),('mdm_recovery.agent_materials',true,true,false),('mdm_recovery.entries',true,true,false),('mdm_recovery.versions',true,true,false),('mdm_recovery.native_actions',true,true,false),
 ('mdm_pki.certificates',true,false,false),('mdm_pki.revocations',true,false,false),('mdm_agent_packages.releases',true,false,false),('mdm_access.agent_bootstraps',true,true,false),('mdm_access.agent_native_enrollments',true,true,false),('mdm_access.grants',true,true,false),('mdm_pki.trust',true,false,false),('mdm_pki.rotations',true,false,false),('mdm_pki.installations',true,true,false),('mdm_pki.acknowledgements',true,true,false),
 ('mdm_windows.trust_deliveries',true,true,false),('mdm_apple.trust_deliveries',true,true,false),
 ('mdm_content.manifests',true,false,false),('mdm_flow.native_protection',true,true,false),('mdm_access.agent_grants',true,true,false),('mdm_access.agent_enrollment_settings',true,false,false),('mdm_access.agent_connection_versions',true,false,false),
 ('mdm.inventory',true,false,false),('mdm.array_versions',true,false,false),('mdm.array_items',true,false,false),('mdm_access.collection_versions',true,false,false),('mdm_access.collection_items',true,false,false),
 ('mdm.field_versions',true,false,false),('mdm.collection_definitions',true,true,false),('mdm.collection_results',true,true,false),
 ('mdm_software_composition.withdrawals',true,false,false),('mdm_software_composition.subjects',true,false,false),('mdm_software_composition.targets',true,false,false),('mdm_software_composition.projections',true,false,false),('mdm_software_release.aggregates',true,false,false),
 ('mdm_planning.operations',true,true,false),('mdm_commands.policy_recovery',true,true,false),('mdm_commands.software_stage_stats',true,true,false),('mdm_commands.software_stats_members',true,true,false),('mdm_commands.software_result_changes',true,false,false),('mdm_commands.software_binding_changes',true,false,false),('mdm_commands.software_binding_revisions',true,false,false),('mdm_policy.policies',true,false,false),('mdm_policy.versions',true,false,false),('mdm_policy.triggers',true,false,false),('mdm_planning.configuration_claims',true,true,true),('mdm_planning.configuration_devices',true,true,false),
 ('mdm_task_signing.heads',true,false,false),('mdm_task_signing.versions',true,false,false),('mdm_task_signing.acknowledgements',true,false,false),
 ('mdm_commands.output_chunks',true,true,false),('mdm_commands.action_polls',true,true,false),('mdm_commands.native_checkins',true,true,false),('mdm_commands.action_runs',true,true,false),('mdm_commands.action_receipts',true,true,false),('mdm_commands.action_attempts',true,true,false),('mdm_resource.aggregates',true,false,false),('mdm_resource.immutable',true,false,false),('mdm_agent.bindings',true,false,false),
 ('mdm_planning.scopes',true,false,false),('mdm_planning.scope_results',true,false,false),('mdm_planning.scope_channel_results',true,false,false),('mdm_planning.scope_source_members',true,false,false),('mdm_planning.scope_runs',true,false,false),('mdm_planning.policy_assignments',true,false,false),('mdm_devices.associations',true,false,false),('mdm_devices.members',true,false,false),('mdm_devices.checkpoints',true,false,false),('mdm_devices.input_snapshots',true,false,false),('mdm_devices.input_objects',true,false,false),
 ('mdm_software.sources',true,false,false),('mdm_software.versions',true,false,false),('mdm_software.materials',true,false,false),
 ('mdm_apple.declarations',true,true,false),('mdm_apple.status_reports',true,true,false),('mdm_apple.attempts',true,true,false),('mdm_apple.profile_qualifications',true,false,false),('mdm_apple.profiles',true,true,false),('mdm_apple.devices',true,false,false),('mdm_apple.channels',true,false,false),('mdm_access.requests',true,true,false),

('mdm_commands.capabilities',true,true,false),
('mdm_commands.capability_queries',true,true,false),

 ('mdm_commands.devices',true,true,false),('mdm_commands.operations',true,true,false),('mdm_commands.requests',true,true,false),('mdm_commands.attempts',true,true,false),('mdm_commands.attempt_items',true,true,false),('mdm_commands.attempt_frames',true,true,false),('mdm_planning.configuration_objects',true,true,false),
 ('mdm_access.devices',true,false,false),('mdm_access.registrations',true,false,false),('mdm_access.registration_admission',true,false,false),('mdm_access.credentials',true,false,false),('mdm_access.report_sources',true,false,false),('mdm_access.enrollment_intents',true,false,false),('mdm_access.enrollment_certificates',true,false,false),('mdm_access.authorization_rules',true,false,false),('mdm_access.user_groups',true,false,false),('mdm_access.api_keys',true,false,false),
 ('mdm_access.management_sessions',true,true,false),('mdm_access.management_messages',true,true,false),('mdm_access.collection_runs',true,true,false),('mdm_windows.collections',true,true,false),('mdm_windows.push_channels',true,true,false),('mdm_windows.push_queries',true,true,false),('rss_audit.records',true,false,false),
 ('rss_device_command.commands',true,false,false),('rss_device_command.authorities',true,false,false),
 ('rss_reconcile.targets',true,false,false),
 ('rss_transactional_messaging.policy',true,false,false),('rss_transactional_messaging.outbox',true,false,false),('rss_transactional_messaging.inbox',true,true,true)
), rejected_sources AS (
 -- Restrictive policies may narrow access; only the tenant policy may grant it.
 SELECT source.relation FROM (SELECT relation FROM allowed UNION SELECT relation FROM read_columns) source
 LEFT JOIN pg_class c ON c.oid=to_regclass(source.relation)
 WHERE source.relation LIKE 'mdm%' AND (c.oid IS NULL OR (c.relkind='r' AND (
 NOT c.relrowsecurity OR NOT c.relforcerowsecurity
 OR (SELECT count(*) FROM pg_policy WHERE polrelid=c.oid AND polpermissive)<>1
 OR NOT EXISTS(SELECT 1 FROM pg_policy p WHERE p.polrelid=c.oid AND p.polname='tenant'
 AND p.polcmd='*' AND p.polpermissive AND p.polroles=ARRAY[0::oid]
 AND lower(replace(regexp_replace(pg_get_expr(p.polqual,p.polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'
 AND pg_get_expr(p.polqual,p.polrelid)=pg_get_expr(p.polwithcheck,p.polrelid)))))
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
 AND (SELECT array_agg(relname::text ORDER BY relname)=ARRAY['action_attempts','action_polls','action_receipts','action_runs','attempt_frames','attempt_items','attempts','capabilities','capability_queries','devices','native_checkins','operations','output_chunks','policy_recovery','query_command_versions','query_revisions','requests','software_binding_changes','software_binding_revisions','software_result_changes','software_stage_stats','software_stats_members'] FROM tables)
 AND NOT EXISTS(SELECT 1 FROM tables t WHERE relkind<>'r' OR relpersistence<>'p' OR NOT relrowsecurity OR NOT relforcerowsecurity OR relowner=(SELECT oid FROM pg_roles WHERE rolname=current_user)
  OR (SELECT count(*) FROM pg_policy WHERE polrelid=t.oid)<>1
  OR NOT EXISTS(SELECT 1 FROM pg_policy WHERE polrelid=t.oid AND polname='tenant' AND polcmd='*' AND polpermissive AND polroles=ARRAY[0::oid]
   AND lower(replace(regexp_replace(pg_get_expr(polqual,polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'
   AND pg_get_expr(polqual,polrelid)=pg_get_expr(polwithcheck,polrelid)))
 AND NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid IN(SELECT oid FROM tables) AND NOT tgisinternal AND NOT((tgrelid='mdm_commands.action_runs'::regclass AND tgname='software_results' AND tgfoid='mdm_commands.advance_software_results()'::regprocedure AND tgenabled='O') OR (tgname='execution_query_revision' AND tgfoid='mdm_commands.capture_query_revision()'::regprocedure AND tgtype=29 AND tgenabled='O' AND tgqual IS NULL AND tgrelid IN('mdm_commands.operations'::regclass,'mdm_commands.action_runs'::regclass,'mdm_commands.attempts'::regclass,'mdm_commands.attempt_items'::regclass,'mdm_commands.attempt_frames'::regclass))))
 AND EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='mdm_commands.action_runs'::regclass AND tgname='software_results' AND tgenabled='O')
 AND EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='mdm_agent.bindings'::regclass AND tgname='software_bindings' AND tgfoid='mdm_commands.advance_software_bindings()'::regprocedure AND tgenabled='O')
 AND NOT EXISTS(SELECT 1 FROM pg_rewrite WHERE ev_class IN(SELECT oid FROM tables))
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace LEFT JOIN allowed a ON a.relation=n.nspname||'.'||c.relname
  WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname NOT IN ('information_schema','rss_ledger') AND c.relkind IN('r','v','m','f')
  AND (has_table_privilege(current_user,c.oid,'SELECT')<>coalesce(a.sel,false)
   OR has_table_privilege(current_user,c.oid,'INSERT')<>coalesce(a.ins,false)
   OR has_table_privilege(current_user,c.oid,'DELETE')<>coalesce(a.del,false)
   OR has_table_privilege(current_user,c.oid,'TRUNCATE,REFERENCES,TRIGGER')
   OR (has_table_privilege(current_user,c.oid,'UPDATE') AND a.relation IS DISTINCT FROM 'rss_transactional_messaging.inbox')))
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_attribute a ON a.attrelid=c.oid
  WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname NOT IN ('information_schema','rss_ledger') AND c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped
  AND has_column_privilege(current_user,c.oid,a.attnum,'UPDATE')<>(n.nspname||'.'||c.relname='rss_transactional_messaging.inbox' OR EXISTS(SELECT 1 FROM update_columns u WHERE u.relation=n.nspname||'.'||c.relname AND u.col=a.attname)))

 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_attribute col ON col.attrelid=c.oid LEFT JOIN allowed a ON a.relation=n.nspname||'.'||c.relname
  WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname NOT IN ('information_schema','rss_ledger') AND c.relkind IN('r','v','m','f') AND col.attnum>0 AND NOT col.attisdropped
  AND (has_column_privilege(current_user,c.oid,col.attnum,'SELECT')<>(coalesce(a.sel,false) OR EXISTS(SELECT 1 FROM read_columns r WHERE r.relation=n.nspname||'.'||c.relname AND r.col=col.attname))
    OR has_column_privilege(current_user,c.oid,col.attnum,'INSERT')<>coalesce(a.ins,false)
    OR has_column_privilege(current_user,c.oid,col.attnum,'REFERENCES')))
 AND NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
  WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname NOT IN('information_schema','rss_device_command','rss_reconcile','rss_audit','rss_ledger')
  AND p.oid IS DISTINCT FROM to_regprocedure('mdm_apple.account_current(uuid,uuid,bigint,uuid,text)')
   AND p.oid NOT IN('mdm_apple.platform_registration_matches(uuid,bigint,jsonb)'::regprocedure,'mdm_recovery.filevault_accessible(jsonb,text)'::regprocedure,'mdm_devices.association_grant_current(uuid,bigint,uuid,bigint)'::regprocedure,'mdm_commands.advance_query_revision(uuid)'::regprocedure,'mdm_commands.lock_query_revision(uuid)'::regprocedure,'mdm_commands.observe_query_commands(uuid,text[],bigint[])'::regprocedure,'mdm_access.operation_authority_valid(jsonb,text,bigint)'::regprocedure,'mdm_access.operation_authority_valid_until(jsonb,text,bigint)'::regprocedure,'mdm_access.access_binding_ready(jsonb)'::regprocedure,'mdm_devices.object_current(jsonb,text)'::regprocedure,'mdm_devices.lock_query_revision(uuid)'::regprocedure,'mdm_planning.scope_state(uuid,text)'::regprocedure,'mdm_planning.channel_admission(uuid,text,text)'::regprocedure,'mdm_commands.access_policy(uuid,text,bigint)'::regprocedure,'mdm_commands.active_access_binding(uuid,bigint,bigint)'::regprocedure,'mdm_apple.application_valid_until(uuid,jsonb,bigint)'::regprocedure,'mdm_commands.retirement_commands(uuid,text)'::regprocedure,'mdm_commands.save_retired_command(uuid,uuid,bigint,bigint)'::regprocedure,'mdm_commands.save_retired_action(uuid,uuid,jsonb,jsonb)'::regprocedure,'mdm_commands.installation_status(uuid)'::regprocedure,'mdm.lock_asset_watermark(uuid)'::regprocedure,'mdm_planning.scope_admission(uuid,text)'::regprocedure,'mdm_planning.policy_lock(uuid)'::regprocedure,'rss_transactional_messaging.check_execution()'::regprocedure,'rss_transactional_messaging.consumer_scope_domain()'::regprocedure,'rss_transactional_messaging.consumer_inbox_allowed(uuid,text,text)'::regprocedure,'rss_transactional_messaging.projection_scope_matches(text,text)'::regprocedure,'rss_transactional_messaging.prepare_outbox_partitions(jsonb)'::regprocedure,'rss_transactional_messaging.append_outbox(bytea,jsonb)'::regprocedure,'rss_transactional_messaging.claim_outbox(uuid,text,integer,bigint)'::regprocedure,'rss_transactional_messaging.next_outbox_wakeup(uuid,text)'::regprocedure,'rss_transactional_messaging.outbox_lease(uuid,bigint,uuid,bigint,bigint,uuid)'::regprocedure,'rss_transactional_messaging.settle_outbox(uuid,bigint,uuid,bigint,text,uuid)'::regprocedure)
  AND has_function_privilege(current_user,p.oid,'EXECUTE'))
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind='S' AND n.nspname NOT LIKE 'pg_%' AND has_sequence_privilege(current_user,c.oid,'SELECT,USAGE,UPDATE'))

 -- The reader must actually have the global purpose coordinates, without grant options.
 AND EXISTS(SELECT 1 FROM pg_class c WHERE c.oid='public.mdm_installation'::regclass AND c.relkind='r'
 AND has_schema_privilege(current_user,c.relnamespace,'USAGE')
 AND has_column_privilege(current_user,c.oid,'instance_id','SELECT')
 AND has_column_privilege(current_user,c.oid,'management_tenant_id','SELECT')
 AND NOT EXISTS(SELECT 1 FROM pg_attribute col,LATERAL aclexplode(col.attacl) a WHERE col.attrelid=c.oid
 AND (a.grantee=0 OR (a.grantee=(SELECT oid FROM pg_roles WHERE rolname=current_user) AND a.is_grantable))))

 AND has_function_privilege(current_user,'mdm.lock_asset_watermark(uuid)','EXECUTE')
 AND has_function_privilege(current_user,'mdm_commands.installation_status(uuid)','EXECUTE')

 AND NOT EXISTS(SELECT 1 FROM rejected_sources),
 (SELECT string_agg(relation,', ' ORDER BY relation) FROM rejected_sources)
