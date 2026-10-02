-- Fresh installation: flow-service owns these objects.
BEGIN;
SET LOCAL check_function_bodies = false;

ALTER TABLE ONLY mdm_commands.action_attempts
    ADD CONSTRAINT action_attempts_tenant_id_registration_fkey FOREIGN KEY (tenant_id, registration) REFERENCES mdm_access.registrations(tenant_id, id);

ALTER TABLE ONLY mdm_commands.action_attempts
    ADD CONSTRAINT action_attempts_tenant_id_run_fkey FOREIGN KEY (tenant_id, run) REFERENCES mdm_commands.action_runs(tenant_id, id);

ALTER TABLE ONLY mdm_commands.action_polls
    ADD CONSTRAINT action_polls_tenant_id_registration_fkey FOREIGN KEY (tenant_id, registration) REFERENCES mdm_access.registrations(tenant_id, id);

ALTER TABLE ONLY mdm_commands.action_runs
    ADD CONSTRAINT action_runs_tenant_id_device_fkey FOREIGN KEY (tenant_id, device) REFERENCES mdm_access.devices(tenant_id, id);

ALTER TABLE ONLY mdm_commands.action_runs
    ADD CONSTRAINT action_runs_tenant_id_policy_version_fkey FOREIGN KEY (tenant_id, policy_version) REFERENCES mdm_policy.versions(tenant_id, id);

ALTER TABLE ONLY mdm_commands.action_runs
    ADD CONSTRAINT action_runs_tenant_id_registration_fkey FOREIGN KEY (tenant_id, registration) REFERENCES mdm_access.registrations(tenant_id, id);

ALTER TABLE ONLY mdm_commands.action_runs
    ADD CONSTRAINT action_runs_tenant_id_remote_operation_device_fkey FOREIGN KEY (tenant_id, remote_operation, device) REFERENCES mdm_planning.remote_operation_targets(tenant_id, operation, device);

ALTER TABLE ONLY mdm_commands.attempts
    ADD CONSTRAINT attempts_tenant_id_credential_fkey FOREIGN KEY (tenant_id, credential) REFERENCES mdm_access.credentials(tenant_id, id);

ALTER TABLE ONLY mdm_commands.attempts
    ADD CONSTRAINT attempts_tenant_id_operation_fkey FOREIGN KEY (tenant_id, operation) REFERENCES mdm_commands.operations(tenant_id, id);

ALTER TABLE ONLY mdm_commands.capabilities
    ADD CONSTRAINT capabilities_tenant_id_registration_fkey FOREIGN KEY (tenant_id, registration) REFERENCES mdm_access.registrations(tenant_id, id);

ALTER TABLE ONLY mdm_commands.capability_queries
    ADD CONSTRAINT capability_queries_tenant_id_registration_fkey FOREIGN KEY (tenant_id, registration) REFERENCES mdm_access.registrations(tenant_id, id);

ALTER TABLE ONLY mdm_commands.capability_queries
    ADD CONSTRAINT capability_queries_tenant_id_registration_session_id_fkey FOREIGN KEY (tenant_id, registration, session_id) REFERENCES mdm_access.management_sessions(tenant_id, registration, session_id) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY mdm_commands.devices
    ADD CONSTRAINT devices_tenant_id_device_fkey FOREIGN KEY (tenant_id, device) REFERENCES mdm_access.devices(tenant_id, id);

ALTER TABLE ONLY mdm_commands.devices
    ADD CONSTRAINT devices_tenant_id_registration_fkey FOREIGN KEY (tenant_id, registration) REFERENCES mdm_access.registrations(tenant_id, id);

ALTER TABLE ONLY mdm_commands.operations
    ADD CONSTRAINT operations_tenant_id_device_fkey FOREIGN KEY (tenant_id, device) REFERENCES mdm_commands.devices(tenant_id, device);

ALTER TABLE ONLY mdm_commands.operations
    ADD CONSTRAINT operations_tenant_id_policy_version_fkey FOREIGN KEY (tenant_id, policy_version) REFERENCES mdm_policy.versions(tenant_id, id);

ALTER TABLE ONLY mdm_commands.operations
    ADD CONSTRAINT operations_tenant_id_remote_operation_device_fkey FOREIGN KEY (tenant_id, remote_operation, device) REFERENCES mdm_planning.remote_operation_targets(tenant_id, operation, device);

ALTER TABLE ONLY mdm_commands.policy_recovery
    ADD CONSTRAINT policy_recovery_tenant_id_policy_fkey FOREIGN KEY (tenant_id, policy) REFERENCES mdm_policy.policies(tenant_id, id);

ALTER TABLE ONLY mdm_commands.apple_profiles
    ADD CONSTRAINT profiles_tenant_id_device_fkey FOREIGN KEY (tenant_id, device) REFERENCES mdm_access.devices(tenant_id, id);

ALTER TABLE ONLY mdm_commands.apple_profiles
    ADD CONSTRAINT profiles_tenant_id_operation_fkey FOREIGN KEY (tenant_id, operation) REFERENCES mdm_commands.operations(tenant_id, id);

ALTER TABLE ONLY mdm_commands.apple_profiles
    ADD CONSTRAINT profiles_tenant_id_registration_fkey FOREIGN KEY (tenant_id, registration) REFERENCES mdm_access.registrations(tenant_id, id);

ALTER TABLE ONLY mdm_commands.requests
    ADD CONSTRAINT requests_tenant_id_operation_fkey FOREIGN KEY (tenant_id, operation) REFERENCES mdm_commands.operations(tenant_id, id);

ALTER TABLE ONLY mdm_planning.configuration_claims
    ADD CONSTRAINT configuration_claims_tenant_id_policy_fkey FOREIGN KEY (tenant_id, policy) REFERENCES mdm_policy.policies(tenant_id, id);

ALTER TABLE ONLY mdm_planning.configuration_claims
    ADD CONSTRAINT configuration_claims_tenant_id_version_fkey FOREIGN KEY (tenant_id, version) REFERENCES mdm_policy.versions(tenant_id, id);

ALTER TABLE ONLY mdm_planning.remote_operation_targets
    ADD CONSTRAINT remote_operation_targets_tenant_id_operation_fkey FOREIGN KEY (tenant_id, operation) REFERENCES mdm_planning.remote_operations(tenant_id, id);

ALTER TABLE ONLY mdm_planning.scope_results
    ADD CONSTRAINT scope_results_tenant_id_run_fkey FOREIGN KEY (tenant_id, run) REFERENCES mdm_planning.scope_runs(tenant_id, id);

ALTER TABLE ONLY mdm_planning.scope_runs
    ADD CONSTRAINT scope_runs_tenant_id_scope_fkey FOREIGN KEY (tenant_id, scope) REFERENCES mdm_planning.scopes(tenant_id, id);

ALTER TABLE ONLY mdm_planning.scope_source_members
    ADD CONSTRAINT scope_source_members_tenant_id_run_fkey FOREIGN KEY (tenant_id, run) REFERENCES mdm_planning.scope_runs(tenant_id, id);

ALTER TABLE ONLY mdm_planning.scope_sources
    ADD CONSTRAINT scope_sources_tenant_id_scope_fkey FOREIGN KEY (tenant_id, scope) REFERENCES mdm_planning.scopes(tenant_id, id);

ALTER TABLE ONLY mdm_planning.scope_versions
    ADD CONSTRAINT scope_versions_tenant_id_id_fkey FOREIGN KEY (tenant_id, id) REFERENCES mdm_planning.scopes(tenant_id, id);

ALTER TABLE ONLY mdm_planning.scopes
    ADD CONSTRAINT scopes_tenant_id_resolution_fkey FOREIGN KEY (tenant_id, resolution) REFERENCES mdm_planning.scope_runs(tenant_id, id);

GRANT USAGE ON SCHEMA mdm_automation TO mdm_flow_runtime;

GRANT USAGE ON SCHEMA mdm_commands TO mdm_command_runtime;
GRANT USAGE ON SCHEMA mdm_commands TO mdm_flow_runtime;

GRANT USAGE ON SCHEMA mdm_flow TO mdm_flow_runtime;

GRANT USAGE ON SCHEMA mdm_planning TO mdm_flow_runtime;
GRANT USAGE ON SCHEMA mdm_planning TO mdm_command_runtime;

GRANT USAGE ON SCHEMA mdm_policy TO mdm_policy_runtime;
GRANT USAGE ON SCHEMA mdm_policy TO mdm_command_runtime;

GRANT USAGE ON SCHEMA mdm_publication TO mdm_flow_runtime;

GRANT USAGE ON SCHEMA mdm_resource TO mdm_resource_runtime;
GRANT USAGE ON SCHEMA mdm_resource TO mdm_command_runtime;

GRANT USAGE ON SCHEMA mdm_resource_catalog TO mdm_flow_runtime;

GRANT USAGE ON SCHEMA mdm_software TO mdm_flow_runtime;
GRANT USAGE ON SCHEMA mdm_software TO mdm_command_runtime;

GRANT USAGE ON SCHEMA mdm_software_composition TO mdm_software_driver;
GRANT USAGE ON SCHEMA mdm_software_composition TO mdm_flow_runtime;

GRANT USAGE ON SCHEMA mdm_software_release TO mdm_software_release_runtime;

GRANT USAGE ON SCHEMA rss_device_command TO mdm_command_runtime;

GRANT USAGE ON SCHEMA rss_reconcile TO mdm_command_runtime;
GRANT USAGE ON SCHEMA rss_reconcile TO mdm_flow_runtime;

GRANT USAGE ON SCHEMA rss_transactional_messaging TO rss_tmsg_relay;
GRANT USAGE ON SCHEMA rss_transactional_messaging TO mdm_resource_runtime;
GRANT USAGE ON SCHEMA rss_transactional_messaging TO mdm_software_release_runtime;
GRANT USAGE ON SCHEMA rss_transactional_messaging TO mdm_group_runtime;
GRANT USAGE ON SCHEMA rss_transactional_messaging TO mdm_policy_runtime;
GRANT USAGE ON SCHEMA rss_transactional_messaging TO mdm_identity_runtime;
GRANT USAGE ON SCHEMA rss_transactional_messaging TO mdm_identity_maintenance;
GRANT USAGE ON SCHEMA rss_transactional_messaging TO mdm_identity_audit;
GRANT USAGE ON SCHEMA rss_transactional_messaging TO mdm_command_runtime;

REVOKE ALL ON FUNCTION mdm_planning.policy_lock(p_policy uuid) FROM PUBLIC;
GRANT ALL ON FUNCTION mdm_planning.policy_lock(p_policy uuid) TO mdm_flow_runtime;
GRANT ALL ON FUNCTION mdm_planning.policy_lock(p_policy uuid) TO mdm_command_runtime;

REVOKE ALL ON FUNCTION mdm_planning.remote_target_page(p_operation uuid, p_after text, p_limit integer) FROM PUBLIC;
GRANT ALL ON FUNCTION mdm_planning.remote_target_page(p_operation uuid, p_after text, p_limit integer) TO mdm_command_runtime;

REVOKE ALL ON FUNCTION mdm_planning.scope_admission(p_scope uuid, p_device text) FROM PUBLIC;
GRANT ALL ON FUNCTION mdm_planning.scope_admission(p_scope uuid, p_device text) TO mdm_command_runtime;
GRANT ALL ON FUNCTION mdm_planning.scope_admission(p_scope uuid, p_device text) TO mdm_flow_runtime;

REVOKE ALL ON FUNCTION rss_device_command.advance(t uuid, d uuid, g bigint, e bigint, ng bigint, ne bigint) FROM PUBLIC;
GRANT ALL ON FUNCTION rss_device_command.advance(t uuid, d uuid, g bigint, e bigint, ng bigint, ne bigint) TO mdm_command_runtime;

REVOKE ALL ON FUNCTION rss_device_command.enqueue(t uuid, d uuid, c text, g bigint, e bigint, digest bytea, expires bigint, at_time bigint, m text, f bytea, domain_name text) FROM PUBLIC;
GRANT ALL ON FUNCTION rss_device_command.enqueue(t uuid, d uuid, c text, g bigint, e bigint, digest bytea, expires bigint, at_time bigint, m text, f bytea, domain_name text) TO mdm_command_runtime;

REVOKE ALL ON FUNCTION rss_device_command.initialize(t uuid, d uuid, g bigint, e bigint) FROM PUBLIC;
GRANT ALL ON FUNCTION rss_device_command.initialize(t uuid, d uuid, g bigint, e bigint) TO mdm_command_runtime;

GRANT SELECT ON TABLE rss_device_command.authorities TO mdm_command_runtime;

REVOKE ALL ON FUNCTION rss_device_command.lock_authority(t uuid, d uuid) FROM PUBLIC;
GRANT ALL ON FUNCTION rss_device_command.lock_authority(t uuid, d uuid) TO mdm_command_runtime;

REVOKE ALL ON FUNCTION rss_device_command.save(t uuid, d uuid, c text, v bigint, s text, p bigint, r bigint, done bigint) FROM PUBLIC;
GRANT ALL ON FUNCTION rss_device_command.save(t uuid, d uuid, c text, v bigint, s text, p bigint, r bigint, done bigint) TO mdm_command_runtime;

REVOKE ALL ON FUNCTION rss_reconcile.assert_tenant(t uuid) FROM PUBLIC;
GRANT ALL ON FUNCTION rss_reconcile.assert_tenant(t uuid) TO mdm_command_runtime;
GRANT ALL ON FUNCTION rss_reconcile.assert_tenant(t uuid) TO mdm_flow_runtime;

GRANT SELECT ON TABLE rss_reconcile.targets TO mdm_command_runtime;
GRANT SELECT ON TABLE rss_reconcile.targets TO mdm_flow_runtime;

REVOKE ALL ON FUNCTION rss_reconcile.claim_due(t uuid, r text, n integer, ttl bigint) FROM PUBLIC;
GRANT ALL ON FUNCTION rss_reconcile.claim_due(t uuid, r text, n integer, ttl bigint) TO mdm_command_runtime;
GRANT ALL ON FUNCTION rss_reconcile.claim_due(t uuid, r text, n integer, ttl bigint) TO mdm_flow_runtime;

REVOKE ALL ON FUNCTION rss_reconcile.finish(t uuid, r text, e text, k uuid, g bigint, w bigint, outcome text, delay bigint, f bigint) FROM PUBLIC;
GRANT ALL ON FUNCTION rss_reconcile.finish(t uuid, r text, e text, k uuid, g bigint, w bigint, outcome text, delay bigint, f bigint) TO mdm_command_runtime;
GRANT ALL ON FUNCTION rss_reconcile.finish(t uuid, r text, e text, k uuid, g bigint, w bigint, outcome text, delay bigint, f bigint) TO mdm_flow_runtime;

REVOKE ALL ON FUNCTION rss_reconcile.lock_claim(t uuid, r text, e text, k uuid, g bigint) FROM PUBLIC;
GRANT ALL ON FUNCTION rss_reconcile.lock_claim(t uuid, r text, e text, k uuid, g bigint) TO mdm_command_runtime;
GRANT ALL ON FUNCTION rss_reconcile.lock_claim(t uuid, r text, e text, k uuid, g bigint) TO mdm_flow_runtime;

REVOKE ALL ON FUNCTION rss_reconcile.mark_applied(t uuid, r text, e text, k uuid, g bigint) FROM PUBLIC;
GRANT ALL ON FUNCTION rss_reconcile.mark_applied(t uuid, r text, e text, k uuid, g bigint) TO mdm_command_runtime;
GRANT ALL ON FUNCTION rss_reconcile.mark_applied(t uuid, r text, e text, k uuid, g bigint) TO mdm_flow_runtime;

REVOKE ALL ON FUNCTION rss_reconcile.release(t uuid, r text, e text, k uuid, g bigint) FROM PUBLIC;
GRANT ALL ON FUNCTION rss_reconcile.release(t uuid, r text, e text, k uuid, g bigint) TO mdm_command_runtime;
GRANT ALL ON FUNCTION rss_reconcile.release(t uuid, r text, e text, k uuid, g bigint) TO mdm_flow_runtime;

REVOKE ALL ON FUNCTION rss_reconcile.renew(t uuid, r text, e text, k uuid, g bigint, ttl bigint) FROM PUBLIC;
GRANT ALL ON FUNCTION rss_reconcile.renew(t uuid, r text, e text, k uuid, g bigint, ttl bigint) TO mdm_command_runtime;
GRANT ALL ON FUNCTION rss_reconcile.renew(t uuid, r text, e text, k uuid, g bigint, ttl bigint) TO mdm_flow_runtime;

REVOKE ALL ON FUNCTION rss_reconcile.wake(t uuid, r text, e text) FROM PUBLIC;
GRANT ALL ON FUNCTION rss_reconcile.wake(t uuid, r text, e text) TO mdm_command_runtime;
GRANT ALL ON FUNCTION rss_reconcile.wake(t uuid, r text, e text) TO mdm_flow_runtime;

REVOKE ALL ON FUNCTION rss_transactional_messaging.append_outbox(p_message bytea, p_transport jsonb) FROM PUBLIC;
GRANT ALL ON FUNCTION rss_transactional_messaging.append_outbox(p_message bytea, p_transport jsonb) TO mdm_group_runtime;
GRANT ALL ON FUNCTION rss_transactional_messaging.append_outbox(p_message bytea, p_transport jsonb) TO mdm_policy_runtime;
GRANT ALL ON FUNCTION rss_transactional_messaging.append_outbox(p_message bytea, p_transport jsonb) TO mdm_resource_runtime;
GRANT ALL ON FUNCTION rss_transactional_messaging.append_outbox(p_message bytea, p_transport jsonb) TO mdm_software_release_runtime;
GRANT ALL ON FUNCTION rss_transactional_messaging.append_outbox(p_message bytea, p_transport jsonb) TO mdm_identity_runtime;
GRANT ALL ON FUNCTION rss_transactional_messaging.append_outbox(p_message bytea, p_transport jsonb) TO mdm_identity_maintenance;
GRANT ALL ON FUNCTION rss_transactional_messaging.append_outbox(p_message bytea, p_transport jsonb) TO mdm_command_runtime;

REVOKE ALL ON FUNCTION rss_transactional_messaging.apply_dr(p_operation uuid, p_digest bytea, p_kind text, p_evidence jsonb, p_members jsonb, p_expected bigint) FROM PUBLIC;

REVOKE ALL ON FUNCTION rss_transactional_messaging.archive_claim(p_op uuid, p_id uuid, p_version bigint, p_digest bytea, p_hot bigint, p_cold bigint, p_hold boolean, p_ttl bigint) FROM PUBLIC;

REVOKE ALL ON FUNCTION rss_transactional_messaging.archive_fault(p_op uuid, p_token uuid, p_digest bytea, p_fault text) FROM PUBLIC;

REVOKE ALL ON FUNCTION rss_transactional_messaging.archive_fence(p_op uuid, p_token uuid, p_digest bytea) FROM PUBLIC;

REVOKE ALL ON FUNCTION rss_transactional_messaging.archive_missing(p_op uuid, p_token uuid, p_digest bytea, p_generation uuid, p_object jsonb) FROM PUBLIC;

REVOKE ALL ON FUNCTION rss_transactional_messaging.archive_prepare(p_op uuid, p_token uuid, p_digest bytea, p_object jsonb, p_bytes bytea) FROM PUBLIC;

REVOKE ALL ON FUNCTION rss_transactional_messaging.archive_purge(p_op uuid, p_token uuid, p_digest bytea, p_object jsonb) FROM PUBLIC;

REVOKE ALL ON FUNCTION rss_transactional_messaging.archive_record(p_op uuid, p_token uuid, p_digest bytea, p_generation uuid, p_object jsonb) FROM PUBLIC;

REVOKE ALL ON FUNCTION rss_transactional_messaging.check_execution() FROM PUBLIC;
GRANT ALL ON FUNCTION rss_transactional_messaging.check_execution() TO mdm_resource_runtime;
GRANT ALL ON FUNCTION rss_transactional_messaging.check_execution() TO mdm_software_release_runtime;
GRANT ALL ON FUNCTION rss_transactional_messaging.check_execution() TO mdm_group_runtime;
GRANT ALL ON FUNCTION rss_transactional_messaging.check_execution() TO mdm_policy_runtime;
GRANT ALL ON FUNCTION rss_transactional_messaging.check_execution() TO mdm_identity_runtime;
GRANT ALL ON FUNCTION rss_transactional_messaging.check_execution() TO mdm_identity_maintenance;
GRANT ALL ON FUNCTION rss_transactional_messaging.check_execution() TO mdm_identity_audit;
GRANT ALL ON FUNCTION rss_transactional_messaging.check_execution() TO mdm_command_runtime;

REVOKE ALL ON FUNCTION rss_transactional_messaging.claim_outbox(p_tenant uuid, p_domain text, p_limit integer, p_ttl_ms bigint) FROM PUBLIC;
GRANT ALL ON FUNCTION rss_transactional_messaging.claim_outbox(p_tenant uuid, p_domain text, p_limit integer, p_ttl_ms bigint) TO mdm_identity_audit;
GRANT ALL ON FUNCTION rss_transactional_messaging.claim_outbox(p_tenant uuid, p_domain text, p_limit integer, p_ttl_ms bigint) TO mdm_command_runtime;

REVOKE ALL ON FUNCTION rss_transactional_messaging.decode_outbox_message(data bytea) FROM PUBLIC;

REVOKE ALL ON FUNCTION rss_transactional_messaging.guard_archive_generation() FROM PUBLIC;

REVOKE ALL ON FUNCTION rss_transactional_messaging.guard_dr_consumer() FROM PUBLIC;

REVOKE ALL ON FUNCTION rss_transactional_messaging.guard_execution() FROM PUBLIC;

REVOKE ALL ON FUNCTION rss_transactional_messaging.outbox_lease(p_tenant uuid, p_seq bigint, p_token uuid, p_lease_us bigint, p_extend_ms bigint, p_dr uuid) FROM PUBLIC;
GRANT ALL ON FUNCTION rss_transactional_messaging.outbox_lease(p_tenant uuid, p_seq bigint, p_token uuid, p_lease_us bigint, p_extend_ms bigint, p_dr uuid) TO mdm_identity_audit;
GRANT ALL ON FUNCTION rss_transactional_messaging.outbox_lease(p_tenant uuid, p_seq bigint, p_token uuid, p_lease_us bigint, p_extend_ms bigint, p_dr uuid) TO mdm_command_runtime;

REVOKE ALL ON FUNCTION rss_transactional_messaging.prepare_outbox_partitions(p_partitions jsonb) FROM PUBLIC;
GRANT ALL ON FUNCTION rss_transactional_messaging.prepare_outbox_partitions(p_partitions jsonb) TO mdm_group_runtime;
GRANT ALL ON FUNCTION rss_transactional_messaging.prepare_outbox_partitions(p_partitions jsonb) TO mdm_policy_runtime;
GRANT ALL ON FUNCTION rss_transactional_messaging.prepare_outbox_partitions(p_partitions jsonb) TO mdm_resource_runtime;
GRANT ALL ON FUNCTION rss_transactional_messaging.prepare_outbox_partitions(p_partitions jsonb) TO mdm_software_release_runtime;
GRANT ALL ON FUNCTION rss_transactional_messaging.prepare_outbox_partitions(p_partitions jsonb) TO mdm_identity_runtime;
GRANT ALL ON FUNCTION rss_transactional_messaging.prepare_outbox_partitions(p_partitions jsonb) TO mdm_identity_maintenance;
GRANT ALL ON FUNCTION rss_transactional_messaging.prepare_outbox_partitions(p_partitions jsonb) TO mdm_command_runtime;

REVOKE ALL ON FUNCTION rss_transactional_messaging.read_dr(p_operation uuid, p_digest bytea) FROM PUBLIC;

REVOKE ALL ON FUNCTION rss_transactional_messaging.read_outbox_frame(data bytea, pos integer, tag integer) FROM PUBLIC;

REVOKE ALL ON FUNCTION rss_transactional_messaging.settle_outbox(p_tenant uuid, p_seq bigint, p_token uuid, p_lease_us bigint, p_disposition text, p_dr uuid) FROM PUBLIC;
GRANT ALL ON FUNCTION rss_transactional_messaging.settle_outbox(p_tenant uuid, p_seq bigint, p_token uuid, p_lease_us bigint, p_disposition text, p_dr uuid) TO mdm_identity_audit;
GRANT ALL ON FUNCTION rss_transactional_messaging.settle_outbox(p_tenant uuid, p_seq bigint, p_token uuid, p_lease_us bigint, p_disposition text, p_dr uuid) TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_automation.automation_jobs TO mdm_flow_runtime;

GRANT UPDATE(forwarded) ON TABLE mdm_automation.automation_jobs TO mdm_flow_runtime;

GRANT UPDATE(completed) ON TABLE mdm_automation.automation_jobs TO mdm_flow_runtime;

GRANT UPDATE(cursor) ON TABLE mdm_automation.automation_jobs TO mdm_flow_runtime;

GRANT UPDATE(replacement_task) ON TABLE mdm_automation.automation_jobs TO mdm_flow_runtime;

GRANT UPDATE(authority_revision) ON TABLE mdm_automation.automation_jobs TO mdm_flow_runtime;

GRANT UPDATE(failure) ON TABLE mdm_automation.automation_jobs TO mdm_flow_runtime;

GRANT UPDATE(failure_detail) ON TABLE mdm_automation.automation_jobs TO mdm_flow_runtime;

GRANT SELECT,INSERT ON TABLE mdm_commands.action_attempts TO mdm_command_runtime;

GRANT UPDATE(permit) ON TABLE mdm_commands.action_attempts TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_commands.action_polls TO mdm_command_runtime;

GRANT UPDATE(cancellation_after) ON TABLE mdm_commands.action_polls TO mdm_command_runtime;

GRANT UPDATE(policy_after) ON TABLE mdm_commands.action_polls TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_commands.action_receipts TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_commands.action_runs TO mdm_command_runtime;

GRANT UPDATE(state) ON TABLE mdm_commands.action_runs TO mdm_command_runtime;

GRANT UPDATE(gateway_accepted) ON TABLE mdm_commands.action_runs TO mdm_command_runtime;

GRANT UPDATE(result) ON TABLE mdm_commands.action_runs TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_commands.apple_profiles TO mdm_command_runtime;

GRANT UPDATE(profile) ON TABLE mdm_commands.apple_profiles TO mdm_command_runtime;

GRANT UPDATE(operation) ON TABLE mdm_commands.apple_profiles TO mdm_command_runtime;

GRANT UPDATE(registration) ON TABLE mdm_commands.apple_profiles TO mdm_command_runtime;

GRANT UPDATE(version) ON TABLE mdm_commands.apple_profiles TO mdm_command_runtime;


GRANT SELECT,INSERT ON TABLE mdm_commands.attempts TO mdm_command_runtime;

GRANT UPDATE(status) ON TABLE mdm_commands.attempt_items TO mdm_command_runtime;

GRANT UPDATE(value) ON TABLE mdm_commands.attempt_items TO mdm_command_runtime;

GRANT UPDATE(received_at) ON TABLE mdm_commands.attempt_items TO mdm_command_runtime;

GRANT UPDATE(receipt_accepted,result_accepted,result_received_at) ON TABLE mdm_commands.attempt_items TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_commands.capabilities TO mdm_command_runtime;
GRANT SELECT ON TABLE mdm_commands.capabilities TO mdm_flow_runtime;

GRANT UPDATE(generation) ON TABLE mdm_commands.capabilities TO mdm_command_runtime;

GRANT UPDATE(os_version) ON TABLE mdm_commands.capabilities TO mdm_command_runtime;

GRANT UPDATE(edition) ON TABLE mdm_commands.capabilities TO mdm_command_runtime;

GRANT UPDATE(session) ON TABLE mdm_commands.capabilities TO mdm_command_runtime;

GRANT UPDATE(observed_at) ON TABLE mdm_commands.capabilities TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_commands.capability_queries TO mdm_command_runtime;

GRANT UPDATE(os_version) ON TABLE mdm_commands.capability_queries TO mdm_command_runtime;

GRANT UPDATE(edition) ON TABLE mdm_commands.capability_queries TO mdm_command_runtime;

GRANT UPDATE(version_status) ON TABLE mdm_commands.capability_queries TO mdm_command_runtime;

GRANT UPDATE(edition_status) ON TABLE mdm_commands.capability_queries TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_commands.devices TO mdm_command_runtime;

GRANT UPDATE(generation) ON TABLE mdm_commands.devices TO mdm_command_runtime;

GRANT UPDATE(epoch) ON TABLE mdm_commands.devices TO mdm_command_runtime;

GRANT UPDATE(registration) ON TABLE mdm_commands.devices TO mdm_command_runtime;

GRANT UPDATE(registration_generation) ON TABLE mdm_commands.devices TO mdm_command_runtime;

GRANT UPDATE(recovery_after) ON TABLE mdm_commands.devices TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_commands.operations TO mdm_command_runtime;
GRANT SELECT ON TABLE mdm_commands.operations TO mdm_flow_runtime;

GRANT UPDATE(approval) ON TABLE mdm_commands.operations TO mdm_command_runtime;

GRANT UPDATE(revision) ON TABLE mdm_commands.operations TO mdm_command_runtime;

GRANT UPDATE(gateway_accepted,dispatch_failure) ON TABLE mdm_commands.operations TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_commands.policy_recovery TO mdm_command_runtime;

GRANT UPDATE(recovery_after,target_after) ON TABLE mdm_commands.policy_recovery TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_commands.requests TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_flow.cursor_keys TO mdm_flow_runtime;

GRANT SELECT,INSERT ON TABLE mdm_planning.asset_dispatch TO mdm_flow_runtime;

GRANT UPDATE(consumed) ON TABLE mdm_planning.asset_dispatch TO mdm_flow_runtime;

GRANT UPDATE(watermark) ON TABLE mdm_planning.asset_dispatch TO mdm_flow_runtime;

GRANT UPDATE(cursor) ON TABLE mdm_planning.asset_dispatch TO mdm_flow_runtime;

GRANT UPDATE(failure) ON TABLE mdm_planning.asset_dispatch TO mdm_flow_runtime;

GRANT UPDATE(failure_generation) ON TABLE mdm_planning.asset_dispatch TO mdm_flow_runtime;

GRANT UPDATE(phase) ON TABLE mdm_planning.asset_dispatch TO mdm_flow_runtime;

GRANT SELECT,INSERT,DELETE ON TABLE mdm_planning.configuration_claims TO mdm_command_runtime;
GRANT SELECT ON TABLE mdm_planning.configuration_claims TO mdm_flow_runtime;

GRANT UPDATE(version) ON TABLE mdm_planning.configuration_claims TO mdm_command_runtime;

GRANT UPDATE(operation) ON TABLE mdm_planning.configuration_claims TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_planning.configuration_devices TO mdm_flow_runtime;
GRANT SELECT,INSERT ON TABLE mdm_planning.configuration_devices TO mdm_command_runtime;

GRANT UPDATE(input_revision) ON TABLE mdm_planning.configuration_devices TO mdm_flow_runtime;
GRANT UPDATE(input_revision) ON TABLE mdm_planning.configuration_devices TO mdm_command_runtime;

GRANT UPDATE(observed_revision) ON TABLE mdm_planning.configuration_devices TO mdm_command_runtime;

GRANT UPDATE(operation) ON TABLE mdm_planning.configuration_objects TO mdm_command_runtime;

GRANT UPDATE(digest) ON TABLE mdm_planning.configuration_objects TO mdm_command_runtime;

GRANT UPDATE(diagnosis) ON TABLE mdm_planning.configuration_objects TO mdm_command_runtime;

GRANT SELECT ON TABLE mdm_planning.configuration_objects TO mdm_flow_runtime;
GRANT SELECT,INSERT ON TABLE mdm_planning.configuration_objects TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_planning.operations TO mdm_flow_runtime;

GRANT SELECT,INSERT ON TABLE mdm_planning.remote_operation_targets TO mdm_command_runtime;
GRANT SELECT ON TABLE mdm_planning.remote_operation_targets TO mdm_flow_runtime;

GRANT SELECT,INSERT ON TABLE mdm_planning.remote_operations TO mdm_flow_runtime;
GRANT SELECT ON TABLE mdm_planning.remote_operations TO mdm_command_runtime;

GRANT UPDATE(cancelled) ON TABLE mdm_planning.remote_operations TO mdm_flow_runtime;

GRANT UPDATE(staged) ON TABLE mdm_planning.remote_operations TO mdm_command_runtime;

GRANT UPDATE(cursor) ON TABLE mdm_planning.remote_operations TO mdm_command_runtime;

GRANT UPDATE(run_after) ON TABLE mdm_planning.remote_operations TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_planning.scope_results TO mdm_flow_runtime;
GRANT SELECT ON TABLE mdm_planning.scope_results TO mdm_command_runtime;

GRANT UPDATE(entry_revision) ON TABLE mdm_planning.scope_results TO mdm_flow_runtime;

GRANT SELECT,INSERT ON TABLE mdm_planning.scope_runs TO mdm_flow_runtime;

GRANT UPDATE(identity_revision) ON TABLE mdm_planning.scope_runs TO mdm_flow_runtime;

GRANT UPDATE(previous_resolution) ON TABLE mdm_planning.scope_runs TO mdm_flow_runtime;

GRANT UPDATE(semantic_changed) ON TABLE mdm_planning.scope_runs TO mdm_flow_runtime;

GRANT UPDATE(result_fingerprint) ON TABLE mdm_planning.scope_runs TO mdm_flow_runtime;

GRANT UPDATE(phase) ON TABLE mdm_planning.scope_runs TO mdm_flow_runtime;

GRANT UPDATE(source_index) ON TABLE mdm_planning.scope_runs TO mdm_flow_runtime;

GRANT UPDATE(source_cursor) ON TABLE mdm_planning.scope_runs TO mdm_flow_runtime;

GRANT UPDATE(evaluation_cursor) ON TABLE mdm_planning.scope_runs TO mdm_flow_runtime;

GRANT UPDATE(object_count) ON TABLE mdm_planning.scope_runs TO mdm_flow_runtime;

GRANT UPDATE(member_count) ON TABLE mdm_planning.scope_runs TO mdm_flow_runtime;

GRANT SELECT,INSERT ON TABLE mdm_planning.scope_source_members TO mdm_flow_runtime;

GRANT SELECT,INSERT,DELETE ON TABLE mdm_planning.scope_sources TO mdm_flow_runtime;

GRANT SELECT,INSERT ON TABLE mdm_planning.scope_versions TO mdm_flow_runtime;

GRANT SELECT,INSERT ON TABLE mdm_planning.scopes TO mdm_flow_runtime;
GRANT SELECT ON TABLE mdm_planning.scopes TO mdm_command_runtime;

GRANT UPDATE(revision) ON TABLE mdm_planning.scopes TO mdm_flow_runtime;

GRANT UPDATE(deleted) ON TABLE mdm_planning.scopes TO mdm_flow_runtime;

GRANT UPDATE(calculation_revision) ON TABLE mdm_planning.scopes TO mdm_flow_runtime;

GRANT UPDATE(resolution) ON TABLE mdm_planning.scopes TO mdm_flow_runtime;

GRANT UPDATE(resolution_revision) ON TABLE mdm_planning.scopes TO mdm_flow_runtime;

GRANT SELECT,INSERT ON TABLE mdm_planning.source_heads TO mdm_flow_runtime;

GRANT UPDATE(revision) ON TABLE mdm_planning.source_heads TO mdm_flow_runtime;

GRANT UPDATE(required_input) ON TABLE mdm_planning.source_heads TO mdm_flow_runtime;

GRANT UPDATE(observed_input) ON TABLE mdm_planning.source_heads TO mdm_flow_runtime;

GRANT SELECT,INSERT ON TABLE mdm_policy.policies TO mdm_policy_runtime;
GRANT SELECT ON TABLE mdm_policy.policies TO mdm_command_runtime;

GRANT UPDATE(revision) ON TABLE mdm_policy.policies TO mdm_policy_runtime;

GRANT UPDATE(current_version) ON TABLE mdm_policy.policies TO mdm_policy_runtime;

GRANT UPDATE(version_number) ON TABLE mdm_policy.policies TO mdm_policy_runtime;

GRANT UPDATE(enabled) ON TABLE mdm_policy.policies TO mdm_policy_runtime;

GRANT UPDATE(definition) ON TABLE mdm_policy.policies TO mdm_policy_runtime;

GRANT UPDATE(author) ON TABLE mdm_policy.policies TO mdm_policy_runtime;

GRANT UPDATE(updated_at) ON TABLE mdm_policy.policies TO mdm_policy_runtime;

GRANT SELECT,INSERT ON TABLE mdm_policy.requests TO mdm_policy_runtime;

GRANT SELECT,INSERT ON TABLE mdm_policy.triggers TO mdm_policy_runtime;
GRANT SELECT ON TABLE mdm_policy.triggers TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_policy.versions TO mdm_policy_runtime;
GRANT SELECT ON TABLE mdm_policy.versions TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_publication.operations TO mdm_flow_runtime;

GRANT SELECT,INSERT ON TABLE mdm_resource.aggregates TO mdm_resource_runtime;
GRANT SELECT ON TABLE mdm_resource.aggregates TO mdm_command_runtime;

GRANT UPDATE(revision) ON TABLE mdm_resource.aggregates TO mdm_resource_runtime;

GRANT UPDATE(document) ON TABLE mdm_resource.aggregates TO mdm_resource_runtime;

GRANT UPDATE(digest) ON TABLE mdm_resource.aggregates TO mdm_resource_runtime;

GRANT SELECT,INSERT ON TABLE mdm_resource.artifact_refs TO mdm_resource_runtime;

GRANT UPDATE(archived) ON TABLE mdm_resource.artifact_refs TO mdm_resource_runtime;

GRANT SELECT,INSERT ON TABLE mdm_resource.immutable TO mdm_resource_runtime;
GRANT SELECT ON TABLE mdm_resource.immutable TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_resource.requests TO mdm_resource_runtime;

GRANT SELECT,INSERT ON TABLE mdm_resource_catalog.operations TO mdm_flow_runtime;

GRANT SELECT,INSERT ON TABLE mdm_software.approvals TO mdm_flow_runtime;
GRANT SELECT ON TABLE mdm_software.approvals TO mdm_command_runtime;

GRANT UPDATE(admission) ON TABLE mdm_software.approvals TO mdm_flow_runtime;

GRANT SELECT,INSERT ON TABLE mdm_software.materials TO mdm_flow_runtime;
GRANT SELECT ON TABLE mdm_software.materials TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_software.operations TO mdm_flow_runtime;

GRANT SELECT,INSERT ON TABLE mdm_software.sources TO mdm_flow_runtime;
GRANT SELECT ON TABLE mdm_software.sources TO mdm_command_runtime;

GRANT UPDATE(admission) ON TABLE mdm_software.sources TO mdm_flow_runtime;

GRANT SELECT,INSERT ON TABLE mdm_software_composition.authorities TO mdm_software_driver;

GRANT UPDATE(candidate) ON TABLE mdm_software_composition.authorities TO mdm_software_driver;

GRANT SELECT,INSERT ON TABLE mdm_software_composition.bindings TO mdm_software_driver;

GRANT SELECT,INSERT,DELETE ON TABLE mdm_software_composition.projections TO mdm_software_driver;

GRANT UPDATE(publication) ON TABLE mdm_software_composition.projections TO mdm_software_driver;

GRANT SELECT,INSERT ON TABLE mdm_software_composition.slots TO mdm_software_driver;

GRANT UPDATE(operation) ON TABLE mdm_software_composition.slots TO mdm_software_driver;

GRANT UPDATE(cursor) ON TABLE mdm_software_composition.slots TO mdm_software_driver;

GRANT SELECT,INSERT ON TABLE mdm_software_composition.subjects TO mdm_software_driver;
GRANT SELECT ON TABLE mdm_software_composition.subjects TO mdm_flow_runtime;

GRANT SELECT,INSERT ON TABLE mdm_software_composition.targets TO mdm_software_driver;

GRANT UPDATE(call_generation) ON TABLE mdm_software_composition.targets TO mdm_software_driver;

GRANT UPDATE(attempted) ON TABLE mdm_software_composition.targets TO mdm_software_driver;

GRANT UPDATE(acknowledged) ON TABLE mdm_software_composition.targets TO mdm_software_driver;

GRANT SELECT,INSERT ON TABLE mdm_software_composition.withdrawals TO mdm_software_driver;

GRANT UPDATE(complete) ON TABLE mdm_software_composition.withdrawals TO mdm_software_driver;

GRANT SELECT,INSERT ON TABLE mdm_software_release.aggregates TO mdm_software_release_runtime;

GRANT UPDATE(revision) ON TABLE mdm_software_release.aggregates TO mdm_software_release_runtime;

GRANT UPDATE(document) ON TABLE mdm_software_release.aggregates TO mdm_software_release_runtime;

GRANT UPDATE(digest) ON TABLE mdm_software_release.aggregates TO mdm_software_release_runtime;

GRANT SELECT,INSERT ON TABLE mdm_software_release.immutable TO mdm_software_release_runtime;

GRANT SELECT,INSERT ON TABLE mdm_software_release.requests TO mdm_software_release_runtime;

GRANT SELECT ON TABLE rss_device_command.commands TO mdm_command_runtime;

GRANT SELECT,INSERT,UPDATE ON TABLE rss_transactional_messaging.dr_members TO rss_tmsg_relay;

GRANT SELECT,INSERT,UPDATE ON TABLE rss_transactional_messaging.dr_plans TO rss_tmsg_relay;

GRANT SELECT ON TABLE rss_transactional_messaging.inbox TO rss_tmsg_relay;
GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE rss_transactional_messaging.inbox TO mdm_identity_audit;
GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE rss_transactional_messaging.inbox TO mdm_command_runtime;

GRANT SELECT,INSERT,UPDATE ON TABLE rss_transactional_messaging.outbox TO rss_tmsg_relay;
GRANT SELECT ON TABLE rss_transactional_messaging.outbox TO mdm_resource_runtime;
GRANT SELECT ON TABLE rss_transactional_messaging.outbox TO mdm_software_release_runtime;
GRANT SELECT ON TABLE rss_transactional_messaging.outbox TO mdm_group_runtime;
GRANT SELECT ON TABLE rss_transactional_messaging.outbox TO mdm_policy_runtime;
GRANT SELECT ON TABLE rss_transactional_messaging.outbox TO mdm_identity_runtime;
GRANT SELECT ON TABLE rss_transactional_messaging.outbox TO mdm_identity_maintenance;
GRANT SELECT ON TABLE rss_transactional_messaging.outbox TO mdm_identity_audit;
GRANT SELECT ON TABLE rss_transactional_messaging.outbox TO mdm_command_runtime;

GRANT SELECT,INSERT,UPDATE ON TABLE rss_transactional_messaging.outbox_partitions TO rss_tmsg_relay;

GRANT USAGE ON SEQUENCE rss_transactional_messaging.outbox_seq_seq TO rss_tmsg_relay;

GRANT SELECT ON TABLE rss_transactional_messaging.policy TO mdm_resource_runtime;
GRANT SELECT ON TABLE rss_transactional_messaging.policy TO mdm_software_release_runtime;
GRANT SELECT ON TABLE rss_transactional_messaging.policy TO mdm_group_runtime;
GRANT SELECT ON TABLE rss_transactional_messaging.policy TO mdm_policy_runtime;
GRANT SELECT ON TABLE rss_transactional_messaging.policy TO mdm_identity_runtime;
GRANT SELECT ON TABLE rss_transactional_messaging.policy TO mdm_identity_maintenance;
GRANT SELECT ON TABLE rss_transactional_messaging.policy TO mdm_identity_audit;
GRANT SELECT ON TABLE rss_transactional_messaging.policy TO mdm_command_runtime;

GRANT SELECT ON TABLE rss_transactional_messaging.storage_lineage TO rss_tmsg_relay;

GRANT UPDATE(singleton) ON TABLE rss_transactional_messaging.storage_lineage TO rss_tmsg_relay;

GRANT SELECT,UPDATE ON TABLE rss_transactional_messaging.tenant_epoch TO rss_tmsg_relay;

-- Native peer registration reads frozen install authority under the access/audit transaction.
GRANT USAGE ON SCHEMA mdm_commands,mdm_policy,mdm_resource,mdm_software,mdm_planning TO mdm_access;
GRANT SELECT ON TABLE mdm_commands.operations,mdm_commands.attempts,mdm_commands.attempt_items,mdm_policy.policies,mdm_policy.versions,mdm_resource.aggregates,mdm_resource.immutable,mdm_software.sources,mdm_software.approvals TO mdm_access;
GRANT EXECUTE ON FUNCTION mdm_planning.scope_admission(uuid,text),mdm_commands.installation_status(uuid) TO mdm_access;

GRANT SELECT,INSERT ON mdm_commands.output_chunks TO mdm_command_runtime;
COMMIT;

ALTER TABLE mdm_commands.attempt_items ADD CONSTRAINT attempt_items_attempt_fkey FOREIGN KEY(tenant_id,attempt) REFERENCES mdm_commands.attempts(tenant_id,id);
GRANT SELECT,INSERT ON TABLE mdm_commands.attempt_items TO mdm_command_runtime;
ALTER TABLE mdm_planning.configuration_objects ADD CONSTRAINT configuration_objects_operation_fkey FOREIGN KEY(tenant_id,operation) REFERENCES mdm_commands.operations(tenant_id,id);

GRANT SELECT,INSERT ON TABLE mdm_flow.native_protection TO mdm_flow_runtime;
