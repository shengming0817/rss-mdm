-- Fresh installation: execution owns these objects.
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

GRANT USAGE ON SCHEMA mdm_commands TO mdm_command_runtime;

GRANT USAGE ON SCHEMA mdm_commands TO mdm_flow_runtime;

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

GRANT SELECT,INSERT ON TABLE mdm_planning.remote_operation_targets TO mdm_command_runtime;

GRANT SELECT ON TABLE mdm_planning.remote_operation_targets TO mdm_flow_runtime;

GRANT SELECT ON TABLE mdm_planning.remote_operations TO mdm_flow_runtime;

GRANT SELECT,INSERT ON TABLE mdm_planning.remote_operations TO mdm_command_runtime;

GRANT UPDATE(cancelled) ON TABLE mdm_planning.remote_operations TO mdm_command_runtime;

GRANT UPDATE(staged) ON TABLE mdm_planning.remote_operations TO mdm_command_runtime;

GRANT UPDATE(cursor) ON TABLE mdm_planning.remote_operations TO mdm_command_runtime;

GRANT UPDATE(run_after) ON TABLE mdm_planning.remote_operations TO mdm_command_runtime;

GRANT USAGE ON SCHEMA mdm_commands TO mdm_access;

GRANT SELECT ON TABLE mdm_commands.operations, mdm_commands.attempts, mdm_commands.attempt_items TO mdm_access;

GRANT EXECUTE ON FUNCTION mdm_commands.installation_status(uuid) TO mdm_access;

GRANT SELECT,INSERT ON mdm_commands.output_chunks TO mdm_command_runtime;

ALTER TABLE mdm_commands.attempt_items ADD CONSTRAINT attempt_items_attempt_fkey FOREIGN KEY(tenant_id,attempt) REFERENCES mdm_commands.attempts(tenant_id,id);

GRANT SELECT,INSERT ON TABLE mdm_commands.attempt_items TO mdm_command_runtime;

ALTER TABLE mdm_planning.configuration_objects ADD CONSTRAINT configuration_objects_operation_fkey FOREIGN KEY(tenant_id,operation) REFERENCES mdm_commands.operations(tenant_id,id);

GRANT SELECT,INSERT ON TABLE mdm_flow.native_protection TO mdm_flow_runtime;

GRANT USAGE ON SCHEMA mdm_flow TO mdm_command_runtime;

GRANT SELECT, INSERT ON mdm_flow.native_protection TO mdm_command_runtime;
GRANT USAGE ON SCHEMA rss_device_command TO mdm_access;
GRANT SELECT ON rss_device_command.commands TO mdm_access;
GRANT EXECUTE ON FUNCTION rss_device_command.save(uuid,uuid,text,bigint,text,bigint,bigint,bigint) TO mdm_access;
GRANT SELECT ON mdm_commands.action_runs TO mdm_access;
GRANT UPDATE(state,revision) ON mdm_commands.action_runs TO mdm_access;
COMMIT;

ALTER TABLE mdm_commands.attempt_frames ADD CONSTRAINT attempt_frames_attempt_fkey FOREIGN KEY(tenant_id,attempt) REFERENCES mdm_commands.attempts(tenant_id,id);
GRANT SELECT,INSERT ON TABLE mdm_commands.attempt_frames TO mdm_command_runtime;
GRANT UPDATE(status,accepted,received_at) ON TABLE mdm_commands.attempt_frames TO mdm_command_runtime;
