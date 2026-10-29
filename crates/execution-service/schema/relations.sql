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

ALTER TABLE ONLY mdm_commands.policy_recovery
    ADD CONSTRAINT policy_recovery_tenant_id_policy_fkey FOREIGN KEY (tenant_id, policy) REFERENCES mdm_policy.policies(tenant_id, id);

ALTER TABLE ONLY mdm_commands.requests
    ADD CONSTRAINT requests_tenant_id_operation_fkey FOREIGN KEY (tenant_id, operation) REFERENCES mdm_commands.operations(tenant_id, id);

ALTER TABLE ONLY mdm_planning.configuration_claims
    ADD CONSTRAINT configuration_claims_tenant_id_policy_fkey FOREIGN KEY (tenant_id, policy) REFERENCES mdm_policy.policies(tenant_id, id);

ALTER TABLE ONLY mdm_planning.configuration_claims
    ADD CONSTRAINT configuration_claims_tenant_id_version_fkey FOREIGN KEY (tenant_id, version) REFERENCES mdm_policy.versions(tenant_id, id);

GRANT USAGE ON SCHEMA mdm_commands TO mdm_command_runtime;

GRANT USAGE ON SCHEMA mdm_commands TO mdm_policy_runtime;

GRANT SELECT,INSERT ON TABLE mdm_commands.action_attempts TO mdm_command_runtime;

GRANT UPDATE(permit) ON TABLE mdm_commands.action_attempts TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_commands.action_polls TO mdm_command_runtime;

GRANT UPDATE(cancellation_after) ON TABLE mdm_commands.action_polls TO mdm_command_runtime;

GRANT UPDATE(policy_after) ON TABLE mdm_commands.action_polls TO mdm_command_runtime;

GRANT UPDATE(profiles) ON TABLE mdm_commands.action_polls TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_commands.action_receipts TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_commands.action_runs TO mdm_command_runtime;

GRANT UPDATE(state) ON TABLE mdm_commands.action_runs TO mdm_command_runtime;

GRANT UPDATE(gateway_accepted) ON TABLE mdm_commands.action_runs TO mdm_command_runtime;

GRANT UPDATE(result) ON TABLE mdm_commands.action_runs TO mdm_command_runtime;

GRANT UPDATE(invocation,source_objects) ON TABLE mdm_commands.action_runs TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_commands.attempts TO mdm_command_runtime;

GRANT UPDATE(status) ON TABLE mdm_commands.attempt_items TO mdm_command_runtime;

GRANT UPDATE(value) ON TABLE mdm_commands.attempt_items TO mdm_command_runtime;

GRANT UPDATE(received_at) ON TABLE mdm_commands.attempt_items TO mdm_command_runtime;

GRANT UPDATE(receipt_accepted,result_accepted,result_received_at) ON TABLE mdm_commands.attempt_items TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_commands.capabilities TO mdm_command_runtime;

GRANT SELECT ON TABLE mdm_commands.capabilities TO mdm_policy_runtime;

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

GRANT SELECT ON TABLE mdm_commands.operations TO mdm_policy_runtime;

GRANT UPDATE(authority) ON TABLE mdm_commands.operations TO mdm_command_runtime;

GRANT UPDATE(revision) ON TABLE mdm_commands.operations TO mdm_command_runtime;

GRANT UPDATE(gateway_accepted,dispatch_failure) ON TABLE mdm_commands.operations TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_commands.policy_recovery TO mdm_command_runtime;

GRANT UPDATE(recovery_after,target_after,input_revision,input_consumed,input_window) ON TABLE mdm_commands.policy_recovery TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_commands.requests TO mdm_command_runtime;

GRANT SELECT,INSERT,DELETE ON TABLE mdm_planning.configuration_claims TO mdm_command_runtime;

GRANT SELECT ON TABLE mdm_planning.configuration_claims TO mdm_policy_runtime,mdm_resource_runtime;

GRANT UPDATE(version) ON TABLE mdm_planning.configuration_claims TO mdm_command_runtime;

GRANT UPDATE(operation) ON TABLE mdm_planning.configuration_claims TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_planning.configuration_devices TO mdm_scope_runtime,mdm_policy_runtime;

GRANT SELECT,INSERT ON TABLE mdm_planning.configuration_devices TO mdm_command_runtime;

GRANT UPDATE(input_revision) ON TABLE mdm_planning.configuration_devices TO mdm_scope_runtime,mdm_policy_runtime;

GRANT UPDATE(input_revision) ON TABLE mdm_planning.configuration_devices TO mdm_command_runtime;

GRANT UPDATE(observed_revision) ON TABLE mdm_planning.configuration_devices TO mdm_command_runtime;

GRANT UPDATE(operation) ON TABLE mdm_planning.configuration_objects TO mdm_command_runtime;

GRANT UPDATE(digest) ON TABLE mdm_planning.configuration_objects TO mdm_command_runtime;

GRANT UPDATE(diagnosis) ON TABLE mdm_planning.configuration_objects TO mdm_command_runtime;

GRANT SELECT ON TABLE mdm_planning.configuration_objects TO mdm_policy_runtime,mdm_resource_runtime;

GRANT SELECT,INSERT ON TABLE mdm_planning.configuration_objects TO mdm_command_runtime;

GRANT USAGE ON SCHEMA mdm_commands TO mdm_access;

GRANT SELECT ON TABLE mdm_commands.operations, mdm_commands.attempts, mdm_commands.attempt_items TO mdm_access;

GRANT EXECUTE ON FUNCTION mdm_commands.installation_status(uuid) TO mdm_access,mdm_command_runtime;

GRANT SELECT,INSERT ON mdm_commands.output_chunks TO mdm_command_runtime;

ALTER TABLE mdm_commands.attempt_items ADD CONSTRAINT attempt_items_attempt_fkey FOREIGN KEY(tenant_id,attempt) REFERENCES mdm_commands.attempts(tenant_id,id);

GRANT SELECT,INSERT ON TABLE mdm_commands.attempt_items TO mdm_command_runtime;

ALTER TABLE mdm_planning.configuration_objects ADD CONSTRAINT configuration_objects_operation_fkey FOREIGN KEY(tenant_id,operation) REFERENCES mdm_commands.operations(tenant_id,id);

GRANT SELECT,INSERT ON TABLE mdm_flow.native_protection TO mdm_policy_runtime;

GRANT USAGE ON SCHEMA mdm_flow TO mdm_command_runtime;

GRANT SELECT, INSERT ON mdm_flow.native_protection TO mdm_command_runtime;
GRANT SELECT ON mdm_commands.action_runs TO mdm_access;
GRANT EXECUTE ON FUNCTION mdm_commands.windows_pending_operations(uuid,bigint,uuid) TO mdm_access;
GRANT EXECUTE ON FUNCTION mdm_commands.windows_wake_candidates(uuid) TO mdm_access;
GRANT EXECUTE ON FUNCTION mdm_commands.retirement_commands(uuid,text),mdm_commands.save_retired_command(uuid,uuid,bigint,bigint) TO mdm_access,mdm_command_runtime;
GRANT EXECUTE ON FUNCTION mdm_commands.save_retired_action(uuid,uuid,jsonb,jsonb) TO mdm_access,mdm_command_runtime;
GRANT UPDATE(software_effect) ON mdm_commands.action_runs TO mdm_command_runtime;
GRANT UPDATE(execution_material) ON mdm_commands.action_attempts TO mdm_command_runtime;
COMMIT;

ALTER TABLE mdm_commands.attempt_frames ADD CONSTRAINT attempt_frames_attempt_fkey FOREIGN KEY(tenant_id,attempt) REFERENCES mdm_commands.attempts(tenant_id,id);
GRANT SELECT,INSERT ON TABLE mdm_commands.attempt_frames TO mdm_command_runtime;
GRANT UPDATE(status,accepted,received_at) ON TABLE mdm_commands.attempt_frames TO mdm_command_runtime;

ALTER TABLE mdm_commands.software_stage_stats ADD FOREIGN KEY(tenant_id,version) REFERENCES mdm_policy.versions(tenant_id,id);
GRANT SELECT,INSERT ON mdm_commands.software_stage_stats TO mdm_command_runtime;
GRANT UPDATE(gate_open,input,cursor,ready,counts,generation,membership_complete) ON mdm_commands.software_stage_stats TO mdm_command_runtime;
GRANT SELECT ON mdm_commands.software_binding_revisions TO mdm_command_runtime;
CREATE TRIGGER software_bindings AFTER INSERT OR UPDATE OR DELETE ON mdm_agent.bindings FOR EACH ROW EXECUTE FUNCTION mdm_commands.advance_software_bindings();

ALTER TABLE mdm_commands.software_stats_members ADD FOREIGN KEY(tenant_id,version,stage) REFERENCES mdm_commands.software_stage_stats(tenant_id,version,stage);
ALTER TABLE mdm_commands.software_result_changes ADD FOREIGN KEY(tenant_id,policy) REFERENCES mdm_policy.policies(tenant_id,id);
GRANT SELECT,INSERT ON mdm_commands.software_stats_members TO mdm_command_runtime;
GRANT UPDATE(generation,target,counts,waiting_until) ON mdm_commands.software_stats_members TO mdm_command_runtime;
GRANT SELECT ON mdm_commands.software_result_changes,mdm_commands.software_binding_changes TO mdm_command_runtime;

ALTER TABLE mdm_commands.native_checkins ADD FOREIGN KEY (tenant_id,registration) REFERENCES mdm_access.registrations(tenant_id,id);
GRANT SELECT,INSERT ON mdm_commands.native_checkins TO mdm_command_runtime;
GRANT UPDATE(active_event,active_at,policy_after,pending_event,pending_at) ON mdm_commands.native_checkins TO mdm_command_runtime;

GRANT SELECT(tenant_id,registration,profiles) ON mdm_commands.action_polls TO mdm_policy_runtime;

GRANT UPDATE(access_binding) ON mdm_commands.action_runs TO mdm_command_runtime;
GRANT SELECT ON mdm_policy.policies,mdm_policy.versions TO mdm_access;

GRANT SELECT ON mdm.asset_clock TO mdm_command_runtime;

-- Policy authors may announce changed desired work, never consume or complete it.
GRANT SELECT(tenant_id,policy,input_revision),INSERT(tenant_id,policy,input_revision),UPDATE(input_revision) ON mdm_commands.policy_recovery TO mdm_policy_runtime;

-- Explicit integration privileges owned by this capability.
GRANT USAGE ON SCHEMA mdm_flow TO mdm_policy_runtime;

GRANT USAGE ON SCHEMA mdm_planning TO mdm_policy_runtime;

GRANT USAGE ON SCHEMA mdm_planning TO mdm_command_runtime;

-- Execution intent participation by the Policy transaction owner.
GRANT SELECT,INSERT ON mdm_commands.devices TO mdm_policy_runtime;
GRANT SELECT,INSERT ON mdm_commands.operations TO mdm_policy_runtime;
GRANT SELECT,INSERT ON mdm_commands.requests TO mdm_policy_runtime;
GRANT SELECT,INSERT ON mdm_commands.action_runs TO mdm_policy_runtime;
GRANT SELECT,INSERT ON mdm_commands.action_receipts TO mdm_policy_runtime;
GRANT SELECT,INSERT ON mdm_commands.policy_recovery TO mdm_policy_runtime;
GRANT SELECT,INSERT,DELETE ON mdm_planning.configuration_claims TO mdm_policy_runtime;
GRANT SELECT,INSERT ON mdm_planning.configuration_devices TO mdm_policy_runtime;
GRANT SELECT,INSERT ON mdm_planning.configuration_objects TO mdm_policy_runtime;
GRANT SELECT,INSERT ON mdm_flow.native_protection TO mdm_policy_runtime;
GRANT UPDATE(generation) ON mdm_commands.devices TO mdm_policy_runtime;
GRANT UPDATE(epoch) ON mdm_commands.devices TO mdm_policy_runtime;
GRANT UPDATE(registration) ON mdm_commands.devices TO mdm_policy_runtime;
GRANT UPDATE(registration_generation) ON mdm_commands.devices TO mdm_policy_runtime;
GRANT UPDATE(authority) ON mdm_commands.operations TO mdm_policy_runtime;
GRANT UPDATE(revision) ON mdm_commands.operations TO mdm_policy_runtime;
GRANT UPDATE(request) ON mdm_commands.operations TO mdm_policy_runtime;
GRANT UPDATE(state) ON mdm_commands.action_runs TO mdm_policy_runtime;
GRANT UPDATE(result) ON mdm_commands.action_runs TO mdm_policy_runtime;
GRANT UPDATE(invocation) ON mdm_commands.action_runs TO mdm_policy_runtime;
GRANT UPDATE(source_objects) ON mdm_commands.action_runs TO mdm_policy_runtime;
GRANT UPDATE(software_effect) ON mdm_commands.action_runs TO mdm_policy_runtime;
GRANT UPDATE(input_revision) ON mdm_commands.policy_recovery TO mdm_policy_runtime;
GRANT UPDATE(version) ON mdm_planning.configuration_claims TO mdm_policy_runtime;
GRANT UPDATE(operation) ON mdm_planning.configuration_claims TO mdm_policy_runtime;
GRANT UPDATE(input_revision) ON mdm_planning.configuration_devices TO mdm_policy_runtime;
GRANT UPDATE(observed_revision) ON mdm_planning.configuration_devices TO mdm_policy_runtime;
GRANT UPDATE(operation) ON mdm_planning.configuration_objects TO mdm_policy_runtime;
GRANT UPDATE(digest) ON mdm_planning.configuration_objects TO mdm_policy_runtime;
GRANT UPDATE(diagnosis) ON mdm_planning.configuration_objects TO mdm_policy_runtime;
GRANT USAGE ON SCHEMA mdm_commands,mdm_planning,mdm_flow TO mdm_policy_runtime;
GRANT SELECT ON mdm_commands.attempts,mdm_commands.attempt_items,mdm_commands.attempt_frames,mdm_commands.action_attempts,mdm_commands.action_polls,mdm_commands.capabilities,mdm_commands.scope_projection_runs,mdm_commands.scope_channel_results TO mdm_policy_runtime;

GRANT UPDATE(access_binding) ON mdm_commands.action_runs TO mdm_policy_runtime;
