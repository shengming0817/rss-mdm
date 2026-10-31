-- Fresh installation: windows-channel owns these objects.
BEGIN;
SET LOCAL check_function_bodies = false;

ALTER TABLE ONLY mdm_access.enrollment_certificates
    ADD CONSTRAINT enrollment_certificates_tenant_id_request_id_fkey FOREIGN KEY (tenant_id, request_id) REFERENCES mdm_access.enrollment_intents(tenant_id, request_id);

ALTER TABLE ONLY mdm_access.enrollment_intents
    ADD CONSTRAINT enrollment_intents_tenant_id_request_id_fkey FOREIGN KEY (tenant_id, request_id) REFERENCES mdm_access.requests(tenant_id, id);

ALTER TABLE ONLY mdm_access.management_messages
    ADD CONSTRAINT management_messages_tenant_id_registration_session_id_fkey FOREIGN KEY (tenant_id, registration, session_id) REFERENCES mdm_access.management_sessions(tenant_id, registration, session_id);

ALTER TABLE ONLY mdm_access.management_sessions
    ADD CONSTRAINT management_sessions_tenant_id_credential_fkey FOREIGN KEY (tenant_id, credential) REFERENCES mdm_access.credentials(tenant_id, id);

ALTER TABLE ONLY mdm_access.management_sessions
    ADD CONSTRAINT management_sessions_tenant_id_registration_fkey FOREIGN KEY (tenant_id, registration) REFERENCES mdm_access.registrations(tenant_id, id);

GRANT USAGE ON SCHEMA mdm_windows TO mdm_access,mdm_policy_runtime;

GRANT SELECT,INSERT ON TABLE mdm_access.enrollment_certificates TO mdm_access;
GRANT SELECT ON TABLE mdm_access.enrollment_certificates TO mdm_command_runtime;

GRANT UPDATE(server_nonce) ON TABLE mdm_access.enrollment_certificates TO mdm_access;
GRANT UPDATE(server_nonce) ON TABLE mdm_access.enrollment_certificates TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_access.enrollment_intents TO mdm_access;
GRANT SELECT ON TABLE mdm_access.enrollment_intents TO mdm_command_runtime;

GRANT SELECT,INSERT,DELETE ON TABLE mdm_access.management_messages TO mdm_access;
GRANT SELECT,INSERT ON TABLE mdm_access.management_messages TO mdm_command_runtime;

GRANT SELECT,INSERT,DELETE ON TABLE mdm_access.management_sessions TO mdm_access;
GRANT SELECT,INSERT ON TABLE mdm_access.management_sessions TO mdm_command_runtime;

GRANT UPDATE(state) ON TABLE mdm_access.management_sessions TO mdm_access;
GRANT UPDATE(state) ON TABLE mdm_access.management_sessions TO mdm_command_runtime;

GRANT UPDATE(last_message) ON TABLE mdm_access.management_sessions TO mdm_access;
GRANT UPDATE(last_message) ON TABLE mdm_access.management_sessions TO mdm_command_runtime;

GRANT UPDATE(client_authenticated) ON TABLE mdm_access.management_sessions TO mdm_access;
GRANT UPDATE(client_authenticated) ON TABLE mdm_access.management_sessions TO mdm_command_runtime;


GRANT UPDATE(nonce) ON TABLE mdm_access.management_sessions TO mdm_access;
GRANT UPDATE(nonce) ON TABLE mdm_access.management_sessions TO mdm_command_runtime;

GRANT UPDATE(run_id) ON TABLE mdm_access.management_sessions TO mdm_access;
GRANT UPDATE(run_id) ON TABLE mdm_access.management_sessions TO mdm_command_runtime;

ALTER TABLE mdm_windows.collections ADD CONSTRAINT windows_collection_run FOREIGN KEY(tenant_id,id) REFERENCES mdm_access.collection_runs(tenant_id,id);
ALTER TABLE mdm_windows.collections ADD CONSTRAINT windows_collection_registration FOREIGN KEY(tenant_id,registration) REFERENCES mdm_access.registrations(tenant_id,id);
GRANT USAGE ON SCHEMA mdm_windows TO mdm_command_runtime;
GRANT SELECT,INSERT ON mdm_windows.collections TO mdm_access,mdm_command_runtime;
GRANT UPDATE(channel_state,template_state) ON mdm_windows.collections TO mdm_access,mdm_command_runtime;
ALTER TABLE mdm_windows.renewals ADD CONSTRAINT renewals_registration_fkey FOREIGN KEY(tenant_id,registration) REFERENCES mdm_access.registrations(tenant_id,id);
GRANT SELECT,INSERT ON mdm_windows.renewals TO mdm_access;
GRANT UPDATE(activated_at) ON mdm_windows.renewals TO mdm_access;
ALTER TABLE mdm_windows.push_channels ADD CONSTRAINT push_channels_registration_fkey FOREIGN KEY(tenant_id,registration) REFERENCES mdm_access.registrations(tenant_id,id);
ALTER TABLE mdm_windows.push_queries ADD CONSTRAINT push_queries_registration_fkey FOREIGN KEY(tenant_id,registration) REFERENCES mdm_access.registrations(tenant_id,id);
GRANT SELECT,INSERT ON mdm_windows.push_channels,mdm_windows.push_queries TO mdm_access,mdm_command_runtime;
GRANT UPDATE(generation,revision,configuration,uri,digest,attempt_until,next_push,lease_id,lease_until,settled_id,failures,status,outcome) ON mdm_windows.push_channels TO mdm_access,mdm_command_runtime;
GRANT UPDATE(results) ON mdm_windows.push_queries TO mdm_command_runtime;
GRANT DELETE ON mdm_windows.push_queries TO mdm_access;
ALTER TABLE mdm_windows.unenrollment_receipts ADD CONSTRAINT unenrollment_receipts_registration_fkey FOREIGN KEY(tenant_id,registration) REFERENCES mdm_access.registrations(tenant_id,id);
GRANT SELECT,INSERT ON mdm_windows.unenrollment_receipts TO mdm_access;
ALTER TABLE mdm_windows.linked_enrollments ADD CONSTRAINT linked_request FOREIGN KEY(tenant_id,request_id) REFERENCES mdm_access.requests(tenant_id,id);
ALTER TABLE mdm_windows.linked_enrollments ADD CONSTRAINT linked_parent FOREIGN KEY(tenant_id,parent_id,parent_generation) REFERENCES mdm_access.registrations(tenant_id,id,generation);
GRANT SELECT,INSERT ON mdm_windows.linked_enrollments TO mdm_access;
GRANT UPDATE(signing_attempt,profile,issuer) ON mdm_access.enrollment_intents TO mdm_access;
ALTER TABLE ONLY mdm_windows.attempts
    ADD CONSTRAINT attempts_tenant_id_credential_fkey FOREIGN KEY (tenant_id, credential) REFERENCES mdm_access.credentials(tenant_id, id);

ALTER TABLE ONLY mdm_windows.attempts
    ADD CONSTRAINT attempts_tenant_id_operation_fkey FOREIGN KEY (tenant_id, operation,registration,generation) REFERENCES mdm_windows.native_commands(tenant_id,id,registration,registration_generation);

ALTER TABLE ONLY mdm_windows.capabilities
    ADD CONSTRAINT capabilities_tenant_id_registration_fkey FOREIGN KEY (tenant_id, registration) REFERENCES mdm_access.registrations(tenant_id, id);

ALTER TABLE ONLY mdm_windows.capability_queries
    ADD CONSTRAINT capability_queries_tenant_id_registration_fkey FOREIGN KEY (tenant_id, registration) REFERENCES mdm_access.registrations(tenant_id, id);

ALTER TABLE ONLY mdm_windows.capability_queries
    ADD CONSTRAINT capability_queries_tenant_id_registration_session_id_fkey FOREIGN KEY (tenant_id, registration, session_id) REFERENCES mdm_access.management_sessions(tenant_id, registration, session_id) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

GRANT SELECT,INSERT ON TABLE mdm_windows.attempts TO mdm_command_runtime;

GRANT UPDATE(status) ON TABLE mdm_windows.attempt_items TO mdm_command_runtime;

GRANT UPDATE(value) ON TABLE mdm_windows.attempt_items TO mdm_command_runtime;

GRANT UPDATE(received_at) ON TABLE mdm_windows.attempt_items TO mdm_command_runtime;

GRANT UPDATE(receipt_accepted,result_accepted,result_received_at) ON TABLE mdm_windows.attempt_items TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_windows.capabilities TO mdm_command_runtime;

GRANT SELECT ON TABLE mdm_windows.capabilities TO mdm_policy_runtime;

GRANT UPDATE(generation) ON TABLE mdm_windows.capabilities TO mdm_command_runtime;

GRANT UPDATE(os_version) ON TABLE mdm_windows.capabilities TO mdm_command_runtime;

GRANT UPDATE(edition) ON TABLE mdm_windows.capabilities TO mdm_command_runtime;

GRANT UPDATE(session) ON TABLE mdm_windows.capabilities TO mdm_command_runtime;

GRANT UPDATE(observed_at) ON TABLE mdm_windows.capabilities TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_windows.capability_queries TO mdm_command_runtime;

GRANT UPDATE(os_version) ON TABLE mdm_windows.capability_queries TO mdm_command_runtime;

GRANT UPDATE(edition) ON TABLE mdm_windows.capability_queries TO mdm_command_runtime;

GRANT UPDATE(version_status) ON TABLE mdm_windows.capability_queries TO mdm_command_runtime;

GRANT UPDATE(edition_status) ON TABLE mdm_windows.capability_queries TO mdm_command_runtime;

ALTER TABLE mdm_windows.attempt_items ADD CONSTRAINT attempt_items_attempt_fkey FOREIGN KEY(tenant_id,attempt) REFERENCES mdm_windows.attempts(tenant_id,id);

GRANT SELECT,INSERT ON TABLE mdm_windows.attempt_items TO mdm_command_runtime;

ALTER TABLE mdm_windows.attempt_frames ADD CONSTRAINT attempt_frames_attempt_fkey FOREIGN KEY(tenant_id,attempt) REFERENCES mdm_windows.attempts(tenant_id,id);

GRANT SELECT,INSERT ON TABLE mdm_windows.attempt_frames TO mdm_command_runtime;

GRANT UPDATE(status,accepted,received_at) ON TABLE mdm_windows.attempt_frames TO mdm_command_runtime;

GRANT SELECT ON mdm_windows.attempts,mdm_windows.attempt_items,mdm_windows.attempt_frames,mdm_windows.capabilities TO mdm_policy_runtime;
ALTER TABLE mdm_windows.attempts ADD FOREIGN KEY(tenant_id,registration) REFERENCES mdm_access.registrations(tenant_id,id);

GRANT SELECT ON TABLE mdm_windows.attempts, mdm_windows.attempt_items TO mdm_access;

COMMIT;
