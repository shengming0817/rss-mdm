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

GRANT USAGE ON SCHEMA mdm_windows TO mdm_access;

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

GRANT SELECT,INSERT ON TABLE mdm_windows.operations TO mdm_access;
ALTER TABLE mdm_windows.collections ADD CONSTRAINT windows_collection_run FOREIGN KEY(tenant_id,id) REFERENCES mdm_access.collection_runs(tenant_id,id);
ALTER TABLE mdm_windows.collections ADD CONSTRAINT windows_collection_registration FOREIGN KEY(tenant_id,registration) REFERENCES mdm_access.registrations(tenant_id,id);
GRANT USAGE ON SCHEMA mdm_windows TO mdm_command_runtime;
GRANT SELECT,INSERT ON mdm_windows.collections TO mdm_access,mdm_command_runtime;
GRANT UPDATE(channel_state) ON mdm_windows.collections TO mdm_access,mdm_command_runtime;
COMMIT;
