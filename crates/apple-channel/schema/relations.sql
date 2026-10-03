-- Fresh installation: apple-channel owns these objects.
BEGIN;
SET LOCAL check_function_bodies = false;

ALTER TABLE mdm_apple.declarations ADD CONSTRAINT declarations_registration_fkey FOREIGN KEY(tenant_id,registration) REFERENCES mdm_access.registrations(tenant_id,id);
ALTER TABLE mdm_apple.declarations ADD CONSTRAINT declarations_operation_fkey FOREIGN KEY(tenant_id,operation) REFERENCES mdm_commands.operations(tenant_id,id);
ALTER TABLE mdm_apple.status_reports ADD CONSTRAINT status_reports_registration_fkey FOREIGN KEY(tenant_id,registration) REFERENCES mdm_access.registrations(tenant_id,id);
GRANT SELECT,INSERT ON mdm_apple.declarations,mdm_apple.status_reports TO mdm_command_runtime;
GRANT UPDATE(retired_at,legacy_released_at,projection) ON mdm_apple.declarations TO mdm_command_runtime;
GRANT SELECT ON mdm_apple.declarations,mdm_apple.status_reports TO mdm_access;
GRANT UPDATE(retired_at) ON mdm_apple.declarations TO mdm_access;

ALTER TABLE mdm_apple.profiles ADD CONSTRAINT profiles_device_fkey FOREIGN KEY(tenant_id,device) REFERENCES mdm_access.devices(tenant_id,id);
ALTER TABLE mdm_apple.profiles ADD CONSTRAINT profiles_registration_fkey FOREIGN KEY(tenant_id,registration) REFERENCES mdm_access.registrations(tenant_id,id);
ALTER TABLE mdm_apple.profiles ADD CONSTRAINT profiles_operation_fkey FOREIGN KEY(tenant_id,operation) REFERENCES mdm_commands.operations(tenant_id,id);
GRANT SELECT,INSERT ON mdm_apple.profiles TO mdm_command_runtime;
GRANT UPDATE(manifest,dispatched_at,observed_at,retired_at) ON mdm_apple.profiles TO mdm_command_runtime;
GRANT SELECT ON mdm_apple.profiles TO mdm_access;
GRANT UPDATE(retired_at) ON mdm_apple.profiles TO mdm_access;

ALTER TABLE ONLY mdm_apple.attempts
    ADD CONSTRAINT attempts_tenant_id_certificate_fkey FOREIGN KEY (tenant_id, certificate) REFERENCES mdm_apple.scep_attempts(tenant_id, id);

ALTER TABLE ONLY mdm_apple.attempts
    ADD CONSTRAINT attempts_tenant_id_collection_fkey FOREIGN KEY (tenant_id, collection) REFERENCES mdm_access.collection_runs(tenant_id, id);

ALTER TABLE ONLY mdm_apple.attempts
    ADD CONSTRAINT attempts_tenant_id_operation_fkey FOREIGN KEY (tenant_id, operation) REFERENCES mdm_commands.operations(tenant_id, id);

ALTER TABLE ONLY mdm_apple.attempts
    ADD CONSTRAINT attempts_tenant_id_registration_fkey FOREIGN KEY (tenant_id, registration) REFERENCES mdm_access.registrations(tenant_id, id);

ALTER TABLE ONLY mdm_apple.devices
    ADD CONSTRAINT devices_tenant_id_registration_fkey FOREIGN KEY (tenant_id, registration) REFERENCES mdm_access.registrations(tenant_id, id);

ALTER TABLE ONLY mdm_apple.scep_attempts
    ADD CONSTRAINT scep_attempts_tenant_id_enrollment_fkey FOREIGN KEY (tenant_id, enrollment) REFERENCES mdm_access.requests(tenant_id, id);

ALTER TABLE ONLY mdm_apple.scep_attempts
    ADD CONSTRAINT scep_attempts_tenant_id_registration_fkey FOREIGN KEY (tenant_id, registration) REFERENCES mdm_access.registrations(tenant_id, id);

ALTER TABLE ONLY mdm_apple.scep_attempts
    ADD CONSTRAINT scep_attempts_tenant_id_renewal_of_fkey FOREIGN KEY (tenant_id, renewal_of) REFERENCES mdm_apple.scep_attempts(tenant_id, id);

GRANT USAGE ON SCHEMA mdm_apple TO mdm_access;
GRANT USAGE ON SCHEMA mdm_apple TO mdm_command_runtime;
GRANT USAGE ON SCHEMA mdm_apple TO mdm_flow_runtime;

GRANT SELECT,INSERT ON TABLE mdm_apple.attempts TO mdm_access;
GRANT SELECT,INSERT ON TABLE mdm_apple.attempts TO mdm_command_runtime;

GRANT UPDATE(state) ON TABLE mdm_apple.attempts TO mdm_access;
GRANT UPDATE(state) ON TABLE mdm_apple.attempts TO mdm_command_runtime;

GRANT UPDATE(response) ON TABLE mdm_apple.attempts TO mdm_access;
GRANT UPDATE(response) ON TABLE mdm_apple.attempts TO mdm_command_runtime;

GRANT UPDATE(response_digest) ON TABLE mdm_apple.attempts TO mdm_access;
GRANT UPDATE(response_digest) ON TABLE mdm_apple.attempts TO mdm_command_runtime;

GRANT UPDATE(native_outcome) ON mdm_apple.attempts TO mdm_access, mdm_command_runtime;
GRANT UPDATE(accepted) ON TABLE mdm_apple.attempts TO mdm_access;
GRANT UPDATE(accepted) ON TABLE mdm_apple.attempts TO mdm_command_runtime;

GRANT UPDATE(received_at) ON TABLE mdm_apple.attempts TO mdm_access;
GRANT UPDATE(received_at) ON TABLE mdm_apple.attempts TO mdm_command_runtime;

GRANT UPDATE(next_attempt) ON TABLE mdm_apple.attempts TO mdm_access;
GRANT UPDATE(next_attempt) ON TABLE mdm_apple.attempts TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_apple.devices TO mdm_access;
GRANT SELECT ON TABLE mdm_apple.devices TO mdm_command_runtime;
GRANT SELECT(tenant_id,registration,state,access_rights) ON TABLE mdm_apple.devices TO mdm_flow_runtime;

GRANT UPDATE(state) ON TABLE mdm_apple.devices TO mdm_access;
GRANT UPDATE(state) ON TABLE mdm_apple.devices TO mdm_command_runtime;

GRANT UPDATE(identity_health,bootstrap,bootstrap_revision) ON mdm_apple.devices TO mdm_access;
ALTER TABLE mdm_apple.channels ADD CONSTRAINT channels_registration_fkey FOREIGN KEY(tenant_id,registration) REFERENCES mdm_apple.devices(tenant_id,registration);
GRANT SELECT,INSERT ON mdm_apple.channels TO mdm_access;
GRANT UPDATE(state,material,material_digest,token_revision,push_id,push_lease_until,next_push,push_failures,push_status,push_outcome) ON mdm_apple.channels TO mdm_access;
GRANT SELECT ON mdm_apple.channels TO mdm_command_runtime;
GRANT UPDATE(state,material,material_digest,push_id,push_lease_until,next_push,push_configuration,push_failures,push_status,push_outcome) ON mdm_apple.channels TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_apple.scep_attempts TO mdm_access;

GRANT UPDATE(state) ON TABLE mdm_apple.scep_attempts TO mdm_access;

GRANT UPDATE(transaction_id) ON TABLE mdm_apple.scep_attempts TO mdm_access;

GRANT UPDATE(csr_digest) ON TABLE mdm_apple.scep_attempts TO mdm_access;

GRANT UPDATE(spki) ON TABLE mdm_apple.scep_attempts TO mdm_access;

GRANT UPDATE(serial) ON TABLE mdm_apple.scep_attempts TO mdm_access;

GRANT UPDATE(fingerprint) ON TABLE mdm_apple.scep_attempts TO mdm_access;

GRANT UPDATE(certificate) ON TABLE mdm_apple.scep_attempts TO mdm_access;

GRANT UPDATE(registration) ON TABLE mdm_apple.scep_attempts TO mdm_access;

GRANT UPDATE(not_before) ON TABLE mdm_apple.scep_attempts TO mdm_access;

GRANT UPDATE(not_after) ON TABLE mdm_apple.scep_attempts TO mdm_access;
COMMIT;
