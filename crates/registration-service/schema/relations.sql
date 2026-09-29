-- Fresh installation: registration-service owns these objects.
BEGIN;
SET LOCAL check_function_bodies = false;

CREATE TRIGGER asset_authority AFTER INSERT OR DELETE OR UPDATE ON mdm_access.credentials FOR EACH ROW EXECUTE FUNCTION mdm_access.capture_asset_authority();

CREATE TRIGGER asset_authority AFTER INSERT OR DELETE OR UPDATE ON mdm_access.devices FOR EACH ROW EXECUTE FUNCTION mdm_access.capture_asset_authority();

CREATE TRIGGER asset_authority AFTER INSERT OR DELETE OR UPDATE ON mdm_access.registrations FOR EACH ROW EXECUTE FUNCTION mdm_access.capture_asset_authority();

CREATE TRIGGER asset_authority AFTER INSERT OR DELETE OR UPDATE ON mdm_access.report_sources FOR EACH ROW EXECUTE FUNCTION mdm_access.capture_asset_authority();

ALTER TABLE ONLY mdm_access.asset_authority_history
    ADD CONSTRAINT asset_authority_history_tenant_id_revision_fkey FOREIGN KEY (tenant_id, revision) REFERENCES mdm.asset_changes(tenant_id, revision);

ALTER TABLE ONLY mdm_access.credentials
    ADD CONSTRAINT credentials_tenant_id_registration_channel_fkey FOREIGN KEY (tenant_id, registration, channel) REFERENCES mdm_access.registrations(tenant_id, id, channel);

ALTER TABLE ONLY mdm_access.registrations
    ADD CONSTRAINT registrations_tenant_id_device_fkey FOREIGN KEY (tenant_id, device) REFERENCES mdm_access.devices(tenant_id, id);

ALTER TABLE ONLY mdm_access.registrations
    ADD CONSTRAINT registrations_tenant_id_request_id_fkey FOREIGN KEY (tenant_id, request_id) REFERENCES mdm_access.requests(tenant_id, id);

ALTER TABLE ONLY mdm_access.report_sources
    ADD CONSTRAINT report_sources_tenant_id_registration_fkey FOREIGN KEY (tenant_id, registration) REFERENCES mdm_access.registrations(tenant_id, id);

ALTER TABLE ONLY mdm_access.requests
    ADD CONSTRAINT requests_tenant_id_grant_id_fkey FOREIGN KEY (tenant_id, grant_id) REFERENCES mdm_access.grants(tenant_id, id);

GRANT USAGE ON SCHEMA mdm_access TO mdm_access;
GRANT USAGE ON SCHEMA mdm_access TO mdm_software_driver;
GRANT USAGE ON SCHEMA mdm_access TO mdm_flow_runtime;
GRANT USAGE ON SCHEMA mdm_access TO mdm_command_runtime;

REVOKE ALL ON FUNCTION mdm_access.capture_asset_authority() FROM PUBLIC;

GRANT SELECT ON TABLE mdm_access.asset_authority_history TO mdm_flow_runtime;

GRANT SELECT,INSERT ON TABLE mdm_access.credentials TO mdm_access;
GRANT SELECT ON TABLE mdm_access.credentials TO mdm_command_runtime;

GRANT SELECT(tenant_id) ON TABLE mdm_access.credentials TO mdm_flow_runtime;

GRANT SELECT(registration) ON TABLE mdm_access.credentials TO mdm_flow_runtime;

GRANT UPDATE(state) ON TABLE mdm_access.credentials TO mdm_access;
GRANT SELECT(state) ON TABLE mdm_access.credentials TO mdm_flow_runtime;

GRANT SELECT,INSERT ON TABLE mdm_access.devices TO mdm_access;
GRANT SELECT ON TABLE mdm_access.devices TO mdm_flow_runtime;
GRANT SELECT ON TABLE mdm_access.devices TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_access.grants TO mdm_access;

GRANT SELECT,INSERT ON TABLE mdm_access.registration_operations TO mdm_access;

GRANT SELECT,INSERT ON TABLE mdm_access.registrations TO mdm_access;
GRANT SELECT ON TABLE mdm_access.registrations TO mdm_flow_runtime;
GRANT SELECT ON TABLE mdm_access.registrations TO mdm_command_runtime;

GRANT UPDATE(state) ON TABLE mdm_access.registrations TO mdm_access;

GRANT SELECT,INSERT ON TABLE mdm_access.report_sources TO mdm_access;
GRANT SELECT ON TABLE mdm_access.report_sources TO mdm_flow_runtime;
GRANT SELECT ON TABLE mdm_access.report_sources TO mdm_command_runtime;

GRANT UPDATE(enabled) ON TABLE mdm_access.report_sources TO mdm_access;

GRANT UPDATE(next_command) ON TABLE mdm_access.report_sources TO mdm_access;
GRANT UPDATE(next_command) ON TABLE mdm_access.report_sources TO mdm_command_runtime;

GRANT UPDATE(next_sequence) ON TABLE mdm_access.report_sources TO mdm_access;
GRANT UPDATE(next_sequence) ON TABLE mdm_access.report_sources TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_access.requests TO mdm_access;
GRANT SELECT ON TABLE mdm_access.requests TO mdm_command_runtime;

GRANT UPDATE(state) ON TABLE mdm_access.requests TO mdm_access;

GRANT UPDATE(password_digest) ON TABLE mdm_access.requests TO mdm_access;

GRANT UPDATE(password_version) ON TABLE mdm_access.requests TO mdm_access;

GRANT UPDATE(credential_ref) ON TABLE mdm_access.requests TO mdm_access;

GRANT UPDATE(expires_at) ON TABLE mdm_access.requests TO mdm_access;
COMMIT;
