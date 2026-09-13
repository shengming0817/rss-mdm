BEGIN;
CREATE SCHEMA mdm_software_composition AUTHORIZATION mdm_owner;
REVOKE ALL ON SCHEMA mdm_software_composition FROM PUBLIC;
CREATE TABLE mdm_software_composition.bindings (
 tenant_id uuid NOT NULL, identity bytea PRIMARY KEY CHECK(octet_length(identity)=32),
 configuration bytea NOT NULL CHECK(octet_length(configuration) BETWEEN 1 AND 1048576),
 UNIQUE(tenant_id,identity)
);
CREATE TABLE mdm_software_composition.subjects (
 tenant_id uuid NOT NULL, candidate text NOT NULL CHECK(octet_length(candidate) BETWEEN 1 AND 128),
 resource text NOT NULL, version text NOT NULL,
 document bytea NOT NULL CHECK(octet_length(document) BETWEEN 1 AND 8388608), digest bytea NOT NULL CHECK(octet_length(digest)=32),
 PRIMARY KEY(tenant_id,candidate),
 FOREIGN KEY(tenant_id,candidate) REFERENCES mdm_software_release.aggregates(tenant_id,id),
 FOREIGN KEY(tenant_id,resource) REFERENCES mdm_resource.aggregates(tenant_id,id)
);
CREATE INDEX resource_references ON mdm_software_composition.subjects(tenant_id,resource,version);
CREATE TABLE mdm_software_composition.authorities (
 tenant_id uuid NOT NULL, software bytea NOT NULL CHECK(octet_length(software)=32),
 material bytea NOT NULL CHECK(octet_length(material)=32), candidate text NOT NULL,
 PRIMARY KEY(tenant_id,software), FOREIGN KEY(tenant_id,candidate) REFERENCES mdm_software_composition.subjects(tenant_id,candidate) DEFERRABLE INITIALLY DEFERRED
);
CREATE TABLE mdm_software_composition.slots (
 tenant_id uuid NOT NULL, binding bytea NOT NULL, coordinate text NOT NULL CHECK(octet_length(coordinate) BETWEEN 1 AND 512),
 operation text CHECK(octet_length(operation) BETWEEN 1 AND 128), cursor text CHECK(cursor ~ '^[0-9a-f]{40}$'),
 PRIMARY KEY(tenant_id,binding,coordinate), FOREIGN KEY(tenant_id,binding) REFERENCES mdm_software_composition.bindings(tenant_id,identity)
);
CREATE TABLE mdm_software_composition.targets (
 tenant_id uuid NOT NULL, id text NOT NULL CHECK(octet_length(id) BETWEEN 1 AND 128), candidate text NOT NULL,
 document bytea NOT NULL CHECK(octet_length(document) BETWEEN 1 AND 1048576), digest bytea NOT NULL CHECK(octet_length(digest)=32),
 attempted boolean NOT NULL DEFAULT false, acknowledged boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,id), FOREIGN KEY(tenant_id,candidate) REFERENCES mdm_software_composition.subjects(tenant_id,candidate),CHECK(NOT acknowledged OR attempted)
);
CREATE TABLE mdm_software_composition.withdrawals (
 tenant_id uuid NOT NULL, id text NOT NULL CHECK(octet_length(id) BETWEEN 1 AND 128), candidate text NOT NULL,
 document bytea NOT NULL CHECK(octet_length(document) BETWEEN 1 AND 1048576), digest bytea NOT NULL CHECK(octet_length(digest)=32),
 complete boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,id), FOREIGN KEY(tenant_id,candidate) REFERENCES mdm_software_composition.subjects(tenant_id,candidate)
);
ALTER TABLE mdm_software_composition.targets ADD COLUMN withdrawal_id text;
ALTER TABLE mdm_software_composition.targets ADD FOREIGN KEY(tenant_id,withdrawal_id) REFERENCES mdm_software_composition.withdrawals(tenant_id,id);
ALTER TABLE mdm_software_composition.targets ADD CHECK((left(id,2)='p:' AND withdrawal_id IS NULL) OR (left(id,2)='w:' AND withdrawal_id=id));
CREATE TABLE mdm_software_composition.projections (
 tenant_id uuid NOT NULL, binding bytea NOT NULL, coordinate text NOT NULL CHECK(octet_length(coordinate) BETWEEN 1 AND 512), publication bytea NOT NULL CHECK(octet_length(publication)=32),
 PRIMARY KEY(tenant_id,binding,coordinate), FOREIGN KEY(tenant_id,binding) REFERENCES mdm_software_composition.bindings(tenant_id,identity)
);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['bindings','subjects','authorities','slots','targets','withdrawals','projections'] LOOP
 EXECUTE format('ALTER TABLE mdm_software_composition.%I ENABLE ROW LEVEL SECURITY',t);
 EXECUTE format('ALTER TABLE mdm_software_composition.%I FORCE ROW LEVEL SECURITY',t);
 EXECUTE format('CREATE POLICY tenant ON mdm_software_composition.%I USING(tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid) WITH CHECK(tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid)',t);
 EXECUTE format('REVOKE ALL ON mdm_software_composition.%I FROM PUBLIC',t);
 END LOOP;
END $$;
GRANT USAGE ON SCHEMA mdm_software_composition TO mdm_software_driver;
GRANT SELECT,INSERT ON ALL TABLES IN SCHEMA mdm_software_composition TO mdm_software_driver;
GRANT UPDATE(candidate) ON mdm_software_composition.authorities TO mdm_software_driver;
GRANT UPDATE(operation,cursor) ON mdm_software_composition.slots TO mdm_software_driver;
GRANT UPDATE(attempted,acknowledged) ON mdm_software_composition.targets TO mdm_software_driver;
GRANT UPDATE(complete) ON mdm_software_composition.withdrawals TO mdm_software_driver;
GRANT UPDATE(publication) ON mdm_software_composition.projections TO mdm_software_driver;
GRANT DELETE ON mdm_software_composition.projections TO mdm_software_driver;
GRANT USAGE ON SCHEMA mdm_access TO mdm_software_driver;
GRANT INSERT ON mdm_access.audit TO mdm_software_driver;
ALTER TABLE mdm_access.audit DROP CONSTRAINT audit_action_check;
ALTER TABLE mdm_access.audit ADD CONSTRAINT audit_action_check CHECK(action IN
('grant_issue','grant_revoke','registration_accept','inventory_read','device_action','authentication',
  'protected_request','registration_bind','credential_revoke','device_report',
  'enrollment_create','enrollment_resume','enrollment_cancel','enrollment_issue','enrollment_read','registration_read',
  'windows_discovery','windows_policy','windows_management','collection_read','collection_finish','software_binding','software_candidate','software_validate','software_approve','software_authorize','software_call','software_result','software_withdraw','software_archive'));
COMMIT;
