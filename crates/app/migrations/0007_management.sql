BEGIN;
CREATE SCHEMA mdm_management;
REVOKE ALL ON SCHEMA mdm_management FROM PUBLIC;
CREATE TABLE mdm_management.scopes (
 tenant_id uuid NOT NULL, id uuid NOT NULL, revision bigint NOT NULL CHECK(revision>0), deleted boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,id)
);
CREATE TABLE mdm_management.scope_versions (
 tenant_id uuid NOT NULL, id uuid NOT NULL, revision bigint NOT NULL CHECK(revision>0), definition jsonb NOT NULL CHECK(octet_length(definition::text)<=65536),
 PRIMARY KEY(tenant_id,id,revision), FOREIGN KEY(tenant_id,id) REFERENCES mdm_management.scopes(tenant_id,id)
);
CREATE TABLE mdm_management.previews (
 tenant_id uuid NOT NULL, id uuid NOT NULL, scope uuid NOT NULL, scope_revision bigint NOT NULL,
 document jsonb NOT NULL CHECK(octet_length(document::text)<=8388608),
 PRIMARY KEY(tenant_id,id), FOREIGN KEY(tenant_id,scope,scope_revision) REFERENCES mdm_management.scope_versions(tenant_id,id,revision)
);
CREATE TABLE mdm_management.operations (
 tenant_id uuid NOT NULL, id uuid NOT NULL, fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),
 response jsonb NOT NULL CHECK(octet_length(response::text)<=8388608), PRIMARY KEY(tenant_id,id)
);
CREATE TABLE mdm_management.plan_references (
 tenant_id uuid NOT NULL, preview uuid NOT NULL, policy text NOT NULL, plan bytea NOT NULL CHECK(octet_length(plan)=32),
 PRIMARY KEY(tenant_id,preview), FOREIGN KEY(tenant_id,preview) REFERENCES mdm_management.previews(tenant_id,id)
);
CREATE TABLE mdm_management.resource_references (
 tenant_id uuid NOT NULL, resource text NOT NULL, version text NOT NULL, policy text NOT NULL,
 PRIMARY KEY(tenant_id,resource,version,policy)
);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['scopes','scope_versions','previews','operations','plan_references','resource_references'] LOOP
 EXECUTE format('ALTER TABLE mdm_management.%I ENABLE ROW LEVEL SECURITY',t);
 EXECUTE format('ALTER TABLE mdm_management.%I FORCE ROW LEVEL SECURITY',t);
 EXECUTE format('CREATE POLICY tenant ON mdm_management.%I USING(tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid) WITH CHECK(tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid)',t);
 END LOOP;
END $$;
GRANT USAGE ON SCHEMA mdm_management,mdm_access,mdm TO mdm_management_runtime;
GRANT USAGE ON SCHEMA mdm_management TO mdm_software_driver;
GRANT SELECT ON mdm_management.resource_references TO mdm_software_driver;
GRANT SELECT,INSERT ON ALL TABLES IN SCHEMA mdm_management TO mdm_management_runtime;
GRANT UPDATE(revision,deleted) ON mdm_management.scopes TO mdm_management_runtime;
GRANT USAGE ON SCHEMA mdm_software_composition TO mdm_management_runtime;
GRANT SELECT ON mdm_software_composition.subjects TO mdm_management_runtime;
GRANT INSERT ON mdm_access.audit TO mdm_management_runtime;
GRANT SELECT ON mdm_access.devices,mdm_access.registrations,mdm_access.report_sources,mdm_access.collection_runs,mdm.inventory TO mdm_management_runtime;
ALTER TABLE mdm_access.grants DROP CONSTRAINT grants_device_check;
ALTER TABLE mdm_access.grants ADD CHECK(octet_length(device) BETWEEN 1 AND 256 AND device !~ '[[:cntrl:]]');
ALTER TABLE mdm_access.audit DROP CONSTRAINT audit_target_check;
ALTER TABLE mdm_access.audit ADD CHECK(target IS NULL OR octet_length(target) BETWEEN 1 AND 256);
ALTER TABLE mdm_access.devices DROP CONSTRAINT devices_id_check;
ALTER TABLE mdm_access.devices ADD CHECK(octet_length(id) BETWEEN 1 AND 256 AND id !~ '[[:cntrl:]]');
ALTER TABLE mdm_access.audit DROP CONSTRAINT audit_action_check;
ALTER TABLE mdm_access.audit ADD CONSTRAINT audit_action_check CHECK(action IN
('grant_issue','grant_revoke','registration_accept','inventory_read','device_action','authentication',
'protected_request','registration_bind','credential_revoke','device_report','enrollment_create','enrollment_resume','enrollment_cancel','enrollment_issue','enrollment_read','registration_read','windows_discovery','windows_policy','windows_management','collection_read','collection_finish','software_binding','software_candidate','software_validate','software_approve','software_authorize','software_call','software_preflight','software_result','software_withdraw','software_archive','management_read','management_write','plan_preview','plan_save'));
COMMIT;
