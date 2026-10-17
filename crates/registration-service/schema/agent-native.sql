BEGIN;
CREATE TABLE mdm_access.agent_native_enrollments (
 tenant_id uuid NOT NULL,task uuid NOT NULL,attempt uuid NOT NULL,operation uuid NOT NULL,
 source_registration uuid NOT NULL,source_generation bigint NOT NULL,
 request uuid NOT NULL,request_digest text NOT NULL,authority jsonb NOT NULL,
 PRIMARY KEY(tenant_id,task),UNIQUE(tenant_id,request),UNIQUE(tenant_id,operation),
 FOREIGN KEY(tenant_id,request) REFERENCES mdm_access.requests(tenant_id,id),
 FOREIGN KEY(tenant_id,source_registration,source_generation) REFERENCES mdm_access.registrations(tenant_id,id,generation)
);
ALTER TABLE mdm_access.agent_native_enrollments ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_access.agent_native_enrollments FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_access.agent_native_enrollments USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON mdm_access.agent_native_enrollments TO mdm_command_runtime;
GRANT SELECT ON mdm_access.agent_native_enrollments TO mdm_access;
GRANT SELECT,INSERT ON mdm_access.requests,mdm_access.grants TO mdm_command_runtime;
ALTER TABLE mdm_access.requests DROP CONSTRAINT requests_authority_kind_check;
ALTER TABLE mdm_access.requests ADD CONSTRAINT requests_authority_kind_check CHECK(authority_kind IN('password','parent_certificate','apple_account','apple_ade','windows_entra','agent_policy'));
ALTER TABLE mdm_access.requests DROP CONSTRAINT enrollment_shape;
ALTER TABLE mdm_access.requests ADD CONSTRAINT enrollment_shape CHECK(
 state='cancelled' OR (expected_generation IS NOT NULL AND expires_at IS NOT NULL AND issuance_operation IS NOT NULL AND (
 (authority_kind='password' AND grant_id IS NOT NULL AND parent_id IS NULL AND password_digest IS NOT NULL AND password_version>0 AND credential_ref IS NOT NULL AND account_version=0 AND account_reference IS NULL AND account_challenge IS NULL AND organization_version=0 AND organization_challenge IS NULL) OR
 (authority_kind='parent_certificate' AND grant_id IS NULL AND source='mdm.windows' AND parent_id IS NOT NULL AND parent_generation IS NOT NULL AND parent_generation>0 AND parent_credential IS NOT NULL AND password_digest IS NULL AND password_version=0 AND credential_ref IS NULL AND account_version=0 AND account_reference IS NULL AND account_challenge IS NULL AND organization_version=0 AND organization_challenge IS NULL) OR
 (authority_kind='apple_account' AND grant_id IS NOT NULL AND source='mdm.apple' AND self_service AND parent_id IS NULL AND password_digest IS NULL AND password_version=0 AND credential_ref IS NULL AND account_version>0 AND account_reference IS NOT NULL AND account_challenge IS NOT NULL AND organization_version=0 AND organization_challenge IS NULL) OR
 (authority_kind='apple_ade' AND grant_id IS NOT NULL AND source='mdm.apple' AND NOT self_service AND parent_id IS NULL AND password_digest IS NULL AND password_version=0 AND credential_ref IS NULL AND account_version=0 AND account_reference IS NULL AND account_challenge IS NULL AND organization_version>0 AND organization_challenge IS NOT NULL) OR
 (authority_kind='windows_entra' AND grant_id IS NOT NULL AND source='mdm.windows' AND NOT self_service AND parent_id IS NULL AND password_digest IS NULL AND password_version=0 AND credential_ref IS NULL AND account_version=0 AND account_reference IS NULL AND account_challenge IS NULL AND organization_version>0 AND organization_challenge IS NULL) OR
 (authority_kind='agent_policy' AND grant_id IS NOT NULL AND NOT self_service AND parent_id IS NULL AND password_digest IS NOT NULL AND password_version=1 AND credential_ref IS NULL AND account_version=0 AND account_reference IS NULL AND account_challenge IS NULL AND organization_version=0 AND organization_challenge IS NULL)
 )));
COMMIT;
