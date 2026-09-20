-- Fresh installation only. Runtime has no startup seed, delete privilege or initialization reset.
BEGIN;
CREATE TABLE mdm_access.authorization_rules (
 tenant_id uuid NOT NULL, instance uuid NOT NULL, id uuid NOT NULL,
 revision bigint NOT NULL CHECK(revision > 0),
 document jsonb CHECK(document IS NULL OR (jsonb_typeof(document)='object' AND octet_length(document::text)<=2097152)),
 PRIMARY KEY(tenant_id,instance,id)
);
CREATE TABLE mdm_access.user_groups (
 tenant_id uuid NOT NULL, instance uuid NOT NULL, id uuid NOT NULL,
 revision bigint NOT NULL CHECK(revision > 0),
 document jsonb CHECK(document IS NULL OR (jsonb_typeof(document)='object' AND octet_length(document::text)<=2097152)),
 PRIMARY KEY(tenant_id,instance,id)
);
CREATE TABLE mdm_access.authorization_initializations (
 tenant_id uuid NOT NULL, instance uuid NOT NULL, operation_id uuid NOT NULL, principal uuid NOT NULL,
 initialized_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,instance)
);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['authorization_rules','user_groups','authorization_initializations'] LOOP
  EXECUTE format('ALTER TABLE mdm_access.%I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE mdm_access.%I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('CREATE POLICY tenant ON mdm_access.%I USING (tenant_id = nullif(current_setting(''rss.tenant_id'',true),'''')::uuid) WITH CHECK (tenant_id = nullif(current_setting(''rss.tenant_id'',true),'''')::uuid)',t);
 END LOOP;
END $$;
GRANT SELECT,INSERT ON mdm_access.authorization_rules,mdm_access.user_groups,mdm_access.authorization_initializations TO mdm_access;
GRANT UPDATE(revision,document) ON mdm_access.authorization_rules,mdm_access.user_groups TO mdm_access;
ALTER TABLE mdm_access.audit DROP CONSTRAINT audit_action_check;
ALTER TABLE mdm_access.audit ADD CONSTRAINT audit_action_check CHECK(action IN
('grant_issue','grant_revoke','registration_accept','inventory_read','device_action','authentication',
'protected_request','registration_bind','credential_revoke','device_report','enrollment_create','enrollment_resume','enrollment_cancel','enrollment_issue','enrollment_read','registration_read','windows_discovery','windows_policy','windows_management','collection_read','collection_finish','software_binding','software_candidate','software_validate','software_approve','software_authorize','software_call','software_preflight','software_result','software_withdraw','software_archive','management_read','management_write','plan_preview','plan_save','authorization_write','authorization_initialize'));
COMMIT;
