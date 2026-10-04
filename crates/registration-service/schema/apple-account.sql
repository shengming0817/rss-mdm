-- Forward-only addition of a native account authority; existing password and parent sources remain distinct.
BEGIN;
ALTER TABLE mdm_access.requests DROP CONSTRAINT requests_authority_kind_check;
ALTER TABLE mdm_access.requests ADD CONSTRAINT requests_authority_kind_check CHECK(authority_kind IN ('password','parent_certificate','apple_account'));
ALTER TABLE mdm_access.requests ADD COLUMN account_version bigint NOT NULL DEFAULT 0 CHECK(account_version>=0);
ALTER TABLE mdm_access.requests ADD COLUMN account_reference jsonb;
ALTER TABLE mdm_access.requests ADD COLUMN account_challenge text CHECK(account_challenge ~ '^[0-9a-f]{64}$');
ALTER TABLE mdm_access.requests DROP CONSTRAINT enrollment_shape;
ALTER TABLE mdm_access.requests ADD CONSTRAINT enrollment_shape CHECK (
 state='cancelled' OR (expected_generation IS NOT NULL AND expires_at IS NOT NULL AND issuance_operation IS NOT NULL AND (
 (authority_kind='password' AND grant_id IS NOT NULL AND parent_id IS NULL AND password_digest IS NOT NULL AND password_version>0 AND credential_ref IS NOT NULL AND account_version=0 AND account_reference IS NULL AND account_challenge IS NULL) OR
 (authority_kind='parent_certificate' AND grant_id IS NULL AND source='mdm.windows' AND parent_id IS NOT NULL AND parent_generation IS NOT NULL AND parent_generation>0 AND parent_credential IS NOT NULL AND password_digest IS NULL AND password_version=0 AND credential_ref IS NULL AND account_version=0 AND account_reference IS NULL AND account_challenge IS NULL) OR
 (authority_kind='apple_account' AND grant_id IS NOT NULL AND source='mdm.apple' AND self_service AND parent_id IS NULL AND password_digest IS NULL AND password_version=0 AND credential_ref IS NULL AND account_version>0 AND account_reference IS NOT NULL AND account_challenge IS NOT NULL)
 )));
GRANT UPDATE(account_version,account_reference,account_challenge) ON mdm_access.requests TO mdm_access;
COMMIT;
