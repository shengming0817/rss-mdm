BEGIN;
-- Includes JSON escaping of 32 KiB plaintext and the complete bounded user scope.
ALTER TABLE mdm_windows.entra_policy DROP CONSTRAINT entra_policy_document_check;
ALTER TABLE mdm_windows.entra_policy ADD CONSTRAINT entra_policy_document_check CHECK(octet_length(document::text)<=131072);
COMMIT;
