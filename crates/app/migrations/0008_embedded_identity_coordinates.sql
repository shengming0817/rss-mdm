-- Fresh installation: request authority is an embedded instance, tenant and principal.
-- No conversion or import of subjects from a central identity deployment.
BEGIN;
ALTER TABLE mdm_access.grants RENAME COLUMN client TO instance;
ALTER TABLE mdm_access.operations RENAME COLUMN client TO instance;
ALTER TABLE mdm_access.audit RENAME COLUMN client TO instance;
ALTER TABLE mdm_access.requests RENAME COLUMN session_ref TO credential_ref;
COMMIT;
