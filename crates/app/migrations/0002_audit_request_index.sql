BEGIN;
CREATE INDEX audit_tenant_request ON mdm_access.audit (tenant_id, request_id);
COMMIT;
