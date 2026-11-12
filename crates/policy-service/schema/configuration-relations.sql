-- Policy configuration relations and least-privilege participants.
BEGIN;
GRANT USAGE ON SCHEMA mdm_planning TO mdm_access,mdm_command_runtime,mdm_policy_runtime,mdm_resource_runtime;
ALTER TABLE ONLY mdm_planning.configuration_claims
    ADD CONSTRAINT configuration_claims_tenant_id_policy_fkey FOREIGN KEY (tenant_id, policy) REFERENCES mdm_policy.policies(tenant_id, id);
ALTER TABLE ONLY mdm_planning.configuration_claims
    ADD CONSTRAINT configuration_claims_tenant_id_version_fkey FOREIGN KEY (tenant_id, version) REFERENCES mdm_policy.versions(tenant_id, id);
ALTER TABLE mdm_planning.configuration_objects ADD CONSTRAINT configuration_objects_operation_fkey FOREIGN KEY (tenant_id, operation) REFERENCES mdm_planning.configuration_operations (tenant_id, id);
GRANT SELECT ON mdm_planning.configuration_claims,mdm_planning.configuration_devices,mdm_planning.configuration_objects,mdm_planning.configuration_operations TO mdm_access,mdm_command_runtime;
GRANT SELECT ON mdm_planning.configuration_claims,mdm_planning.configuration_objects TO mdm_resource_runtime;
GRANT SELECT,INSERT,DELETE ON mdm_planning.configuration_claims TO mdm_policy_runtime,mdm_command_runtime;
GRANT SELECT,INSERT ON mdm_planning.configuration_devices,mdm_planning.configuration_objects,mdm_planning.configuration_operations,mdm_planning.configuration_receipts,mdm_planning.configuration_recovery TO mdm_policy_runtime,mdm_command_runtime;
GRANT UPDATE(version,operation) ON mdm_planning.configuration_claims TO mdm_policy_runtime,mdm_command_runtime;
GRANT UPDATE(input_revision,observed_revision) ON mdm_planning.configuration_devices TO mdm_policy_runtime,mdm_command_runtime;
GRANT UPDATE(operation,digest,diagnosis) ON mdm_planning.configuration_objects TO mdm_policy_runtime,mdm_command_runtime;
GRANT UPDATE(dispatch_failure,gateway_accepted,revision,observed_command_version) ON mdm_planning.configuration_operations TO mdm_policy_runtime,mdm_command_runtime;
GRANT UPDATE(authority_epoch,recovery_after) ON mdm_planning.configuration_recovery TO mdm_policy_runtime,mdm_command_runtime;
ALTER TABLE mdm_planning.configuration_claims ADD FOREIGN KEY (tenant_id, operation) REFERENCES mdm_planning.configuration_operations (tenant_id, id);
ALTER TABLE mdm_planning.configuration_devices ADD FOREIGN KEY(tenant_id,device) REFERENCES mdm_access.devices(tenant_id,id);
ALTER TABLE mdm_planning.configuration_claims ADD FOREIGN KEY(tenant_id,device) REFERENCES mdm_access.devices(tenant_id,id);
ALTER TABLE mdm_planning.configuration_objects ADD FOREIGN KEY(tenant_id,device) REFERENCES mdm_access.devices(tenant_id,id);
COMMIT;

GRANT EXECUTE ON FUNCTION mdm_planning.configuration_windows_pending_operations(uuid,uuid), mdm_planning.configuration_windows_wake_candidates(uuid) TO mdm_access,mdm_command_runtime,mdm_policy_runtime;

-- Invoker permissions and underlying forced RLS remain authoritative in a caller's snapshot.
CREATE VIEW mdm_planning.configuration_execution_facts WITH (security_invoker=true,security_barrier=true) AS
 SELECT o.tenant_id,o.id,o.device,'command'::text AS kind,
 'policy'::text AS source_kind,o.policy_version,v.policy,(o.input_context->>'deadline')::bigint AS deadline,
 coalesce(d.status,'unknown') AS status,
 (octet_length(o.request)+octet_length(o.authority::text)+octet_length(o.input_context::text)+coalesce(octet_length(o.dispatch_failure::text),0)+1024)::bigint AS input_bytes
 FROM mdm_planning.configuration_operations o
 LEFT JOIN rss_device_command.commands d ON(d.tenant_id,d.command_id)=(o.tenant_id,o.id::text)
 LEFT JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(o.tenant_id,o.policy_version);
GRANT SELECT ON mdm_planning.configuration_execution_facts TO mdm_command_runtime,mdm_policy_runtime,mdm_access;
