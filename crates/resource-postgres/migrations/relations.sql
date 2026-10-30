
-- Explicit integration privileges owned by this capability.
GRANT USAGE ON SCHEMA mdm_resource TO mdm_resource_runtime;

GRANT USAGE ON SCHEMA mdm_resource TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_resource.aggregates TO mdm_resource_runtime;

GRANT SELECT ON TABLE mdm_resource.aggregates TO mdm_command_runtime;

GRANT UPDATE(revision) ON TABLE mdm_resource.aggregates TO mdm_resource_runtime;

GRANT UPDATE(document) ON TABLE mdm_resource.aggregates TO mdm_resource_runtime;

GRANT UPDATE(digest) ON TABLE mdm_resource.aggregates TO mdm_resource_runtime;

GRANT SELECT,INSERT ON TABLE mdm_resource.artifact_refs TO mdm_resource_runtime;

GRANT UPDATE(archived) ON TABLE mdm_resource.artifact_refs TO mdm_resource_runtime;

GRANT SELECT,INSERT ON TABLE mdm_resource.immutable TO mdm_resource_runtime;

GRANT SELECT ON TABLE mdm_resource.immutable TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_resource.requests TO mdm_resource_runtime;

GRANT SELECT ON TABLE mdm_resource.aggregates, mdm_resource.immutable, mdm_software.sources, mdm_software.versions TO mdm_access;

GRANT USAGE ON SCHEMA mdm_resource TO mdm_policy_runtime,mdm_inventory_runtime,mdm_content_runtime,mdm_telemetry_runtime,mdm_software_runtime;
GRANT SELECT ON mdm_resource.aggregates,mdm_resource.immutable TO mdm_policy_runtime,mdm_inventory_runtime,mdm_content_runtime,mdm_telemetry_runtime;

GRANT SELECT ON mdm_resource.field_refs TO mdm_inventory_runtime;

GRANT SELECT(tenant_id,sha256,archived) ON mdm_resource.artifact_refs TO mdm_content_runtime;
