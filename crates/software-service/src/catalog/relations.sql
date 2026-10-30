
-- Explicit integration privileges owned by this capability.
GRANT USAGE ON SCHEMA mdm_software TO mdm_software_runtime;

GRANT USAGE ON SCHEMA mdm_software TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_software.versions TO mdm_software_runtime;

GRANT SELECT ON TABLE mdm_software.versions TO mdm_command_runtime;

GRANT UPDATE(lifecycle) ON TABLE mdm_software.versions TO mdm_software_runtime;

GRANT SELECT,INSERT ON TABLE mdm_software.materials TO mdm_software_runtime;

GRANT SELECT ON TABLE mdm_software.materials TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_software.operations TO mdm_software_runtime;

GRANT SELECT,INSERT ON TABLE mdm_software.sources TO mdm_software_runtime;

GRANT SELECT ON TABLE mdm_software.sources TO mdm_command_runtime;

GRANT UPDATE(lifecycle) ON TABLE mdm_software.sources TO mdm_software_runtime;

GRANT USAGE ON SCHEMA mdm_software TO mdm_resource_runtime,mdm_policy_runtime,mdm_content_runtime,mdm_telemetry_runtime;
GRANT SELECT ON mdm_software.sources,mdm_software.versions,mdm_software.materials TO mdm_resource_runtime,mdm_policy_runtime,mdm_content_runtime,mdm_telemetry_runtime;
