
-- Explicit integration privileges owned by this capability.
GRANT USAGE ON SCHEMA rss_device_command TO mdm_command_runtime,mdm_policy_runtime;

REVOKE ALL ON FUNCTION rss_device_command.advance(t uuid, d uuid, g bigint, e bigint, ng bigint, ne bigint) FROM PUBLIC;

GRANT ALL ON FUNCTION rss_device_command.advance(t uuid, d uuid, g bigint, e bigint, ng bigint, ne bigint) TO mdm_command_runtime,mdm_policy_runtime;

REVOKE ALL ON FUNCTION rss_device_command.enqueue(t uuid, d uuid, c text, g bigint, e bigint, digest bytea, expires bigint, at_time bigint, m text, f bytea, domain_name text) FROM PUBLIC;

GRANT ALL ON FUNCTION rss_device_command.enqueue(t uuid, d uuid, c text, g bigint, e bigint, digest bytea, expires bigint, at_time bigint, m text, f bytea, domain_name text) TO mdm_command_runtime,mdm_policy_runtime;

REVOKE ALL ON FUNCTION rss_device_command.initialize(t uuid, d uuid, g bigint, e bigint) FROM PUBLIC;

GRANT ALL ON FUNCTION rss_device_command.initialize(t uuid, d uuid, g bigint, e bigint) TO mdm_command_runtime,mdm_policy_runtime;

GRANT SELECT ON TABLE rss_device_command.authorities TO mdm_command_runtime,mdm_policy_runtime;

REVOKE ALL ON FUNCTION rss_device_command.lock_authority(t uuid, d uuid) FROM PUBLIC;

GRANT ALL ON FUNCTION rss_device_command.lock_authority(t uuid, d uuid) TO mdm_command_runtime,mdm_policy_runtime;

REVOKE ALL ON FUNCTION rss_device_command.save(t uuid, d uuid, c text, v bigint, s text, p bigint, r bigint, done bigint) FROM PUBLIC;

GRANT ALL ON FUNCTION rss_device_command.save(t uuid, d uuid, c text, v bigint, s text, p bigint, r bigint, done bigint) TO mdm_command_runtime,mdm_policy_runtime;

GRANT SELECT ON TABLE rss_device_command.commands TO mdm_command_runtime,mdm_policy_runtime;
