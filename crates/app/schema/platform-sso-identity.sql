BEGIN;
GRANT USAGE ON SCHEMA mdm_access,mdm_planning,mdm_scope,mdm_policy,mdm_devices,mdm_commands,mdm,mdm_apple TO mdm_identity_runtime;
GRANT SELECT ON mdm_access.devices,mdm_access.registrations,mdm_access.credentials,mdm_access.report_sources,mdm_access.device_access_bindings TO mdm_identity_runtime;
GRANT UPDATE(tenant_id) ON mdm_access.device_access_bindings TO mdm_identity_runtime;
GRANT SELECT ON mdm_policy.policies,mdm_policy.versions,mdm_scope.scopes,mdm_scope.scope_runs,mdm_scope.scope_source_members,mdm_commands.scope_channel_results TO mdm_identity_runtime;
GRANT SELECT ON mdm_devices.checkpoints,mdm_devices.object_cuts,mdm_devices.object_versions,mdm_devices.object_heads,mdm_devices.query_revisions,mdm_devices.checkpoints TO mdm_identity_runtime;
GRANT SELECT ON mdm_apple.devices,mdm_apple.profiles,mdm_apple.attempts,mdm.inventory,mdm.collection_definitions TO mdm_identity_runtime;
GRANT EXECUTE ON FUNCTION mdm.lock_asset_watermark(uuid),mdm_policy.lock_policy(uuid),mdm_scope.scope_admission(uuid,text) TO mdm_identity_runtime;
GRANT EXECUTE ON FUNCTION mdm_access.access_binding_ready(jsonb),mdm_devices.object_current(jsonb,text),
 mdm_scope.scope_state(uuid,text),mdm_commands.channel_admission(uuid,text,text),
 mdm_commands.access_policy(uuid,text,bigint),mdm_commands.active_access_binding(uuid,bigint,bigint)
 TO mdm_identity_runtime;
-- DA consumes Identity's proof on the existing Identity runtime. The access role is unchanged.
GRANT SELECT,INSERT ON mdm_access.registration_operations TO mdm_identity_runtime;
GRANT INSERT ON mdm_access.device_access_bindings TO mdm_identity_runtime;
GRANT UPDATE(instance,principal,generation,revision,state,account,document) ON mdm_access.device_access_bindings TO mdm_identity_runtime;
GRANT USAGE ON SCHEMA mdm_agent TO mdm_identity_runtime;
GRANT SELECT ON mdm_agent.bindings,mdm_access.agent_issuances TO mdm_identity_runtime;
GRANT SELECT,INSERT,DELETE ON mdm_access.device_access_ceremonies TO mdm_identity_runtime;
GRANT UPDATE(consumed) ON mdm_access.device_access_ceremonies TO mdm_identity_runtime;
COMMIT;
