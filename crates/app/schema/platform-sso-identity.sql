BEGIN;
GRANT USAGE ON SCHEMA mdm_access,mdm_planning,mdm_policy,mdm_devices,mdm_commands,mdm,mdm_apple TO mdm_identity_runtime;
GRANT SELECT ON mdm_access.devices,mdm_access.registrations,mdm_access.credentials,mdm_access.report_sources,mdm_access.device_access_bindings TO mdm_identity_runtime;
GRANT UPDATE(tenant_id) ON mdm_access.device_access_bindings TO mdm_identity_runtime;
GRANT SELECT ON mdm_policy.policies,mdm_policy.versions,mdm_planning.scopes,mdm_planning.scope_runs,mdm_planning.scope_source_members,mdm_planning.scope_channel_results TO mdm_identity_runtime;
GRANT SELECT ON mdm_devices.input_snapshots,mdm_devices.input_objects,mdm_devices.checkpoints TO mdm_identity_runtime;
GRANT SELECT ON mdm_apple.devices,mdm_apple.profiles,mdm_apple.attempts,mdm.inventory,mdm.collection_definitions TO mdm_identity_runtime;
GRANT EXECUTE ON FUNCTION mdm.lock_asset_watermark(uuid),mdm_planning.policy_lock(uuid),mdm_planning.scope_admission(uuid,text) TO mdm_identity_runtime;
GRANT EXECUTE ON FUNCTION mdm_access.access_binding_ready(jsonb),mdm_devices.object_current(jsonb,text),
 mdm_planning.scope_state(uuid,text),mdm_planning.channel_admission(uuid,text,text),
 mdm_commands.access_policy(uuid,text,bigint),mdm_commands.active_access_binding(uuid,bigint,bigint)
 TO mdm_identity_runtime;
COMMIT;
