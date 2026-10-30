-- Live directory and owner relationships share their caller's read snapshot.
GRANT USAGE ON SCHEMA mdm_devices,mdm TO mdm_identity_runtime;
GRANT SELECT ON mdm_devices.associations,mdm_devices.members,mdm_devices.asset_states,mdm_devices.checkpoints TO mdm_identity_runtime;
