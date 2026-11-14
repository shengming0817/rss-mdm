-- The existing consumer captures only original owner work coordinates; it cannot change owner progress.
GRANT SELECT,INSERT ON rss_transactional_messaging.consumer_dead_letter TO mdm_asset_ingress_consumer;

GRANT USAGE ON SCHEMA mdm_assets,mdm_devices,mdm_compliance,mdm_scope,mdm_planning,mdm_software_deployment TO mdm_asset_ingress_consumer;
GRANT SELECT(tenant_id,expected_epoch),INSERT(tenant_id,expected_epoch) ON mdm_assets.group_dispatch,mdm_devices.checkpoints,mdm_compliance.dispatch,mdm_scope.asset_dispatch,mdm_planning.configuration_source_dispatch,mdm_devices.control_source_dispatch,mdm_software_deployment.device_source_dispatch TO mdm_asset_ingress_consumer;

GRANT SELECT(tenant_id,expected_epoch),INSERT(tenant_id,expected_epoch) ON mdm_scope.asset_dispatch TO mdm_scope_group_consumer;
