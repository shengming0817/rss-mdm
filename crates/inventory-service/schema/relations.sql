-- Fresh installation: inventory-service owns these objects.
BEGIN;

SET LOCAL check_function_bodies = false;


ALTER TABLE ONLY mdm_assets.asset_query_facets
    ADD CONSTRAINT asset_query_facets_tenant_id_run_fkey FOREIGN KEY (tenant_id, run) REFERENCES mdm_assets.asset_query_runs(tenant_id, id);


ALTER TABLE ONLY mdm_assets.asset_query_results
    ADD CONSTRAINT asset_query_results_tenant_id_run_fkey FOREIGN KEY (tenant_id, run) REFERENCES mdm_assets.asset_query_runs(tenant_id, id);

GRANT USAGE ON SCHEMA mdm TO mdm_api;

GRANT USAGE ON SCHEMA mdm TO mdm_inventory_runtime;

GRANT USAGE ON SCHEMA mdm TO mdm_command_runtime;


GRANT USAGE ON SCHEMA mdm_assets TO mdm_inventory_runtime;


GRANT USAGE ON SCHEMA mdm_inventory TO mdm_access;


REVOKE ALL ON FUNCTION mdm.capture_inventory_history() FROM PUBLIC;


REVOKE ALL ON FUNCTION mdm.capture_manual_history() FROM PUBLIC;



REVOKE ALL ON FUNCTION mdm.record_asset_change(t uuid, k text, i jsonb, f text[]) FROM PUBLIC;


GRANT SELECT ON TABLE mdm.asset_changes TO mdm_inventory_runtime;

GRANT SELECT ON TABLE mdm.inventory TO mdm_api;

GRANT SELECT ON TABLE mdm.inventory TO mdm_inventory_runtime;

GRANT SELECT ON TABLE mdm.inventory TO mdm_command_runtime;


GRANT SELECT ON TABLE mdm.inventory_history TO mdm_inventory_runtime;


GRANT SELECT,INSERT ON TABLE mdm.manual_assignments TO mdm_inventory_runtime;


GRANT UPDATE(revision) ON TABLE mdm.manual_assignments TO mdm_inventory_runtime;


GRANT UPDATE(fact) ON TABLE mdm.manual_assignments TO mdm_inventory_runtime;


GRANT SELECT ON TABLE mdm.manual_history TO mdm_inventory_runtime;


GRANT SELECT,INSERT ON TABLE mdm_assets.asset_query_facets TO mdm_inventory_runtime;


GRANT UPDATE(total) ON TABLE mdm_assets.asset_query_facets TO mdm_inventory_runtime;


GRANT SELECT,INSERT ON TABLE mdm_assets.asset_query_results TO mdm_inventory_runtime;


GRANT SELECT,INSERT ON TABLE mdm_assets.asset_query_runs TO mdm_inventory_runtime;


GRANT UPDATE(total) ON TABLE mdm_assets.asset_query_runs TO mdm_inventory_runtime;


GRANT UPDATE(matched) ON TABLE mdm_assets.asset_query_runs TO mdm_inventory_runtime;


GRANT UPDATE(unknown) ON TABLE mdm_assets.asset_query_runs TO mdm_inventory_runtime;


GRANT SELECT,INSERT ON TABLE mdm_assets.operations TO mdm_inventory_runtime;


GRANT SELECT,INSERT ON TABLE mdm_assets.field_layouts TO mdm_inventory_runtime;

GRANT UPDATE(revision,document) ON TABLE mdm_assets.field_layouts TO mdm_inventory_runtime;


GRANT SELECT,INSERT ON TABLE mdm_assets.saved_queries TO mdm_inventory_runtime;


GRANT UPDATE(revision) ON TABLE mdm_assets.saved_queries TO mdm_inventory_runtime;


GRANT UPDATE(document) ON TABLE mdm_assets.saved_queries TO mdm_inventory_runtime;


GRANT SELECT,INSERT ON TABLE mdm_inventory.collection_operations TO mdm_access;


GRANT USAGE ON SCHEMA mdm TO mdm_access,mdm_command_runtime;

GRANT SELECT ON mdm.field_versions TO mdm_access,mdm_command_runtime;

GRANT SELECT,INSERT ON mdm.field_versions TO mdm_inventory_runtime;

GRANT EXECUTE ON FUNCTION mdm.append_field_version(uuid,text,bigint,jsonb) TO mdm_inventory_runtime;

GRANT SELECT,INSERT ON mdm.collection_definitions TO mdm_access,mdm_command_runtime,mdm_inventory_runtime;

GRANT SELECT,INSERT ON mdm.collection_results TO mdm_access,mdm_command_runtime,mdm_inventory_runtime;

GRANT EXECUTE ON FUNCTION mdm.record_asset_change(uuid,text,jsonb,text[]) TO mdm_inventory_runtime;

GRANT SELECT,INSERT ON mdm.array_versions,mdm.array_items TO mdm_inventory_runtime;

GRANT SELECT ON mdm.array_versions,mdm.array_items TO mdm_access,mdm_command_runtime;

GRANT UPDATE(value_version,last_known_version) ON mdm.manual_assignments TO mdm_inventory_runtime;

COMMIT;


GRANT UPDATE(started,completed,failure,cursor) ON mdm_assets.asset_query_runs TO mdm_inventory_runtime;


GRANT USAGE ON SCHEMA mdm,mdm_assets TO mdm_scope_runtime,mdm_policy_runtime,mdm_resource_runtime,mdm_software_runtime,mdm_telemetry_runtime;

GRANT SELECT ON mdm.asset_changes,mdm.inventory,mdm.inventory_history,mdm.manual_history,mdm.field_versions,mdm.collection_definitions,mdm.collection_results,mdm.array_versions,mdm.array_items TO mdm_scope_runtime,mdm_policy_runtime,mdm_telemetry_runtime;

GRANT SELECT ON mdm.field_versions,mdm.collection_definitions,mdm.collection_results TO mdm_resource_runtime,mdm_software_runtime;

GRANT SELECT,INSERT ON mdm.collection_definitions TO mdm_policy_runtime;


-- Periodic current facts enter the existing immutable collection producer in the same transaction.
GRANT INSERT ON mdm.collection_definitions,mdm.collection_results TO mdm_telemetry_runtime;