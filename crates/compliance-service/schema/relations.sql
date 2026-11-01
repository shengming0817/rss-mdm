-- Compliance service application capabilities.

GRANT USAGE ON SCHEMA mdm_compliance TO mdm_inventory_runtime;

GRANT SELECT,INSERT,DELETE ON TABLE mdm_compliance.fields TO mdm_inventory_runtime;

GRANT SELECT,INSERT,DELETE ON TABLE mdm_compliance.groups TO mdm_inventory_runtime;

GRANT SELECT,INSERT ON TABLE mdm_compliance.operations TO mdm_inventory_runtime;

GRANT SELECT,INSERT ON TABLE mdm_compliance.results TO mdm_inventory_runtime;

GRANT SELECT,INSERT ON TABLE mdm_compliance.rules TO mdm_inventory_runtime;

GRANT UPDATE(revision) ON TABLE mdm_compliance.rules TO mdm_inventory_runtime;

GRANT UPDATE(enabled) ON TABLE mdm_compliance.rules TO mdm_inventory_runtime;

GRANT UPDATE(desired) ON TABLE mdm_compliance.rules TO mdm_inventory_runtime;

GRANT UPDATE(current_run) ON TABLE mdm_compliance.rules TO mdm_inventory_runtime;

GRANT SELECT,INSERT ON TABLE mdm_compliance.versions TO mdm_inventory_runtime;