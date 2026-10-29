
-- Explicit integration privileges owned by this capability.
GRANT USAGE ON SCHEMA mdm_software_composition TO mdm_software_driver;

GRANT USAGE ON SCHEMA mdm_software_composition TO mdm_software_runtime;

GRANT SELECT,INSERT ON TABLE mdm_software_composition.authorities TO mdm_software_driver;

GRANT UPDATE(record) ON TABLE mdm_software_composition.authorities TO mdm_software_driver;

GRANT SELECT,INSERT ON TABLE mdm_software_composition.bindings TO mdm_software_driver;

GRANT SELECT,INSERT,DELETE ON TABLE mdm_software_composition.projections TO mdm_software_driver;

GRANT UPDATE(publication) ON TABLE mdm_software_composition.projections TO mdm_software_driver;

GRANT SELECT,INSERT ON TABLE mdm_software_composition.slots TO mdm_software_driver;

GRANT UPDATE(operation) ON TABLE mdm_software_composition.slots TO mdm_software_driver;

GRANT UPDATE(cursor) ON TABLE mdm_software_composition.slots TO mdm_software_driver;

GRANT SELECT,INSERT ON TABLE mdm_software_composition.subjects TO mdm_software_driver;

GRANT SELECT ON TABLE mdm_software_composition.subjects TO mdm_software_runtime;

GRANT SELECT,INSERT ON TABLE mdm_software_composition.targets TO mdm_software_driver;

GRANT UPDATE(call_generation) ON TABLE mdm_software_composition.targets TO mdm_software_driver;

GRANT UPDATE(attempted) ON TABLE mdm_software_composition.targets TO mdm_software_driver;

GRANT UPDATE(acknowledged) ON TABLE mdm_software_composition.targets TO mdm_software_driver;

GRANT SELECT,INSERT ON TABLE mdm_software_composition.withdrawals TO mdm_software_driver;

GRANT UPDATE(complete) ON TABLE mdm_software_composition.withdrawals TO mdm_software_driver;
