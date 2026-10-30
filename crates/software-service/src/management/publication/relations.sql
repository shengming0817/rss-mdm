
-- Explicit integration privileges owned by this capability.
GRANT USAGE ON SCHEMA mdm_publication TO mdm_software_runtime;

GRANT SELECT,INSERT ON TABLE mdm_publication.operations TO mdm_software_runtime;
