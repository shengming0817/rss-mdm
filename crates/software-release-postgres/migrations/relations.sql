
-- Explicit integration privileges owned by this capability.
GRANT USAGE ON SCHEMA mdm_software_release TO mdm_software_release_runtime;

GRANT SELECT,INSERT ON TABLE mdm_software_release.aggregates TO mdm_software_release_runtime;

GRANT UPDATE(revision) ON TABLE mdm_software_release.aggregates TO mdm_software_release_runtime;

GRANT UPDATE(document) ON TABLE mdm_software_release.aggregates TO mdm_software_release_runtime;

GRANT UPDATE(digest) ON TABLE mdm_software_release.aggregates TO mdm_software_release_runtime;

GRANT SELECT,INSERT ON TABLE mdm_software_release.immutable TO mdm_software_release_runtime;

GRANT SELECT,INSERT ON TABLE mdm_software_release.requests TO mdm_software_release_runtime;
