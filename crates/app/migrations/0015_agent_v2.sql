BEGIN;
-- Historical V1 bindings remain audit evidence. Runtime admission requires V2.
ALTER TABLE mdm_access.agent_bindings DROP CONSTRAINT agent_bindings_wire_version_check;
ALTER TABLE mdm_access.agent_bindings DROP CONSTRAINT agent_bindings_capabilities_check;
ALTER TABLE mdm_access.agent_bindings ADD CONSTRAINT agent_binding_profile CHECK (
 (wire_version=1 AND capabilities='["inventory.basic.v1"]') OR
 (wire_version=2 AND capabilities='["inventory.basic.v2"]')
);
COMMIT;
