-- App binds the Telemetry invalidator to the Inventory and Policy owners.
CREATE TRIGGER invalidate_telemetry_prefix BEFORE UPDATE OR DELETE ON mdm.field_versions
 FOR EACH ROW EXECUTE FUNCTION mdm_telemetry.invalidate_frozen_prefix();
CREATE TRIGGER invalidate_telemetry_prefix BEFORE UPDATE OR DELETE ON mdm_policy.versions
 FOR EACH ROW EXECUTE FUNCTION mdm_telemetry.invalidate_frozen_prefix();
