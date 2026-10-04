-- Fresh installation: content-service owns these objects.
BEGIN;
SET LOCAL check_function_bodies = false;

GRANT USAGE ON SCHEMA mdm_content TO mdm_flow_runtime;

GRANT SELECT,INSERT ON TABLE mdm_content.bindings TO mdm_flow_runtime;
GRANT USAGE ON SCHEMA mdm_content TO mdm_command_runtime;
GRANT SELECT,INSERT ON mdm_content.diagnostic_artifacts TO mdm_command_runtime;
GRANT SELECT ON mdm_content.diagnostic_artifacts TO mdm_flow_runtime;
GRANT SELECT,INSERT,UPDATE,DELETE ON mdm_content.uploads,mdm_content.objects,mdm_content.manifests,mdm_content.pins TO mdm_flow_runtime;
GRANT SELECT,INSERT ON mdm_content.settings TO mdm_flow_runtime;
GRANT SELECT ON mdm_content.manifests TO mdm_command_runtime;
-- Resource's artifact lock orders insertion against qualification of deletion. At READ COMMITTED
-- this trigger observes the committed deletion barrier even if an earlier preflight was ready.
CREATE FUNCTION mdm_content.reference_ready() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT NEW.archived AND EXISTS(SELECT 1 FROM mdm_content.manifests WHERE tenant_id=NEW.tenant_id AND sha256=NEW.sha256 AND state='deleting') THEN
  RAISE EXCEPTION 'content is deleting' USING ERRCODE='40001';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER content_reference_ready BEFORE INSERT OR UPDATE ON mdm_resource.artifact_refs
 FOR EACH ROW EXECUTE FUNCTION mdm_content.reference_ready();
COMMIT;
