-- Only a complete, published cut can wake readers of object history.
-- ref: PostgreSQL src/backend/commands/trigger.c (transactional AFTER triggers).
CREATE FUNCTION mdm_devices.capture_object_publication() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE epoch uuid;
BEGIN
 SELECT id INTO STRICT epoch FROM mdm.asset_epochs WHERE active;
 PERFORM mdm.append_input_event(NEW.tenant_id,'object.published.v1:'||epoch::text||':'||NEW.id::text,
  'object.published','mdm.device.object-published','sha256:6e0595ce698ed915f6174ab801127037e55600b80a69585124d429c9f139c28c',
  jsonb_build_object('v',1,'tenant',NEW.tenant_id,'historyEpoch',epoch,
   'snapshotId',NEW.id,'through',NEW.through));
 RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION mdm_devices.capture_object_publication() FROM PUBLIC;
CREATE TRIGGER object_publication AFTER INSERT ON mdm_devices.object_cuts
 FOR EACH ROW EXECUTE FUNCTION mdm_devices.capture_object_publication();
