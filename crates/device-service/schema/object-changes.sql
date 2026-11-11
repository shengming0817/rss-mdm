-- Object publication and its reliable downstream hint share the owner transaction.
CREATE FUNCTION mdm_devices.capture_object_change() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE epoch uuid;
BEGIN
 SELECT id INTO STRICT epoch FROM mdm.asset_epochs WHERE active;
 PERFORM mdm.append_input_event(NEW.tenant_id,'object.changed.v1:'||epoch::text||':'||NEW.revision::text,
  'object.changed','mdm.device.object-changed','sha256:3e335783bd163d2fe768ca7308c7bf17e2587b29f22a810a63fc489836b41457',
  jsonb_build_object('v',1,'tenant',NEW.tenant_id,'revision',NEW.revision,'historyEpoch',epoch,
   'object',NEW.object,'oldDevices',to_jsonb(NEW.old_devices),'newDevices',to_jsonb(NEW.new_devices)));
 RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION mdm_devices.capture_object_change() FROM PUBLIC;
CREATE TRIGGER object_change AFTER INSERT ON mdm_devices.object_changes
 FOR EACH ROW EXECUTE FUNCTION mdm_devices.capture_object_change();
