-- Only a complete, published cut can wake readers of object history.
-- ref: PostgreSQL src/backend/commands/trigger.c (transactional AFTER triggers).
CREATE FUNCTION mdm_devices.capture_object_publication() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE epoch uuid;
BEGIN
 SELECT id INTO STRICT epoch FROM mdm.asset_epochs WHERE active;
 PERFORM mdm.append_input_event(NEW.tenant_id,'object.published.v1:'||epoch::text||':'||NEW.id::text,
  'object.published','mdm.device.object-published','sha256:4aaeba1085d9ce3a8f6929c68c271c40077160e7b8140aab3bbc6dd46113ef91',
  jsonb_build_object('v',1,'executionEpoch',NEW.expected_epoch,'tenant',NEW.tenant_id,'historyEpoch',epoch,
   'snapshotId',NEW.id,'through',NEW.through));
 RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION mdm_devices.capture_object_publication() FROM PUBLIC;
CREATE TRIGGER object_publication AFTER INSERT ON mdm_devices.object_cuts
 FOR EACH ROW EXECUTE FUNCTION mdm_devices.capture_object_publication();

CREATE FUNCTION mdm_devices.asset_delivery_scopes(after_tenant uuid,after_epoch bigint)
RETURNS TABLE(tenant_id uuid,expected_epoch bigint)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT DISTINCT o.tenant_id,o.claim_epoch FROM rss_transactional_messaging.outbox o
 WHERE o.domain='mdm-assets' AND o.status IN ('pending','publishing','dead_letter')
   AND (after_tenant IS NULL OR (o.tenant_id,o.claim_epoch)>(after_tenant,after_epoch))
 ORDER BY o.tenant_id,o.claim_epoch LIMIT 32
$$;
REVOKE ALL ON FUNCTION mdm_devices.asset_delivery_scopes(uuid,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mdm_devices.asset_delivery_scopes(uuid,bigint) TO mdm_access;
