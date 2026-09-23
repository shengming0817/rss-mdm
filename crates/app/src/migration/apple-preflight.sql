-- Stop producers and let the previous release settle accepted work before changing its ABI.
DO $$ DECLARE t text; BEGIN
 FOR t IN SELECT jsonb_array_elements_text(configuration->'tenants') FROM public.mdm_installation LOOP
  PERFORM set_config('rss.tenant_id',t,true);
  IF EXISTS(SELECT 1 FROM rss_device_command.commands WHERE status IN ('queued','published','received'))
   OR EXISTS(SELECT 1 FROM rss_transactional_messaging.outbox WHERE domain='mdm.commands.v1' AND status<>'published')
   OR EXISTS(SELECT 1 FROM mdm_access.management_sessions WHERE expires_at>clock_timestamp())
   OR EXISTS(SELECT 1 FROM mdm_access.collection_runs WHERE sealed_at IS NULL OR delivery_pending)
   OR EXISTS(SELECT 1 FROM rss_reconcile.targets WHERE reconciler='mdm.commands.v1' AND (lease_until>clock_timestamp() OR result IN ('pending','running','retry'))) THEN
   RAISE EXCEPTION 'quiesce commands, dispatch, sessions, collections and command reconciliation before upgrade';
  END IF;
 END LOOP;
END $$;
