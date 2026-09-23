-- Called under the installer lock, before recording any new migration intent.
-- Every installed tenant is checked explicitly: the non-bypass owner is subject to FORCE RLS.
DO $$ DECLARE t text; BEGIN
 FOR t IN SELECT jsonb_array_elements_text(configuration->'tenants') FROM public.mdm_installation LOOP
 PERFORM set_config('rss.tenant_id',t,true);
 IF EXISTS(SELECT 1 FROM rss_device_command.commands WHERE status IN('queued','published','received'))
 OR EXISTS(SELECT 1 FROM rss_transactional_messaging.outbox WHERE domain='mdm.commands.v1' AND status<>'published')
 OR EXISTS(SELECT 1 FROM mdm_access.management_sessions WHERE expires_at>clock_timestamp()) THEN
 RAISE EXCEPTION 'quiesce old commands, settle dispatch and expire old management sessions before upgrade';
 END IF;
 END LOOP;
END $$;
