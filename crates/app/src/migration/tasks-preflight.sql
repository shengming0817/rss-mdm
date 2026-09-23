-- Installer advisory lock is already held. A stopped service and all-tenant quiescence
-- are required; migration never silently revokes principals or deletes business evidence.
DO $$ DECLARE t text; BEGIN
 FOR t IN SELECT jsonb_array_elements_text(configuration->'tenants') FROM public.mdm_installation LOOP
  PERFORM set_config('rss.tenant_id',t,true);
  IF EXISTS(SELECT 1 FROM mdm_access.collection_runs WHERE source='agent.builtin' AND delivery_pending)
   OR EXISTS(SELECT 1 FROM mdm_access.registrations WHERE channel='agent' AND state='active')
   OR EXISTS(SELECT 1 FROM mdm_access.credentials WHERE channel='agent' AND state='active') THEN
   RAISE EXCEPTION 'drain pending Agent reports and revoke V1 credentials and registrations before upgrade';
  END IF;
  IF EXISTS(SELECT 1 FROM mdm_resource.immutable
    WHERE kind='version' AND (convert_from(document,'UTF8')::jsonb->>4)='1') THEN
   RAISE EXCEPTION 'legacy Script versions require explicit re-authoring outside this installation';
  END IF;
 END LOOP;
END $$;
