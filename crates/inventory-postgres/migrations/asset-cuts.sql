-- Committed history visibility. XIDs are local to an installation incarnation.
-- ref: PostgreSQL REL_17_STABLE src/backend/utils/adt/xid8funcs.c.
CREATE FUNCTION mdm.capture_asset_cut(t uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,mdm AS $$
DECLARE epoch uuid;
BEGIN
 IF t IS DISTINCT FROM nullif(current_setting('rss.tenant_id',true),'')::uuid THEN
  RAISE EXCEPTION 'asset tenant mismatch' USING ERRCODE='42501';
 END IF;
 IF current_setting('transaction_read_only') <> 'on' THEN
  RAISE EXCEPTION 'asset cut requires a read-only transaction' USING ERRCODE='25006';
 END IF;
 SELECT id INTO STRICT epoch FROM mdm.asset_epochs WHERE active;
 RETURN jsonb_build_object('tenant',t,'epoch',epoch,'snapshot',pg_current_snapshot()::text);
END $$;
REVOKE ALL ON FUNCTION mdm.capture_asset_cut(uuid) FROM PUBLIC;

CREATE FUNCTION mdm.asset_cut_contains(cut jsonb, event_epoch uuid, event_xid xid8) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,mdm AS $$
DECLARE cut_epoch uuid; visibility pg_snapshot;
BEGIN
 -- NULL is the empty starting coordinate, not a forged snapshot.
 IF cut IS NULL THEN RETURN false; END IF;
 IF (cut->>'tenant')::uuid IS DISTINCT FROM nullif(current_setting('rss.tenant_id',true),'')::uuid THEN
  RAISE EXCEPTION 'asset cut tenant mismatch' USING ERRCODE='42501';
 END IF;
 IF jsonb_typeof(cut)<>'object' OR NOT (cut ?& ARRAY['tenant','epoch','snapshot'])
    OR cut-ARRAY['tenant','epoch','snapshot']<>'{}'::jsonb
    OR octet_length(cut->>'snapshot')>65536 THEN
  RAISE EXCEPTION 'invalid asset cut' USING ERRCODE='23514';
 END IF;
 cut_epoch=(cut->>'epoch')::uuid;
 visibility=(cut->>'snapshot')::pg_snapshot;
 IF NOT EXISTS(SELECT FROM mdm.asset_epochs WHERE id=cut_epoch) THEN
  RAISE EXCEPTION 'unknown asset epoch' USING ERRCODE='23514';
 END IF;
 IF event_epoch=cut_epoch THEN
  RETURN pg_visible_in_snapshot(event_xid,visibility);
 END IF;
 RETURN EXISTS(WITH RECURSIVE ancestors AS (
   SELECT parent FROM mdm.asset_epochs WHERE id=cut_epoch
   UNION ALL SELECT e.parent FROM mdm.asset_epochs e JOIN ancestors a ON e.id=a.parent
  ) SELECT FROM ancestors WHERE parent=event_epoch);
END $$;
REVOKE ALL ON FUNCTION mdm.asset_cut_contains(jsonb,uuid,xid8) FROM PUBLIC;

CREATE FUNCTION mdm.asset_visible(cut jsonb, event bigint) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,mdm AS $$
 SELECT coalesce((SELECT mdm.asset_cut_contains(cut,e.source_epoch,e.writer_xid)
  FROM mdm.asset_changes e
  WHERE e.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND e.revision=event),false)
$$;
REVOKE ALL ON FUNCTION mdm.asset_visible(jsonb,bigint) FROM PUBLIC;

-- The existing stopped restore owner calls this after pg_restore, before writers.
-- Ordinary runtime roles receive no privilege on this function or the epoch table.
CREATE FUNCTION mdm.advance_asset_epoch(operation uuid) RETURNS uuid
LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog,mdm AS $$
DECLARE previous uuid; replacement uuid; largest bigint; allocated bigint; called boolean;
BEGIN
 IF operation IS NULL OR operation='00000000-0000-0000-0000-000000000000'::uuid THEN
  RAISE EXCEPTION 'restore operation required' USING ERRCODE='22023';
 END IF;
 LOCK TABLE mdm.asset_epochs IN EXCLUSIVE MODE;
 IF NOT EXISTS(SELECT FROM pg_sequence s JOIN pg_class c ON c.oid=s.seqrelid
  WHERE s.seqrelid='mdm.asset_event_ids'::regclass AND s.seqtypid='bigint'::regtype
   AND s.seqincrement=1 AND s.seqcache=1 AND NOT s.seqcycle AND s.seqmin=1
   AND s.seqmax=9223372036854775807 AND c.relowner=(SELECT relowner FROM pg_class WHERE oid='mdm.asset_epochs'::regclass)) THEN
  RAISE EXCEPTION 'asset event allocator contract' USING ERRCODE='23514';
 END IF;
 SELECT coalesce(max(revision),0) INTO largest FROM mdm.asset_changes;
 SELECT last_value,is_called INTO allocated,called FROM mdm.asset_event_ids;
 IF allocated<largest OR (allocated=largest AND NOT called) THEN
  RAISE EXCEPTION 'asset event allocator behind history' USING ERRCODE='23514';
 END IF;

 SELECT id INTO replacement FROM mdm.asset_epochs WHERE restore_operation=operation;
 IF FOUND THEN
  IF NOT EXISTS(SELECT FROM mdm.asset_epochs WHERE id=replacement AND active) THEN
   RAISE EXCEPTION 'restore operation superseded' USING ERRCODE='23514';
  END IF;
  RETURN replacement;
 END IF;
 SELECT id INTO STRICT previous FROM mdm.asset_epochs WHERE active;
 replacement=gen_random_uuid();
 UPDATE mdm.asset_epochs SET active=false WHERE id=previous;
 INSERT INTO mdm.asset_epochs(id,parent,restore_operation,active) VALUES(replacement,previous,operation,true);
 RETURN replacement;
END $$;
REVOKE ALL ON FUNCTION mdm.advance_asset_epoch(uuid) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION mdm.capture_asset_cut(uuid) TO mdm_api;
GRANT EXECUTE ON FUNCTION mdm.capture_asset_cut(uuid),mdm.asset_cut_contains(jsonb,uuid,xid8),mdm.asset_visible(jsonb,bigint)
 TO mdm_runtime,mdm_access,mdm_identity_runtime,mdm_inventory_runtime,mdm_scope_runtime,mdm_policy_runtime,mdm_resource_runtime,mdm_telemetry_runtime,mdm_command_runtime;
