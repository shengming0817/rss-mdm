-- Fresh installation: content-service owns these objects.
BEGIN;
SET LOCAL check_function_bodies = false;

GRANT USAGE ON SCHEMA mdm_content TO mdm_flow_runtime;

GRANT SELECT,INSERT ON TABLE mdm_content.bindings TO mdm_flow_runtime;
GRANT USAGE ON SCHEMA mdm_content TO mdm_command_runtime,mdm_access;
GRANT SELECT ON mdm_content.settings,mdm_content.generations,mdm_content.migrations,mdm_content.objects TO mdm_access;
GRANT SELECT ON mdm_content.migrations TO mdm_flow_runtime;
GRANT SELECT,INSERT,UPDATE,DELETE ON mdm_content.uploads,mdm_content.objects,mdm_content.manifests,mdm_content.pins TO mdm_flow_runtime;
GRANT SELECT,INSERT ON mdm_content.settings,mdm_content.generations TO mdm_flow_runtime;
GRANT USAGE ON SCHEMA mdm_content TO mdm_resource_runtime;
GRANT SELECT ON mdm_content.manifests TO mdm_command_runtime;
GRANT SELECT(tenant_id,sha256,state) ON mdm_content.manifests TO mdm_resource_runtime;
GRANT SELECT(tenant_id,maintenance) ON mdm_content.settings TO mdm_resource_runtime;
-- Resource's artifact lock orders insertion against qualification of deletion. At READ COMMITTED
-- this trigger observes the committed deletion barrier even if an earlier preflight was ready.
CREATE FUNCTION mdm_content.reference_ready() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 PERFORM pg_advisory_xact_lock_shared(hashtextextended(NEW.tenant_id::text,30041));
 IF EXISTS(SELECT 1 FROM mdm_content.settings WHERE tenant_id=NEW.tenant_id AND maintenance<>'normal') THEN
  RAISE EXCEPTION 'content maintenance' USING ERRCODE='40001';
 END IF;
 IF NOT NEW.archived AND EXISTS(SELECT 1 FROM mdm_content.manifests WHERE tenant_id=NEW.tenant_id AND sha256=NEW.sha256 AND state='deleting') THEN
  RAISE EXCEPTION 'content is deleting' USING ERRCODE='40001';
 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION mdm_content.reference_ready() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mdm_content.reference_ready() TO mdm_resource_runtime;
CREATE TRIGGER content_reference_ready BEFORE INSERT OR UPDATE ON mdm_resource.artifact_refs
 FOR EACH ROW EXECUTE FUNCTION mdm_content.reference_ready();
CREATE FUNCTION mdm_content.request_migration(p_operation uuid,p_revision bigint,p_target bigint,p_generation uuid,p_request jsonb) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $migration$
DECLARE tenant uuid := nullif(current_setting('rss.tenant_id',true),'')::uuid; source uuid; active_revision bigint; mode text;
BEGIN
 IF tenant IS NULL OR p_operation='00000000-0000-0000-0000-000000000000' OR p_generation='00000000-0000-0000-0000-000000000000' OR p_revision<=0 OR p_target<=0 OR pg_column_size(p_request)>32768 THEN RAISE EXCEPTION 'invalid migration request'; END IF;
 SELECT active_generation,revision,maintenance INTO source,active_revision,mode FROM mdm_content.settings WHERE tenant_id=tenant FOR UPDATE;
 IF source IS NULL OR active_revision<>p_revision OR mode<>'normal' THEN RAISE EXCEPTION 'storage revision conflict'; END IF;
 IF NOT EXISTS(SELECT 1 FROM mdm_content_connections.versions WHERE tenant_id=tenant AND revision=p_target AND state='qualified' AND NOT revoked AND (expires_at IS NULL OR expires_at>extract(epoch FROM clock_timestamp()))) THEN RAISE EXCEPTION 'target not qualified'; END IF;
 INSERT INTO mdm_content.migrations(tenant_id,operation_id,source_generation,target_generation,expected_revision,target_revision,request,phase) VALUES(tenant,p_operation,source,p_generation,p_revision,p_target,p_request,'requested');
END $migration$;
ALTER FUNCTION mdm_content.request_migration(uuid,bigint,bigint,uuid,jsonb) OWNER TO mdm_owner;
REVOKE ALL ON FUNCTION mdm_content.request_migration(uuid,bigint,bigint,uuid,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mdm_content.request_migration(uuid,bigint,bigint,uuid,jsonb) TO mdm_access;
CREATE FUNCTION mdm_content.observe_generation(p_generation uuid) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $observe$
DECLARE tenant uuid := nullif(current_setting('rss.tenant_id',true),'')::uuid;
BEGIN
 UPDATE mdm_content.migrations m SET observed_at=coalesce(observed_at,floor(extract(epoch FROM clock_timestamp()))::bigint)
 WHERE tenant_id=tenant AND target_generation=p_generation AND phase='committed'
 AND EXISTS(SELECT 1 FROM mdm_content.settings s WHERE s.tenant_id=m.tenant_id AND s.active_generation=p_generation AND s.operation=m.operation_id AND s.maintenance='switching');
 UPDATE mdm_content.settings s SET maintenance='normal',operation=NULL
 WHERE tenant_id=tenant AND active_generation=p_generation AND maintenance='switching'
 AND EXISTS(SELECT 1 FROM mdm_content.migrations m WHERE m.tenant_id=s.tenant_id AND m.operation_id=s.operation AND m.target_generation=p_generation AND m.phase='committed');
 RETURN FOUND;
END $observe$;
ALTER FUNCTION mdm_content.observe_generation(uuid) OWNER TO mdm_owner;
REVOKE ALL ON FUNCTION mdm_content.observe_generation(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mdm_content.observe_generation(uuid) TO mdm_flow_runtime;
CREATE FUNCTION mdm_content.cancel_migration(p_operation uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $cancel$
DECLARE tenant uuid := nullif(current_setting('rss.tenant_id',true),'')::uuid; state text;
BEGIN
 IF NOT pg_try_advisory_xact_lock(hashtextextended(tenant::text,30042)) THEN RAISE EXCEPTION 'migration busy'; END IF;
 SELECT phase INTO state FROM mdm_content.migrations WHERE tenant_id=tenant AND operation_id=p_operation FOR UPDATE;
 IF state='cancelled' THEN RETURN; END IF;
 IF state IS NULL OR state='committed' THEN RAISE EXCEPTION 'migration cannot be cancelled'; END IF;
 UPDATE mdm_content.settings SET maintenance='normal',operation=NULL WHERE tenant_id=tenant AND operation=p_operation;
 UPDATE mdm_content.migrations SET phase='cancelled',blocked_reason=NULL WHERE tenant_id=tenant AND operation_id=p_operation;
END $cancel$;
ALTER FUNCTION mdm_content.cancel_migration(uuid) OWNER TO mdm_owner;
REVOKE ALL ON FUNCTION mdm_content.cancel_migration(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mdm_content.cancel_migration(uuid) TO mdm_access;
CREATE FUNCTION mdm_content.record_marker(p_generation uuid,p_marker jsonb) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $marker$
DECLARE tenant uuid := nullif(current_setting('rss.tenant_id',true),'')::uuid; old jsonb;
BEGIN
 IF tenant IS NULL OR pg_column_size(p_marker)>32768 THEN RAISE EXCEPTION 'invalid marker'; END IF;
 SELECT marker INTO old FROM mdm_content.generations WHERE tenant_id=tenant AND id=p_generation FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'unknown generation'; END IF;
 IF old IS NOT NULL AND old<>p_marker THEN RAISE EXCEPTION 'marker conflict'; END IF;
 UPDATE mdm_content.generations SET marker=p_marker WHERE tenant_id=tenant AND id=p_generation AND marker IS NULL;
END $marker$;
ALTER FUNCTION mdm_content.record_marker(uuid,jsonb) OWNER TO mdm_owner;
REVOKE ALL ON FUNCTION mdm_content.record_marker(uuid,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mdm_content.record_marker(uuid,jsonb) TO mdm_flow_runtime;
CREATE FUNCTION mdm_content.require_mutation() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $mutation$
DECLARE tenant uuid := nullif(current_setting('rss.tenant_id',true),'')::uuid;
BEGIN
 IF current_user='mdm_owner' AND session_user='mdm_owner' THEN RETURN NULL; END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended(tenant::text,30041));
 IF NOT EXISTS(SELECT 1 FROM mdm_content.settings WHERE tenant_id=tenant AND maintenance='normal' AND active_generation=nullif(current_setting('rss.content_generation',true),'')::uuid) THEN
  RAISE EXCEPTION 'content generation fenced' USING ERRCODE='40001';
 END IF;
 RETURN NULL;
END $mutation$;
REVOKE ALL ON FUNCTION mdm_content.require_mutation() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mdm_content.require_mutation() TO mdm_flow_runtime;
CREATE TRIGGER content_mutation BEFORE INSERT OR UPDATE OR DELETE ON mdm_content.objects FOR EACH STATEMENT EXECUTE FUNCTION mdm_content.require_mutation();
CREATE TRIGGER content_mutation BEFORE INSERT OR UPDATE OR DELETE ON mdm_content.uploads FOR EACH STATEMENT EXECUTE FUNCTION mdm_content.require_mutation();
CREATE TRIGGER content_mutation BEFORE INSERT OR UPDATE OR DELETE ON mdm_content.manifests FOR EACH STATEMENT EXECUTE FUNCTION mdm_content.require_mutation();
-- The owner seals a complete target. This bounded capability only commits that existing proof
-- in the restricted Audit source transaction; it cannot copy, qualify or forge a generation.
CREATE FUNCTION mdm_content.commit_migration(p_operation uuid) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $commit_migration$
DECLARE tenant uuid := nullif(current_setting('rss.tenant_id',true),'')::uuid; m mdm_content.migrations%ROWTYPE;
BEGIN
 IF NOT (pg_try_advisory_xact_lock(hashtextextended(tenant::text,30042)) AND pg_try_advisory_xact_lock(hashtextextended(tenant::text,30041)) AND pg_try_advisory_xact_lock(hashtextextended(tenant::text,30040))) THEN RAISE EXCEPTION 'content operations active'; END IF;
 SELECT * INTO m FROM mdm_content.migrations WHERE tenant_id=tenant AND operation_id=p_operation FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'unknown migration'; END IF;
 IF m.phase='committed' THEN RETURN true; END IF;
 IF m.phase<>'ready' THEN RAISE EXCEPTION 'migration not ready'; END IF;
 IF NOT EXISTS(SELECT 1 FROM mdm_content_connections.versions WHERE tenant_id=tenant AND revision=m.target_revision AND state='qualified' AND NOT revoked AND (expires_at IS NULL OR expires_at>extract(epoch FROM clock_timestamp()))) THEN RAISE EXCEPTION 'target not qualified'; END IF;
 UPDATE mdm_content.settings SET active_generation=m.target_generation,revision=revision+1,maintenance='switching'
 WHERE tenant_id=tenant AND active_generation=m.source_generation AND revision=m.expected_revision AND maintenance='switching' AND operation=p_operation;
 IF NOT FOUND THEN RAISE EXCEPTION 'source generation conflict'; END IF;
 UPDATE mdm_content.migrations SET phase='committed',blocked_reason=NULL WHERE tenant_id=tenant AND operation_id=p_operation;
 RETURN false;
END $commit_migration$;
ALTER FUNCTION mdm_content.commit_migration(uuid) OWNER TO mdm_owner;
REVOKE ALL ON FUNCTION mdm_content.commit_migration(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mdm_content.commit_migration(uuid) TO mdm_access;
COMMIT;
