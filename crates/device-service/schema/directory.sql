-- Non-inventory inputs to directory cursors. Inventory and association generations
-- remain with their existing owners. The sum of fixed shards is an equality witness.
BEGIN;
CREATE TABLE mdm_devices.query_revisions (
 tenant_id uuid NOT NULL,bucket smallint NOT NULL CHECK(bucket BETWEEN 0 AND 63),
 revision bigint NOT NULL CHECK(revision>=0),PRIMARY KEY(tenant_id,bucket)
);
ALTER TABLE mdm_devices.query_revisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_devices.query_revisions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_devices.query_revisions USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON mdm_devices.query_revisions FROM PUBLIC;
GRANT SELECT ON mdm_devices.query_revisions TO mdm_access,mdm_inventory_runtime,mdm_scope_runtime,mdm_policy_runtime,mdm_telemetry_runtime,mdm_command_runtime,mdm_identity_runtime;
-- One transaction chooses exactly one shard before any participating statement.
-- Nested triggers therefore cannot acquire a second shard in an accidental order.
CREATE FUNCTION mdm_devices.prepare_query_revision() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE tenant uuid:=nullif(current_setting('rss.tenant_id',true),'')::uuid;
 shard smallint:=mod(pg_current_xact_id()::text::numeric,64)::smallint;
BEGIN
 IF tenant IS NULL THEN RAISE EXCEPTION 'tenant required' USING ERRCODE='42501'; END IF;
 IF NOT pg_try_advisory_xact_lock(hashtextextended(tenant::text||':'||shard::text,3047)) THEN
  RAISE EXCEPTION 'query revision busy' USING ERRCODE='40001';
 END IF;
 RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION mdm_devices.prepare_query_revision() FROM PUBLIC;
CREATE FUNCTION mdm_devices.advance_query_revision() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE tenant uuid; doc jsonb; shard smallint:=mod(pg_current_xact_id()::text::numeric,64)::smallint; advanced bigint;
BEGIN
 IF TG_OP='UPDATE' AND NEW IS NOT DISTINCT FROM OLD THEN RETURN NEW; END IF;
 doc=CASE WHEN TG_OP='DELETE' THEN to_jsonb(OLD) ELSE to_jsonb(NEW) END;
 tenant=(doc->>'tenant_id')::uuid;
 IF tenant IS DISTINCT FROM nullif(current_setting('rss.tenant_id',true),'')::uuid THEN
  RAISE EXCEPTION 'tenant mismatch' USING ERRCODE='42501';
 END IF;
 INSERT INTO mdm_devices.query_revisions VALUES(tenant,shard,1)
 ON CONFLICT(tenant_id,bucket) DO UPDATE SET revision=mdm_devices.query_revisions.revision+1
 WHERE mdm_devices.query_revisions.revision<9223372036854775807 RETURNING revision INTO advanced;
 IF NOT FOUND THEN RAISE EXCEPTION 'query revision exhausted' USING ERRCODE='22003'; END IF;
 RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
END $$;
REVOKE ALL ON FUNCTION mdm_devices.advance_query_revision() FROM PUBLIC;

CREATE TRIGGER prepare_directory_revision BEFORE INSERT OR UPDATE OR DELETE ON mdm_access.current_users FOR EACH STATEMENT EXECUTE FUNCTION mdm_devices.prepare_query_revision();
CREATE TRIGGER directory_revision AFTER INSERT OR UPDATE OR DELETE ON mdm_access.current_users FOR EACH ROW EXECUTE FUNCTION mdm_devices.advance_query_revision();
CREATE TRIGGER prepare_directory_revision BEFORE INSERT OR UPDATE OR DELETE ON mdm_access.registration_users FOR EACH STATEMENT EXECUTE FUNCTION mdm_devices.prepare_query_revision();
CREATE TRIGGER directory_revision AFTER INSERT OR UPDATE OR DELETE ON mdm_access.registration_users FOR EACH ROW EXECUTE FUNCTION mdm_devices.advance_query_revision();
CREATE TRIGGER prepare_directory_revision BEFORE INSERT OR UPDATE OR DELETE ON mdm_access.requests FOR EACH STATEMENT EXECUTE FUNCTION mdm_devices.prepare_query_revision();
CREATE TRIGGER directory_revision AFTER INSERT OR UPDATE OR DELETE ON mdm_access.requests FOR EACH ROW EXECUTE FUNCTION mdm_devices.advance_query_revision();
CREATE TRIGGER prepare_directory_revision BEFORE INSERT OR UPDATE OR DELETE ON mdm_access.grants FOR EACH STATEMENT EXECUTE FUNCTION mdm_devices.prepare_query_revision();
CREATE TRIGGER directory_revision AFTER INSERT OR UPDATE OR DELETE ON mdm_access.grants FOR EACH ROW EXECUTE FUNCTION mdm_devices.advance_query_revision();
CREATE TRIGGER prepare_directory_revision BEFORE INSERT OR UPDATE OR DELETE ON mdm_devices.asset_states FOR EACH STATEMENT EXECUTE FUNCTION mdm_devices.prepare_query_revision();
CREATE TRIGGER directory_revision AFTER INSERT OR UPDATE OR DELETE ON mdm_devices.asset_states FOR EACH ROW EXECUTE FUNCTION mdm_devices.advance_query_revision();
CREATE TRIGGER prepare_directory_revision BEFORE INSERT OR UPDATE OR DELETE ON mdm_pki.trust FOR EACH STATEMENT EXECUTE FUNCTION mdm_devices.prepare_query_revision();
CREATE TRIGGER directory_revision AFTER INSERT OR UPDATE OR DELETE ON mdm_pki.trust FOR EACH ROW EXECUTE FUNCTION mdm_devices.advance_query_revision();
CREATE TRIGGER prepare_directory_revision BEFORE INSERT OR UPDATE OR DELETE ON mdm_pki.revocations FOR EACH STATEMENT EXECUTE FUNCTION mdm_devices.prepare_query_revision();
CREATE TRIGGER directory_revision AFTER INSERT OR UPDATE OR DELETE ON mdm_pki.revocations FOR EACH ROW EXECUTE FUNCTION mdm_devices.advance_query_revision();
-- Platform session qualification changes invalidate search and hydration together.
CREATE TRIGGER prepare_directory_revision BEFORE INSERT OR UPDATE OR DELETE ON mdm_apple.psso_sources FOR EACH STATEMENT EXECUTE FUNCTION mdm_devices.prepare_query_revision();
CREATE TRIGGER directory_revision AFTER INSERT OR UPDATE OR DELETE ON mdm_apple.psso_sources FOR EACH ROW EXECUTE FUNCTION mdm_devices.advance_query_revision();
CREATE TRIGGER prepare_directory_revision BEFORE INSERT OR UPDATE OR DELETE ON mdm_access.device_access_bindings FOR EACH STATEMENT EXECUTE FUNCTION mdm_devices.prepare_query_revision();
CREATE TRIGGER directory_revision AFTER INSERT OR UPDATE OR DELETE ON mdm_access.device_access_bindings FOR EACH ROW EXECUTE FUNCTION mdm_devices.advance_query_revision();
CREATE TRIGGER prepare_directory_revision BEFORE INSERT OR UPDATE OR DELETE ON mdm_apple.devices FOR EACH STATEMENT EXECUTE FUNCTION mdm_devices.prepare_query_revision();
CREATE TRIGGER directory_revision AFTER INSERT OR UPDATE OR DELETE ON mdm_apple.devices FOR EACH ROW EXECUTE FUNCTION mdm_devices.advance_query_revision();
CREATE TRIGGER prepare_directory_revision BEFORE INSERT OR UPDATE OR DELETE ON mdm_apple.profiles FOR EACH STATEMENT EXECUTE FUNCTION mdm_devices.prepare_query_revision();
CREATE TRIGGER directory_revision AFTER INSERT OR UPDATE OR DELETE ON mdm_apple.profiles FOR EACH ROW EXECUTE FUNCTION mdm_devices.advance_query_revision();
CREATE TRIGGER prepare_directory_revision BEFORE INSERT OR UPDATE OR DELETE ON mdm_apple.attempts FOR EACH STATEMENT EXECUTE FUNCTION mdm_devices.prepare_query_revision();
CREATE TRIGGER directory_revision AFTER INSERT OR UPDATE OR DELETE ON mdm_apple.attempts FOR EACH ROW EXECUTE FUNCTION mdm_devices.advance_query_revision();
CREATE TRIGGER prepare_directory_revision BEFORE INSERT OR UPDATE OR DELETE ON mdm_policy.policies FOR EACH STATEMENT EXECUTE FUNCTION mdm_devices.prepare_query_revision();
CREATE TRIGGER directory_revision AFTER INSERT OR UPDATE OR DELETE ON mdm_policy.policies FOR EACH ROW EXECUTE FUNCTION mdm_devices.advance_query_revision();
CREATE TRIGGER prepare_directory_revision BEFORE INSERT OR UPDATE OR DELETE ON mdm_scope.scopes FOR EACH STATEMENT EXECUTE FUNCTION mdm_devices.prepare_query_revision();
CREATE TRIGGER directory_revision AFTER INSERT OR UPDATE OR DELETE ON mdm_scope.scopes FOR EACH ROW EXECUTE FUNCTION mdm_devices.advance_query_revision();
CREATE TRIGGER prepare_directory_revision BEFORE INSERT OR UPDATE OR DELETE ON mdm_scope.scope_runs FOR EACH STATEMENT EXECUTE FUNCTION mdm_devices.prepare_query_revision();
CREATE TRIGGER directory_revision AFTER INSERT OR UPDATE OR DELETE ON mdm_scope.scope_runs FOR EACH ROW EXECUTE FUNCTION mdm_devices.advance_query_revision();
CREATE TRIGGER prepare_directory_revision BEFORE INSERT OR UPDATE OR DELETE ON mdm_scope.scope_source_members FOR EACH STATEMENT EXECUTE FUNCTION mdm_devices.prepare_query_revision();
CREATE TRIGGER directory_revision AFTER INSERT OR UPDATE OR DELETE ON mdm_scope.scope_source_members FOR EACH ROW EXECUTE FUNCTION mdm_devices.advance_query_revision();
CREATE TRIGGER prepare_directory_revision BEFORE INSERT OR UPDATE OR DELETE ON mdm_commands.scope_channel_results FOR EACH STATEMENT EXECUTE FUNCTION mdm_devices.prepare_query_revision();
CREATE TRIGGER directory_revision AFTER INSERT OR UPDATE OR DELETE ON mdm_commands.scope_channel_results FOR EACH ROW EXECUTE FUNCTION mdm_devices.advance_query_revision();
CREATE TRIGGER prepare_directory_revision BEFORE INSERT OR UPDATE OR DELETE ON mdm_access.authorization_rules FOR EACH STATEMENT EXECUTE FUNCTION mdm_devices.prepare_query_revision();
CREATE TRIGGER directory_revision AFTER INSERT OR UPDATE OR DELETE ON mdm_access.authorization_rules FOR EACH ROW EXECUTE FUNCTION mdm_devices.advance_query_revision();
CREATE TRIGGER prepare_directory_revision BEFORE INSERT OR UPDATE OR DELETE ON mdm_access.user_groups FOR EACH STATEMENT EXECUTE FUNCTION mdm_devices.prepare_query_revision();
CREATE TRIGGER directory_revision AFTER INSERT OR UPDATE OR DELETE ON mdm_access.user_groups FOR EACH ROW EXECUTE FUNCTION mdm_devices.advance_query_revision();
CREATE TRIGGER prepare_directory_revision BEFORE INSERT OR UPDATE OR DELETE ON mdm_group.source_state FOR EACH STATEMENT EXECUTE FUNCTION mdm_devices.prepare_query_revision();
CREATE TRIGGER directory_revision AFTER INSERT OR UPDATE OR DELETE ON mdm_group.source_state FOR EACH ROW EXECUTE FUNCTION mdm_devices.advance_query_revision();
CREATE TRIGGER prepare_directory_revision BEFORE INSERT OR UPDATE OR DELETE ON mdm_group.groups FOR EACH STATEMENT EXECUTE FUNCTION mdm_devices.prepare_query_revision();
CREATE TRIGGER directory_revision AFTER INSERT OR UPDATE OR DELETE ON mdm_group.groups FOR EACH ROW EXECUTE FUNCTION mdm_devices.advance_query_revision();
CREATE TRIGGER prepare_directory_revision BEFORE INSERT OR UPDATE OR DELETE ON mdm_group.member_runs FOR EACH STATEMENT EXECUTE FUNCTION mdm_devices.prepare_query_revision();
CREATE TRIGGER directory_revision AFTER INSERT OR UPDATE OR DELETE ON mdm_group.member_runs FOR EACH ROW EXECUTE FUNCTION mdm_devices.advance_query_revision();
GRANT USAGE ON SCHEMA mdm_devices,mdm TO mdm_identity_runtime;
GRANT SELECT ON mdm_devices.associations,mdm_devices.members,mdm_devices.asset_states,mdm_devices.checkpoints,mdm.asset_clock TO mdm_identity_runtime;
COMMIT;

CREATE TRIGGER prepare_directory_revision BEFORE INSERT OR UPDATE OR DELETE ON mdm_access.api_keys FOR EACH STATEMENT EXECUTE FUNCTION mdm_devices.prepare_query_revision();
CREATE TRIGGER directory_revision AFTER INSERT OR UPDATE OR DELETE ON mdm_access.api_keys FOR EACH ROW EXECUTE FUNCTION mdm_devices.advance_query_revision();
