-- Non-inventory inputs to directory cursors. Inventory and association generations
-- remain with their existing owners; these low-frequency facts have one monotonic revision.
BEGIN;
ALTER TABLE mdm_devices.checkpoints ADD COLUMN query_revision bigint NOT NULL DEFAULT 0 CHECK(query_revision>=0);
CREATE FUNCTION mdm_devices.advance_query_revision() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE tenant uuid;
BEGIN
 tenant=CASE WHEN TG_OP='DELETE' THEN OLD.tenant_id ELSE NEW.tenant_id END;
 INSERT INTO mdm_devices.checkpoints(tenant_id,watermark,query_revision) VALUES(tenant,0,1)
 ON CONFLICT(tenant_id) DO UPDATE SET query_revision=mdm_devices.checkpoints.query_revision+1;
 RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
END $$;
REVOKE ALL ON FUNCTION mdm_devices.advance_query_revision() FROM PUBLIC;
CREATE TRIGGER directory_revision AFTER INSERT OR UPDATE OR DELETE ON mdm_access.current_users FOR EACH ROW EXECUTE FUNCTION mdm_devices.advance_query_revision();
CREATE TRIGGER directory_revision AFTER INSERT OR UPDATE OR DELETE ON mdm_access.registration_users FOR EACH ROW EXECUTE FUNCTION mdm_devices.advance_query_revision();
CREATE TRIGGER directory_revision AFTER INSERT OR UPDATE OR DELETE ON mdm_access.requests FOR EACH ROW EXECUTE FUNCTION mdm_devices.advance_query_revision();
CREATE TRIGGER directory_revision AFTER INSERT OR UPDATE OR DELETE ON mdm_access.grants FOR EACH ROW EXECUTE FUNCTION mdm_devices.advance_query_revision();
CREATE TRIGGER directory_revision AFTER INSERT OR UPDATE OR DELETE ON mdm_devices.asset_states FOR EACH ROW EXECUTE FUNCTION mdm_devices.advance_query_revision();
CREATE TRIGGER directory_revision AFTER INSERT OR UPDATE OR DELETE ON mdm_pki.trust FOR EACH ROW EXECUTE FUNCTION mdm_devices.advance_query_revision();
CREATE TRIGGER directory_revision AFTER INSERT OR UPDATE OR DELETE ON mdm_pki.revocations FOR EACH ROW EXECUTE FUNCTION mdm_devices.advance_query_revision();
-- Platform session qualification changes invalidate search and hydration together.
CREATE TRIGGER directory_revision AFTER INSERT OR UPDATE OR DELETE ON mdm_apple.psso_sources FOR EACH ROW EXECUTE FUNCTION mdm_devices.advance_query_revision();
CREATE TRIGGER directory_revision AFTER INSERT OR UPDATE OR DELETE ON mdm_access.device_access_bindings FOR EACH ROW EXECUTE FUNCTION mdm_devices.advance_query_revision();
CREATE TRIGGER directory_revision AFTER INSERT OR UPDATE OR DELETE ON mdm_apple.devices FOR EACH ROW EXECUTE FUNCTION mdm_devices.advance_query_revision();
CREATE TRIGGER directory_revision AFTER INSERT OR UPDATE OR DELETE ON mdm_apple.profiles FOR EACH ROW EXECUTE FUNCTION mdm_devices.advance_query_revision();
CREATE TRIGGER directory_revision AFTER INSERT OR UPDATE OR DELETE ON mdm_apple.attempts FOR EACH ROW EXECUTE FUNCTION mdm_devices.advance_query_revision();
CREATE TRIGGER directory_revision AFTER INSERT OR UPDATE OR DELETE ON mdm_policy.policies FOR EACH ROW EXECUTE FUNCTION mdm_devices.advance_query_revision();
CREATE TRIGGER directory_revision AFTER INSERT OR UPDATE OR DELETE ON mdm_planning.scopes FOR EACH ROW EXECUTE FUNCTION mdm_devices.advance_query_revision();
CREATE TRIGGER directory_revision AFTER INSERT OR UPDATE OR DELETE ON mdm_planning.scope_runs FOR EACH ROW EXECUTE FUNCTION mdm_devices.advance_query_revision();
CREATE TRIGGER directory_revision AFTER INSERT OR UPDATE OR DELETE ON mdm_planning.scope_source_members FOR EACH ROW EXECUTE FUNCTION mdm_devices.advance_query_revision();
CREATE TRIGGER directory_revision AFTER INSERT OR UPDATE OR DELETE ON mdm_planning.scope_channel_results FOR EACH ROW EXECUTE FUNCTION mdm_devices.advance_query_revision();
CREATE TRIGGER directory_revision AFTER INSERT OR UPDATE OR DELETE ON mdm_access.authorization_rules FOR EACH ROW EXECUTE FUNCTION mdm_devices.advance_query_revision();
CREATE TRIGGER directory_revision AFTER INSERT OR UPDATE OR DELETE ON mdm_access.user_groups FOR EACH ROW EXECUTE FUNCTION mdm_devices.advance_query_revision();
CREATE TRIGGER directory_revision AFTER INSERT OR UPDATE OR DELETE ON mdm_planning.source_heads FOR EACH ROW EXECUTE FUNCTION mdm_devices.advance_query_revision();
CREATE TRIGGER directory_revision AFTER INSERT OR UPDATE OR DELETE ON mdm_group.groups FOR EACH ROW EXECUTE FUNCTION mdm_devices.advance_query_revision();
CREATE TRIGGER directory_revision AFTER INSERT OR UPDATE OR DELETE ON mdm_group.member_runs FOR EACH ROW EXECUTE FUNCTION mdm_devices.advance_query_revision();
GRANT USAGE ON SCHEMA mdm_devices,mdm TO mdm_identity_runtime;
GRANT SELECT ON mdm_devices.associations,mdm_devices.members,mdm_devices.asset_states,mdm_devices.checkpoints,mdm.asset_clock TO mdm_identity_runtime;
COMMIT;

CREATE TRIGGER directory_revision AFTER INSERT OR UPDATE OR DELETE ON mdm_access.api_keys FOR EACH ROW EXECUTE FUNCTION mdm_devices.advance_query_revision();
