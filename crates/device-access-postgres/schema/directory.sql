CREATE TABLE rss_da.business_revision(tenant_id uuid PRIMARY KEY,revision bigint NOT NULL CHECK(revision>0));
ALTER TABLE rss_da.business_revision ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_da.business_revision FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON rss_da.business_revision USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON rss_da.business_revision FROM PUBLIC;
GRANT SELECT ON rss_da.business_revision TO da_access,da_identity_runtime,da_command_runtime;
CREATE FUNCTION rss_da.capture_business_change() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE t uuid;
BEGIN
 t:=CASE WHEN TG_OP='DELETE' THEN OLD.tenant_id ELSE NEW.tenant_id END;
 IF t IS DISTINCT FROM nullif(current_setting('rss.tenant_id',true),'')::uuid THEN RAISE EXCEPTION 'DA tenant mismatch'; END IF;
 INSERT INTO rss_da.business_revision(tenant_id,revision) VALUES(t,1) ON CONFLICT(tenant_id) DO UPDATE SET revision=rss_da.business_revision.revision+1;
 RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
END $$;
REVOKE ALL ON FUNCTION rss_da.capture_business_change() FROM PUBLIC;
CREATE TRIGGER business_change AFTER INSERT OR UPDATE OR DELETE ON rss_da.bindings FOR EACH ROW EXECUTE FUNCTION rss_da.capture_business_change();
CREATE TRIGGER business_change AFTER INSERT OR UPDATE OR DELETE ON rss_da.subject_denials FOR EACH ROW EXECUTE FUNCTION rss_da.capture_business_change();
CREATE TRIGGER business_change AFTER INSERT OR UPDATE OR DELETE ON rss_da.lifecycles FOR EACH ROW EXECUTE FUNCTION rss_da.capture_business_change();
CREATE TRIGGER business_change AFTER INSERT OR UPDATE OR DELETE ON rss_da.relying_parties FOR EACH ROW EXECUTE FUNCTION rss_da.capture_business_change();
CREATE TRIGGER business_change AFTER INSERT OR UPDATE OR DELETE ON rss_da.subjects FOR EACH ROW EXECUTE FUNCTION rss_da.capture_business_change();
CREATE TRIGGER business_change AFTER INSERT OR UPDATE OR DELETE ON rss_da.subject_versions FOR EACH ROW EXECUTE FUNCTION rss_da.capture_business_change();
CREATE TRIGGER business_change AFTER INSERT OR UPDATE OR DELETE ON rss_da.subject_owners FOR EACH ROW EXECUTE FUNCTION rss_da.capture_business_change();
CREATE TRIGGER business_change AFTER INSERT OR UPDATE OR DELETE ON rss_da.windows_sources FOR EACH ROW EXECUTE FUNCTION rss_da.capture_business_change();
CREATE TRIGGER business_change AFTER INSERT OR UPDATE OR DELETE ON rss_da.psso_sources FOR EACH ROW EXECUTE FUNCTION rss_da.capture_business_change();
CREATE TRIGGER business_change AFTER INSERT OR UPDATE OR DELETE ON rss_da.agent_delivery FOR EACH ROW EXECUTE FUNCTION rss_da.capture_business_change();
CREATE TRIGGER business_change AFTER INSERT OR UPDATE OR DELETE ON rss_da.deployment_evidence FOR EACH ROW EXECUTE FUNCTION rss_da.capture_business_change();
CREATE TRIGGER business_change AFTER INSERT OR UPDATE OR DELETE ON rss_da.policies FOR EACH ROW EXECUTE FUNCTION rss_da.capture_business_change();
CREATE TRIGGER business_change AFTER INSERT OR UPDATE OR DELETE ON rss_da.policy_versions FOR EACH ROW EXECUTE FUNCTION rss_da.capture_business_change();
