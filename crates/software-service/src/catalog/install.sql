CREATE SCHEMA mdm_software;
REVOKE ALL ON SCHEMA mdm_software FROM PUBLIC;
GRANT USAGE ON SCHEMA mdm_software TO mdm_flow_runtime;
CREATE TABLE mdm_software.sources (
 tenant_id uuid NOT NULL,id text NOT NULL,revision text NOT NULL,
 definition jsonb NOT NULL CHECK(octet_length(definition::text)<=65536),
 lifecycle jsonb NOT NULL CHECK(octet_length(lifecycle::text)<=65536),PRIMARY KEY(tenant_id,id,revision)
);
CREATE TABLE mdm_software.versions (
 tenant_id uuid NOT NULL,resource text NOT NULL,version text NOT NULL,
 lifecycle jsonb NOT NULL CHECK(octet_length(lifecycle::text)<=65536),PRIMARY KEY(tenant_id,resource,version)
);
CREATE TABLE mdm_software.operations (
 tenant_id uuid NOT NULL,id uuid NOT NULL,fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),
 response jsonb NOT NULL CHECK(octet_length(response::text)<=1048576),PRIMARY KEY(tenant_id,id)
);
CREATE TABLE mdm_software.materials (
 tenant_id uuid NOT NULL,coordinate bytea NOT NULL CHECK(octet_length(coordinate)=32),
 digest bytea NOT NULL CHECK(octet_length(digest)=32),PRIMARY KEY(tenant_id,coordinate)
);
DO $$ DECLARE t text; BEGIN FOREACH t IN ARRAY ARRAY['sources','versions','operations','materials'] LOOP
 EXECUTE format('ALTER TABLE mdm_software.%I ENABLE ROW LEVEL SECURITY',t);
 EXECUTE format('ALTER TABLE mdm_software.%I FORCE ROW LEVEL SECURITY',t);
 EXECUTE format('CREATE POLICY tenant ON mdm_software.%I USING(tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid) WITH CHECK(tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid)',t);
 EXECUTE format('GRANT SELECT,INSERT ON mdm_software.%I TO mdm_flow_runtime',t);
END LOOP; END $$;
GRANT UPDATE(lifecycle) ON mdm_software.sources,mdm_software.versions TO mdm_flow_runtime;

GRANT USAGE ON SCHEMA mdm_software TO mdm_software_driver;
GRANT SELECT ON mdm_software.sources,mdm_software.versions,mdm_software.materials TO mdm_software_driver;

-- The publication owner may atomically enable draft versions, never change source policy.
GRANT INSERT ON mdm_software.versions, mdm_software.materials TO mdm_software_driver;
GRANT UPDATE(lifecycle) ON mdm_software.versions TO mdm_software_driver;

-- Catalog-owned committed version; readers never acquire this row or the catalog lock.
CREATE TABLE mdm_software.authority_revision (tenant_id uuid PRIMARY KEY, revision bigint NOT NULL CHECK(revision>0));
ALTER TABLE mdm_software.authority_revision ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_software.authority_revision FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_software.authority_revision USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON mdm_software.authority_revision FROM PUBLIC;
CREATE FUNCTION mdm_software.advance_authority_revision() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='UPDATE' AND NEW IS NOT DISTINCT FROM OLD THEN RETURN NEW; END IF;
 INSERT INTO mdm_software.authority_revision VALUES(CASE WHEN TG_OP='DELETE' THEN OLD.tenant_id ELSE NEW.tenant_id END,1)
 ON CONFLICT(tenant_id) DO UPDATE SET revision=mdm_software.authority_revision.revision+1;
 RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
END $$;
REVOKE ALL ON FUNCTION mdm_software.advance_authority_revision() FROM PUBLIC;
CREATE TRIGGER authority_revision AFTER INSERT OR UPDATE OR DELETE ON mdm_software.sources FOR EACH ROW EXECUTE FUNCTION mdm_software.advance_authority_revision();
CREATE TRIGGER authority_revision AFTER INSERT OR UPDATE OR DELETE ON mdm_software.versions FOR EACH ROW EXECUTE FUNCTION mdm_software.advance_authority_revision();
