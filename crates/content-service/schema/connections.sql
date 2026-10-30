BEGIN;
CREATE SCHEMA mdm_content_connections;
CREATE TABLE mdm_content_connections.heads (
 tenant_id uuid PRIMARY KEY, revision bigint NOT NULL CHECK(revision>=0)
);
CREATE TABLE mdm_content_connections.versions (
 tenant_id uuid NOT NULL, revision bigint NOT NULL CHECK(revision>0), operation_id uuid NOT NULL,
 profile text NOT NULL, generated boolean NOT NULL, credentials bytea NOT NULL,
 fingerprint_key text NOT NULL, fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),
 state text NOT NULL DEFAULT 'pending' CHECK(state IN('pending','qualified','rejected')),
 failure_reason text, attempted_at timestamptz,
 endpoint text, region text, bucket text, namespace text, private_ca bytea,
 qualified_at bigint, expires_at bigint, revoked boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,revision), UNIQUE(tenant_id,operation_id),
 CHECK(state<>'qualified' OR (endpoint IS NOT NULL AND region IS NOT NULL AND bucket IS NOT NULL AND namespace IS NOT NULL AND qualified_at IS NOT NULL))
);
ALTER TABLE mdm_content_connections.heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_content_connections.heads FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_content_connections.heads USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
ALTER TABLE mdm_content_connections.versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_content_connections.versions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_content_connections.versions USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON SCHEMA mdm_content_connections FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA mdm_content_connections FROM PUBLIC;
GRANT USAGE ON SCHEMA mdm_content_connections TO mdm_access,mdm_content_runtime;
GRANT SELECT ON ALL TABLES IN SCHEMA mdm_content_connections TO mdm_access,mdm_content_runtime;
-- Only this bounded insertion capability is delegated. Runtime cannot claim provider qualification.
CREATE FUNCTION mdm_content_connections.reserve(p_revision bigint,p_operation uuid,p_profile text,p_generated boolean,p_credentials bytea,p_fingerprint_key text,p_fingerprint bytea,p_expires bigint) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $reserve$
DECLARE tenant uuid := nullif(current_setting('rss.tenant_id',true),'')::uuid; current_revision bigint;
BEGIN
 IF tenant IS NULL OR p_operation='00000000-0000-0000-0000-000000000000' OR p_revision<0 OR p_revision=9223372036854775807 OR length(p_profile) NOT BETWEEN 1 AND 64 OR octet_length(p_credentials)>32768 OR octet_length(p_fingerprint)<>32 THEN RAISE EXCEPTION 'invalid connection reservation'; END IF;
 INSERT INTO mdm_content_connections.heads VALUES(tenant,0) ON CONFLICT DO NOTHING;
 SELECT revision INTO current_revision FROM mdm_content_connections.heads WHERE tenant_id=tenant FOR UPDATE;
 IF current_revision<>p_revision THEN RAISE EXCEPTION 'connection revision conflict'; END IF;
 INSERT INTO mdm_content_connections.versions(tenant_id,revision,operation_id,profile,generated,credentials,fingerprint_key,fingerprint,expires_at) VALUES(tenant,p_revision+1,p_operation,p_profile,p_generated,p_credentials,p_fingerprint_key,p_fingerprint,p_expires);
 UPDATE mdm_content_connections.heads SET revision=p_revision+1 WHERE tenant_id=tenant;
END $reserve$;
ALTER FUNCTION mdm_content_connections.reserve(bigint,uuid,text,boolean,bytea,text,bytea,bigint) OWNER TO mdm_owner;
REVOKE ALL ON FUNCTION mdm_content_connections.reserve(bigint,uuid,text,boolean,bytea,text,bytea,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mdm_content_connections.reserve(bigint,uuid,text,boolean,bytea,text,bytea,bigint) TO mdm_access;
COMMIT;
