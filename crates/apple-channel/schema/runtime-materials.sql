BEGIN;
CREATE SCHEMA mdm_apple_runtime;
CREATE TABLE mdm_apple_runtime.identity (
 tenant_id uuid PRIMARY KEY,challenge_id text NOT NULL CHECK(challenge_id ~ '^[A-Za-z0-9_-]{1,128}$'),notify_id text NOT NULL CHECK(notify_id ~ '^[A-Za-z0-9_-]{1,128}$'),CHECK(challenge_id<>notify_id)
);
ALTER TABLE mdm_apple_runtime.identity ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_apple_runtime.identity FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_apple_runtime.identity USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE TABLE mdm_apple_runtime.heads (
 tenant_id uuid NOT NULL,
 purpose text NOT NULL CHECK(purpose IN ('apns','profile','managed_account')),
 revision bigint NOT NULL DEFAULT 0 CHECK(revision>=0),
 desired_revision bigint CHECK(desired_revision>0 AND desired_revision<=revision),
 PRIMARY KEY(tenant_id,purpose)
);
CREATE TABLE mdm_apple_runtime.versions (
 tenant_id uuid NOT NULL,
 purpose text NOT NULL,
 revision bigint NOT NULL CHECK(revision>0),
 key_id uuid NOT NULL,
 public_digest text NOT NULL CHECK(public_digest ~ '^[0-9a-f]{64}$'),
 private_key bytea NOT NULL,
 csr text NOT NULL,
 certificate text,
 certificate_digest text CHECK(certificate_digest ~ '^[0-9a-f]{64}$'),
 topic text,
 expires_at bigint,
 revoked boolean NOT NULL DEFAULT false,
 selected boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,purpose,revision),
 FOREIGN KEY(tenant_id,purpose) REFERENCES mdm_apple_runtime.heads(tenant_id,purpose),
 CHECK((certificate IS NULL AND certificate_digest IS NULL AND expires_at IS NULL) OR (certificate IS NOT NULL AND certificate_digest IS NOT NULL AND expires_at>0))
);
CREATE TABLE mdm_apple_runtime.operations (
 tenant_id uuid NOT NULL,
 operation_id uuid NOT NULL,
 fingerprint_key text NOT NULL,
 fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),
 receipt jsonb NOT NULL,
 PRIMARY KEY(tenant_id,operation_id)
);
CREATE TABLE mdm_apple_runtime.account_bindings (
 tenant_id uuid NOT NULL, alias text NOT NULL CHECK(length(alias) BETWEEN 1 AND 128),
 revision bigint NOT NULL CHECK(revision>0), PRIMARY KEY(tenant_id,alias)
);
ALTER TABLE mdm_apple_runtime.account_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_apple_runtime.account_bindings FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_apple_runtime.account_bindings USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
ALTER TABLE mdm_apple_runtime.heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_apple_runtime.heads FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_apple_runtime.heads USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
ALTER TABLE mdm_apple_runtime.versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_apple_runtime.versions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_apple_runtime.versions USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
ALTER TABLE mdm_apple_runtime.operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_apple_runtime.operations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_apple_runtime.operations USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON SCHEMA mdm_apple_runtime FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA mdm_apple_runtime FROM PUBLIC;
GRANT USAGE ON SCHEMA mdm_apple_runtime TO mdm_access;
GRANT SELECT,INSERT ON ALL TABLES IN SCHEMA mdm_apple_runtime TO mdm_access;
GRANT UPDATE(revision,desired_revision) ON mdm_apple_runtime.heads TO mdm_access;
GRANT UPDATE(revoked,private_key,selected) ON mdm_apple_runtime.versions TO mdm_access;
GRANT UPDATE(revision) ON mdm_apple_runtime.account_bindings TO mdm_access;
-- The command runtime can fence a claim against its tenant's current certificate without reading keys.
CREATE FUNCTION mdm_apple.claim_push_material(r bigint, expected_topic text) RETURNS boolean
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT EXISTS(SELECT FROM mdm_apple_runtime.heads h JOIN mdm_apple_runtime.versions v
 ON (v.tenant_id,v.purpose,v.revision)=(h.tenant_id,h.purpose,h.desired_revision)
 WHERE h.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND h.purpose='apns'
 AND v.revision=r AND v.topic=expected_topic AND v.selected AND NOT v.revoked AND v.expires_at>extract(epoch FROM clock_timestamp())
 FOR SHARE OF h,v)
$$;
REVOKE ALL ON FUNCTION mdm_apple.claim_push_material(bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mdm_apple.claim_push_material(bigint,text) TO mdm_command_runtime;
-- Resolve only the selected provider identity under the candidate tenant's material RLS.
CREATE FUNCTION mdm_apple.selected_push_topic(t uuid, rejected_revision bigint, observed bigint) RETURNS text
LANGUAGE plpgsql STABLE SET search_path=pg_catalog AS $$
DECLARE prior text := current_setting('rss.tenant_id',true); selected_topic text;
BEGIN
 PERFORM set_config('rss.tenant_id',t::text,true);
 SELECT v.topic INTO selected_topic FROM mdm_apple_runtime.heads h JOIN mdm_apple_runtime.versions v
 ON (v.tenant_id,v.purpose,v.revision)=(h.tenant_id,h.purpose,h.desired_revision)
 WHERE h.tenant_id=t AND h.purpose='apns' AND v.expires_at>observed AND v.revision IS DISTINCT FROM rejected_revision AND v.selected AND NOT v.revoked;
 PERFORM set_config('rss.tenant_id',coalesce(prior,''),true);
 RETURN selected_topic;
END $$;
REVOKE ALL ON FUNCTION mdm_apple.selected_push_topic(uuid,bigint,bigint) FROM PUBLIC;
CREATE FUNCTION mdm_apple.push_channel_page(t uuid,d uuid,u text,observed bigint)
RETURNS TABLE(tenant_id uuid,device uuid,user_key text,topic text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT c.tenant_id,c.device,c.user_key,selected.topic
 FROM mdm_apple.channels c CROSS JOIN LATERAL (SELECT mdm_apple.selected_push_topic(c.tenant_id,CASE WHEN c.push_outcome='rejected' THEN c.push_material_revision END,observed) AS topic OFFSET 0) selected
 WHERE c.state='active' AND c.next_push<=statement_timestamp()
 AND (c.push_lease_until IS NULL OR c.push_lease_until<=statement_timestamp())
 AND selected.topic IS NOT NULL AND (t IS NULL OR (c.tenant_id,c.device,c.user_key)>(t,d,u))
 ORDER BY c.tenant_id,c.device,c.user_key LIMIT 32
$$;
REVOKE ALL ON FUNCTION mdm_apple.push_channel_page(uuid,uuid,text,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mdm_apple.push_channel_page(uuid,uuid,text,bigint) TO mdm_access;
COMMIT;
