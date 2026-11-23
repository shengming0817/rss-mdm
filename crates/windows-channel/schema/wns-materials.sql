BEGIN;
CREATE SCHEMA mdm_wns;
CREATE TABLE mdm_wns.heads (
 tenant_id uuid PRIMARY KEY, revision bigint NOT NULL CHECK(revision>=0),
 desired_revision bigint CHECK(desired_revision>0 AND desired_revision<=revision)
);
CREATE TABLE mdm_wns.versions (
 tenant_id uuid NOT NULL, revision bigint NOT NULL CHECK(revision>0), operation_id uuid NOT NULL,
 actor text NOT NULL, fingerprint_key text NOT NULL, fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),
 pfn text NOT NULL CHECK(length(pfn) BETWEEN 1 AND 256), sid_digest bytea NOT NULL CHECK(octet_length(sid_digest)=32),
 configuration bytea NOT NULL CHECK(octet_length(configuration)=32), material bytea NOT NULL,
 attempted_at bigint, failure_reason text CHECK(failure_reason IN ('oauth_validation_failed')),
 qualified_at bigint, selected boolean NOT NULL DEFAULT false, revoked boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,revision), UNIQUE(tenant_id,operation_id),
 FOREIGN KEY(tenant_id) REFERENCES mdm_wns.heads(tenant_id)
);
CREATE TABLE mdm_wns.revocations (
 tenant_id uuid NOT NULL, operation_id uuid NOT NULL, revision bigint NOT NULL,
 material_revision bigint NOT NULL, fingerprint_key text NOT NULL, fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),
 PRIMARY KEY(tenant_id,operation_id), FOREIGN KEY(tenant_id,material_revision) REFERENCES mdm_wns.versions(tenant_id,revision)
);
ALTER TABLE mdm_wns.revocations ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_wns.revocations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_wns.revocations USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
ALTER TABLE mdm_wns.heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_wns.heads FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_wns.heads USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
ALTER TABLE mdm_wns.versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_wns.versions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_wns.versions USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY insert_only ON mdm_wns.heads AS RESTRICTIVE FOR INSERT WITH CHECK(current_user::text='mdm_owner'::text OR (revision=0 AND desired_revision IS NULL));
CREATE POLICY insert_only ON mdm_wns.versions AS RESTRICTIVE FOR INSERT WITH CHECK(current_user::text='mdm_owner'::text OR (qualified_at IS NULL AND attempted_at IS NULL AND failure_reason IS NULL AND NOT selected AND NOT revoked));
REVOKE ALL ON SCHEMA mdm_wns FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA mdm_wns FROM PUBLIC;
GRANT USAGE ON SCHEMA mdm_wns TO mdm_access;
GRANT SELECT,INSERT ON ALL TABLES IN SCHEMA mdm_wns TO mdm_access;
GRANT UPDATE(revision) ON mdm_wns.heads TO mdm_access;
GRANT UPDATE(revoked) ON mdm_wns.versions TO mdm_access;
-- 资格核验和切换仅由受限部署进程完成；普通 HTTP 只保留候选请求。
-- One deadline per contributing tenant and OAuth identity, including across credential rotations.
CREATE TABLE mdm_wns.provider_throttles (
 tenant_id uuid NOT NULL, sid_digest bytea NOT NULL CHECK(octet_length(sid_digest)=32),
 retry_at timestamptz NOT NULL, PRIMARY KEY(tenant_id,sid_digest)
);
ALTER TABLE mdm_wns.provider_throttles ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_wns.provider_throttles FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_wns.provider_throttles USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY cooldown_discovery ON mdm_wns.provider_throttles FOR SELECT TO mdm_owner USING(true);
CREATE INDEX ON mdm_wns.provider_throttles(sid_digest,retry_at);
-- Only the provider worker may attribute a shared deadline to its original live lease.
CREATE FUNCTION mdm_wns.settle_throttle(d uuid, channel_rev bigint, lease uuid, material_rev bigint, seconds bigint, date_seconds bigint)
RETURNS TABLE(changed boolean, wait_seconds double precision)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE t uuid := nullif(current_setting('rss.tenant_id',true),'')::uuid; sid bytea; deadline timestamptz;
BEGIN
 PERFORM rss_transactional_messaging.check_execution();
 SELECT v.sid_digest INTO STRICT sid FROM mdm_wns.versions v
 WHERE v.tenant_id=t AND v.revision=material_rev AND v.qualified_at IS NOT NULL;
 UPDATE mdm_windows.push_channels p SET lease_id=NULL,lease_until=NULL,settled_id=lease,
   status=406,outcome='retryable',failures=least(5,p.failures)+1,
   next_push=greatest(clock_timestamp()+make_interval(secs=>greatest(15*(1<<(least(5,p.failures)+1)),seconds)::float8),
                      to_timestamp(date_seconds::float8))
 WHERE p.tenant_id=t AND p.device=d AND p.revision=channel_rev AND p.material_revision=material_rev
   AND p.lease_id=lease AND p.lease_until>clock_timestamp()
 RETURNING p.next_push INTO deadline;
 IF FOUND THEN
   INSERT INTO mdm_wns.provider_throttles(tenant_id,sid_digest,retry_at) VALUES(t,sid,deadline)
   ON CONFLICT(tenant_id,sid_digest) DO UPDATE SET retry_at=greatest(mdm_wns.provider_throttles.retry_at,EXCLUDED.retry_at);
   RETURN QUERY SELECT true,greatest(0,extract(epoch FROM deadline-clock_timestamp()))::float8;
 ELSE
   RETURN QUERY SELECT false,greatest(0,extract(epoch FROM p.next_push-clock_timestamp()))::float8
   FROM mdm_windows.push_channels p WHERE p.tenant_id=t AND p.device=d AND p.revision=channel_rev
    AND p.material_revision=material_rev AND p.settled_id=lease AND p.status=406 AND p.outcome='retryable';
 END IF;
END $$;
REVOKE ALL ON FUNCTION mdm_wns.settle_throttle(uuid,bigint,uuid,bigint,bigint,bigint) FROM PUBLIC;
GRANT USAGE ON SCHEMA mdm_wns TO mdm_wns_runtime;
GRANT EXECUTE ON FUNCTION mdm_wns.settle_throttle(uuid,bigint,uuid,bigint,bigint,bigint) TO mdm_wns_runtime;
CREATE FUNCTION mdm_wns.provider_wait(material_rev bigint) RETURNS double precision
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT extract(epoch FROM max(p.retry_at)-statement_timestamp())::float8
 FROM mdm_wns.versions v JOIN mdm_wns.provider_throttles p USING(sid_digest)
 WHERE v.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND v.revision=material_rev
 AND v.qualified_at IS NOT NULL AND p.retry_at>statement_timestamp()
$$;
REVOKE ALL ON FUNCTION mdm_wns.provider_wait(bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mdm_wns.provider_wait(bigint) TO mdm_access;
CREATE FUNCTION mdm_wns.provider_available(digest bytea) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT EXISTS(SELECT FROM mdm_wns.versions v JOIN mdm_wns.heads h
   ON (v.tenant_id,v.revision)=(h.tenant_id,h.desired_revision)
   WHERE h.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND v.sid_digest=digest AND v.qualified_at IS NOT NULL AND NOT v.revoked)
 AND NOT EXISTS(SELECT FROM mdm_wns.provider_throttles WHERE sid_digest=digest AND retry_at>statement_timestamp())
$$;
CREATE FUNCTION mdm_wns.next_provider_wakeup() RETURNS double precision
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT extract(epoch FROM min(retry_at)-statement_timestamp())::float8 FROM mdm_wns.provider_throttles WHERE retry_at>statement_timestamp()
$$;
REVOKE ALL ON FUNCTION mdm_wns.next_provider_wakeup() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mdm_wns.next_provider_wakeup() TO mdm_access;
REVOKE ALL ON FUNCTION mdm_wns.provider_available(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mdm_wns.provider_available(bytea) TO mdm_access;
COMMIT;
