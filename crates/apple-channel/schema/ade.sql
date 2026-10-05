-- Product ADE directories and protocol operations. Device lifecycle remains mdm_access-owned.
BEGIN;
CREATE TABLE mdm_apple.ade_servers (
 tenant_id uuid NOT NULL, organization uuid NOT NULL, revision bigint NOT NULL CHECK(revision>0), enabled boolean NOT NULL,
 server_uuid uuid NOT NULL, org_id text NOT NULL CHECK(length(org_id) BETWEEN 1 AND 256),
 key_id uuid NOT NULL, certificate bytea NOT NULL, private_key bytea NOT NULL,
 token bytea, token_revision bigint NOT NULL DEFAULT 0 CHECK(token_revision>=0), token_expires bigint,
 verified boolean NOT NULL DEFAULT false, token_invalid boolean NOT NULL DEFAULT false,
 cursor text, synced_at bigint, next_sync bigint NOT NULL DEFAULT 0,
 PRIMARY KEY(tenant_id,organization), FOREIGN KEY(tenant_id,organization) REFERENCES mdm_apple.organizations(tenant_id,id),
 CHECK((token IS NULL AND token_expires IS NULL AND token_revision=0 AND NOT verified) OR (token IS NOT NULL AND token_expires IS NOT NULL AND token_revision>0))
);
CREATE TABLE mdm_apple.ade_profiles (
 tenant_id uuid NOT NULL, organization uuid NOT NULL, id uuid NOT NULL, revision bigint NOT NULL CHECK(revision>0),
 configuration jsonb NOT NULL CHECK(octet_length(configuration::text)<=16384), remote_uuid uuid,
 PRIMARY KEY(tenant_id,organization,id), FOREIGN KEY(tenant_id,organization) REFERENCES mdm_apple.ade_servers(tenant_id,organization)
);
CREATE TABLE mdm_apple.ade_devices (
 tenant_id uuid NOT NULL, organization uuid NOT NULL, serial text NOT NULL CHECK(length(serial) BETWEEN 1 AND 128),
 operation_date timestamptz NOT NULL, deleted boolean NOT NULL, seen_run uuid NOT NULL,
 remote_profile uuid, assignment_revision bigint NOT NULL DEFAULT 1 CHECK(assignment_revision>0), observed_at bigint NOT NULL,
 PRIMARY KEY(tenant_id,organization,serial), FOREIGN KEY(tenant_id,organization) REFERENCES mdm_apple.ade_servers(tenant_id,organization)
);
CREATE TABLE mdm_apple.ade_operations (
 tenant_id uuid NOT NULL, organization uuid NOT NULL, id uuid NOT NULL, kind text NOT NULL CHECK(kind IN('configuration','token','sync','profile','assign','clear','resolve','reconcile')),
 digest text NOT NULL CHECK(digest ~ '^[0-9a-f]{64}$'), actor text NOT NULL, instance text NOT NULL,
 server_revision bigint NOT NULL, token_revision bigint NOT NULL, request jsonb NOT NULL CHECK(octet_length(request::text)<=262144),
 state text NOT NULL CHECK(state IN('pending','running','succeeded','failed','unknown','superseded')),
 receipt jsonb NOT NULL, result jsonb, cursor text, cursor_digests text[] NOT NULL DEFAULT ARRAY[]::text[] CHECK(cardinality(cursor_digests)<=10000), full_sync boolean NOT NULL DEFAULT false, lease uuid, lease_until bigint,
 next_attempt bigint NOT NULL DEFAULT 0, attempts integer NOT NULL DEFAULT 0, created_at bigint NOT NULL,
 PRIMARY KEY(tenant_id,id), FOREIGN KEY(tenant_id,organization) REFERENCES mdm_apple.organizations(tenant_id,id)
);
CREATE TABLE mdm_apple.ade_sync_devices (
 tenant_id uuid NOT NULL, operation uuid NOT NULL, serial text NOT NULL CHECK(length(serial) BETWEEN 1 AND 128),
 operation_date timestamptz NOT NULL, deleted boolean NOT NULL, remote_profile uuid,
 PRIMARY KEY(tenant_id,operation,serial), FOREIGN KEY(tenant_id,operation) REFERENCES mdm_apple.ade_operations(tenant_id,id)
);
ALTER TABLE mdm_apple.ade_sync_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_apple.ade_sync_devices FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_apple.ade_sync_devices USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT,DELETE ON mdm_apple.ade_sync_devices TO mdm_access;
GRANT UPDATE(operation_date,deleted,remote_profile) ON mdm_apple.ade_sync_devices TO mdm_access;
CREATE UNIQUE INDEX ade_one_sync ON mdm_apple.ade_operations(tenant_id,organization) WHERE kind='sync' AND state IN('pending','running');
CREATE TABLE mdm_apple.ade_enrollments (
 tenant_id uuid NOT NULL, enrollment uuid NOT NULL, organization uuid NOT NULL, serial text NOT NULL, udid text NOT NULL,
 server_revision bigint NOT NULL, assignment_revision bigint NOT NULL, profile_id uuid NOT NULL, profile_revision bigint NOT NULL,
 machine_digest text NOT NULL CHECK(machine_digest ~ '^[0-9a-f]{64}$'), machine jsonb NOT NULL,
 profile bytea NOT NULL, revoked boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,enrollment), FOREIGN KEY(tenant_id,enrollment) REFERENCES mdm_access.requests(tenant_id,id),
 FOREIGN KEY(tenant_id,organization,serial) REFERENCES mdm_apple.ade_devices(tenant_id,organization,serial),
 FOREIGN KEY(tenant_id,organization,profile_id) REFERENCES mdm_apple.ade_profiles(tenant_id,organization,id)
);
CREATE UNIQUE INDEX ade_one_serial_identity ON mdm_apple.ade_enrollments(tenant_id,organization,serial) WHERE NOT revoked;
CREATE UNIQUE INDEX ade_one_pending_identity ON mdm_apple.ade_enrollments(tenant_id,organization,udid) WHERE NOT revoked;
ALTER TABLE mdm_apple.ade_servers ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_apple.ade_servers FORCE ROW LEVEL SECURITY;
ALTER TABLE mdm_apple.ade_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_apple.ade_profiles FORCE ROW LEVEL SECURITY;
ALTER TABLE mdm_apple.ade_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_apple.ade_devices FORCE ROW LEVEL SECURITY;
ALTER TABLE mdm_apple.ade_operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_apple.ade_operations FORCE ROW LEVEL SECURITY;
ALTER TABLE mdm_apple.ade_enrollments ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_apple.ade_enrollments FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_apple.ade_servers USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY tenant ON mdm_apple.ade_profiles USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY tenant ON mdm_apple.ade_devices USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY tenant ON mdm_apple.ade_operations USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY tenant ON mdm_apple.ade_enrollments USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON mdm_apple.ade_servers,mdm_apple.ade_profiles,mdm_apple.ade_devices,mdm_apple.ade_operations,mdm_apple.ade_enrollments TO mdm_access;
GRANT UPDATE(revision,enabled,server_uuid,org_id,key_id,certificate,private_key,token,token_revision,token_expires,verified,token_invalid,cursor,synced_at,next_sync) ON mdm_apple.ade_servers TO mdm_access;
GRANT UPDATE(revision,configuration,remote_uuid) ON mdm_apple.ade_profiles TO mdm_access;
GRANT UPDATE(operation_date,deleted,seen_run,remote_profile,assignment_revision,observed_at) ON mdm_apple.ade_devices TO mdm_access;
GRANT UPDATE(state,result,cursor,cursor_digests,full_sync,lease,lease_until,next_attempt,attempts) ON mdm_apple.ade_operations TO mdm_access;
GRANT UPDATE(revoked) ON mdm_apple.ade_enrollments TO mdm_access;
COMMIT;
