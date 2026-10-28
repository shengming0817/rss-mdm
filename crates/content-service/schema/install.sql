-- Fresh installation: content-service owns these objects.
BEGIN;
SET LOCAL check_function_bodies = false;

CREATE SCHEMA mdm_content;

CREATE TABLE mdm_content.bindings (
    tenant_id uuid NOT NULL,
    operation uuid NOT NULL,
    resource text NOT NULL,
    version text NOT NULL,
    reference text NOT NULL,
    length bigint NOT NULL,
    sha256 bytea NOT NULL,
    actor text NOT NULL,
    binding jsonb NOT NULL,
    CONSTRAINT bindings_actor_check CHECK ((length(actor) > 0)),
    CONSTRAINT bindings_length_check CHECK ((length > 0)),
    CONSTRAINT bindings_sha256_check CHECK ((octet_length(sha256) = 32))
);

ALTER TABLE ONLY mdm_content.bindings FORCE ROW LEVEL SECURITY;

ALTER TABLE ONLY mdm_content.bindings
    ADD CONSTRAINT bindings_pkey PRIMARY KEY (tenant_id, actor, operation);

ALTER TABLE mdm_content.bindings ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant ON mdm_content.bindings USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));
CREATE TABLE mdm_content.uploads (
 tenant_id uuid NOT NULL, id uuid NOT NULL, document jsonb NOT NULL,
 epoch uuid, held_until bigint NOT NULL DEFAULT 0, expires bigint NOT NULL,
 reserved bigint NOT NULL CHECK(reserved>0), complete boolean NOT NULL,
 PRIMARY KEY(tenant_id,id)
);
CREATE TABLE mdm_content.objects (
 tenant_id uuid NOT NULL, generation uuid NOT NULL, id uuid NOT NULL, owner uuid NOT NULL,
 content jsonb NOT NULL, location jsonb NOT NULL,
 expires bigint NOT NULL, state text NOT NULL CHECK(state IN ('pending','ready','deleting','deleted')),
 PRIMARY KEY(tenant_id,generation,id)
);
CREATE TABLE mdm_content.manifests (
 tenant_id uuid NOT NULL, class text NOT NULL, sha256 bytea NOT NULL CHECK(octet_length(sha256)=32),
 length bigint NOT NULL CHECK(length>0), document jsonb NOT NULL, expires bigint NOT NULL,
 state text NOT NULL CHECK(state IN ('ready','deleting','deleted')),
 PRIMARY KEY(tenant_id,class,sha256,length)
);
CREATE TABLE mdm_content.pins (
 tenant_id uuid NOT NULL, id uuid NOT NULL, class text NOT NULL, sha256 bytea NOT NULL,
 length bigint NOT NULL, expires bigint NOT NULL, reserved bigint NOT NULL CHECK(reserved>=0),
 PRIMARY KEY(tenant_id,id)
);
CREATE TABLE mdm_content.settings (
 tenant_id uuid NOT NULL, protection text NOT NULL, active_generation uuid NOT NULL,
 revision bigint NOT NULL DEFAULT 1 CHECK(revision>0),
 maintenance text NOT NULL DEFAULT 'normal' CHECK(maintenance IN ('normal','frozen','switching')),
 operation uuid, PRIMARY KEY(tenant_id)
);
CREATE TABLE mdm_content.generations (
 tenant_id uuid NOT NULL, id uuid NOT NULL, descriptor jsonb NOT NULL, marker jsonb,
 PRIMARY KEY(tenant_id,id)
);
ALTER TABLE mdm_content.generations ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_content.generations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_content.generations USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
ALTER TABLE mdm_content.objects ADD FOREIGN KEY(tenant_id,generation) REFERENCES mdm_content.generations(tenant_id,id);
ALTER TABLE mdm_content.settings ADD FOREIGN KEY(tenant_id,active_generation) REFERENCES mdm_content.generations(tenant_id,id);
CREATE TABLE mdm_content.migrations (
 tenant_id uuid NOT NULL, operation_id uuid NOT NULL, source_generation uuid NOT NULL,
 target_generation uuid NOT NULL, expected_revision bigint NOT NULL CHECK(expected_revision>0),
 target_revision bigint NOT NULL CHECK(target_revision>0), request jsonb NOT NULL,
 phase text NOT NULL CHECK(phase IN ('requested','preparing','ready','committed','cancelled')),
 blocked_reason text, observed_at bigint, created_at timestamptz NOT NULL DEFAULT clock_timestamp(), PRIMARY KEY(tenant_id,operation_id), UNIQUE(tenant_id,target_generation)
);
CREATE UNIQUE INDEX one_storage_migration ON mdm_content.migrations(tenant_id) WHERE phase NOT IN ('committed','cancelled');
ALTER TABLE mdm_content.migrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_content.migrations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_content.migrations USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
ALTER TABLE mdm_content.uploads ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_content.uploads FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_content.uploads USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
ALTER TABLE mdm_content.objects ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_content.objects FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_content.objects USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
ALTER TABLE mdm_content.manifests ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_content.manifests FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_content.manifests USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
ALTER TABLE mdm_content.pins ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_content.pins FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_content.pins USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
ALTER TABLE mdm_content.settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_content.settings FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_content.settings USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
COMMIT;
