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
CREATE TABLE mdm_content.diagnostic_artifacts (
 tenant_id uuid NOT NULL, operation uuid NOT NULL, registration uuid NOT NULL,
 generation bigint NOT NULL CHECK(generation>0), identity jsonb NOT NULL,
 reference text NOT NULL, length bigint NOT NULL CHECK(length BETWEEN 1 AND 16777216),
 sha256 bytea NOT NULL CHECK(octet_length(sha256)=32), expires_at bigint NOT NULL CHECK(expires_at>0),
 PRIMARY KEY(tenant_id,operation), UNIQUE(tenant_id,reference)
);
ALTER TABLE mdm_content.diagnostic_artifacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_content.diagnostic_artifacts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_content.diagnostic_artifacts USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
CREATE TABLE mdm_content.uploads (
 tenant_id uuid NOT NULL, id uuid NOT NULL, document jsonb NOT NULL,
 epoch uuid, held_until bigint NOT NULL DEFAULT 0, expires bigint NOT NULL,
 reserved bigint NOT NULL CHECK(reserved>0), complete boolean NOT NULL,
 PRIMARY KEY(tenant_id,id)
);
CREATE TABLE mdm_content.objects (
 tenant_id uuid NOT NULL, id uuid NOT NULL, owner uuid NOT NULL,
 content jsonb NOT NULL, intent jsonb NOT NULL, coordinate jsonb,
 expires bigint NOT NULL, state text NOT NULL CHECK(state IN ('pending','ready','deleting','deleted')),
 PRIMARY KEY(tenant_id,id)
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
 tenant_id uuid NOT NULL, identity jsonb NOT NULL, PRIMARY KEY(tenant_id)
);
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
