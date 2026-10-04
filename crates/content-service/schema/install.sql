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
COMMIT;
