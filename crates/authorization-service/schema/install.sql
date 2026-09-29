-- Fresh installation: authorization-service owns these objects.
BEGIN;
SET LOCAL check_function_bodies = false;

CREATE TABLE mdm_access.authorization_initializations (
    tenant_id uuid NOT NULL,
    instance uuid NOT NULL,
    operation_id uuid NOT NULL,
    principal uuid NOT NULL,
    initialized_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL
);

ALTER TABLE ONLY mdm_access.authorization_initializations FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_access.authorization_operations (
    tenant_id uuid NOT NULL,
    actor text NOT NULL,
    instance uuid NOT NULL,
    operation_id uuid NOT NULL,
    digest text NOT NULL,
    result text NOT NULL,
    CONSTRAINT authorization_operations_digest_check CHECK ((length(digest) = 64)),
    CONSTRAINT authorization_operations_result_check CHECK ((length(result) <= 2048))
);

ALTER TABLE ONLY mdm_access.authorization_operations FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_access.authorization_rules (
    tenant_id uuid NOT NULL,
    instance uuid NOT NULL,
    id uuid NOT NULL,
    revision bigint NOT NULL,
    document jsonb,
    CONSTRAINT authorization_rules_document_check CHECK (((document IS NULL) OR ((jsonb_typeof(document) = 'object'::text) AND (octet_length((document)::text) <= 2097152)))),
    CONSTRAINT authorization_rules_revision_check CHECK ((revision > 0))
);

ALTER TABLE ONLY mdm_access.authorization_rules FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_access.user_groups (
    tenant_id uuid NOT NULL,
    instance uuid NOT NULL,
    id uuid NOT NULL,
    revision bigint NOT NULL,
    document jsonb,
    CONSTRAINT user_groups_document_check CHECK (((document IS NULL) OR ((jsonb_typeof(document) = 'object'::text) AND (octet_length((document)::text) <= 2097152)))),
    CONSTRAINT user_groups_revision_check CHECK ((revision > 0))
);

ALTER TABLE ONLY mdm_access.user_groups FORCE ROW LEVEL SECURITY;

ALTER TABLE ONLY mdm_access.authorization_initializations
    ADD CONSTRAINT authorization_initializations_pkey PRIMARY KEY (tenant_id, instance);

ALTER TABLE ONLY mdm_access.authorization_operations
    ADD CONSTRAINT authorization_operations_pkey PRIMARY KEY (tenant_id, actor, operation_id);

ALTER TABLE ONLY mdm_access.authorization_rules
    ADD CONSTRAINT authorization_rules_pkey PRIMARY KEY (tenant_id, instance, id);

ALTER TABLE ONLY mdm_access.user_groups
    ADD CONSTRAINT user_groups_pkey PRIMARY KEY (tenant_id, instance, id);

ALTER TABLE mdm_access.authorization_initializations ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_access.authorization_operations ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_access.authorization_rules ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant ON mdm_access.authorization_initializations USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_access.authorization_operations USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_access.authorization_rules USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_access.user_groups USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

ALTER TABLE mdm_access.user_groups ENABLE ROW LEVEL SECURITY;
COMMIT;
