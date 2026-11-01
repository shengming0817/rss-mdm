-- Group service owns these application tables; physical namespace is retained.
CREATE TABLE mdm_assets.group_fields (
    tenant_id uuid NOT NULL,
    group_id uuid NOT NULL,
    field text NOT NULL
);

ALTER TABLE ONLY mdm_assets.group_fields FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_assets.group_operations (
    tenant_id uuid NOT NULL,
    actor text NOT NULL,
    id uuid NOT NULL,
    fingerprint bytea NOT NULL,
    response jsonb NOT NULL,
    CONSTRAINT group_operations_fingerprint_check CHECK ((octet_length(fingerprint) = 32)),
    CONSTRAINT group_operations_response_check CHECK ((octet_length((response)::text) <= 8388608))
);

ALTER TABLE ONLY mdm_assets.group_operations FORCE ROW LEVEL SECURITY;

ALTER TABLE ONLY mdm_assets.group_fields
    ADD CONSTRAINT group_fields_pkey PRIMARY KEY (tenant_id, group_id, field);

ALTER TABLE ONLY mdm_assets.group_operations
    ADD CONSTRAINT group_operations_pkey PRIMARY KEY (tenant_id, actor, id);

CREATE INDEX group_fields_field ON mdm_assets.group_fields USING btree (tenant_id, field, group_id);

ALTER TABLE mdm_assets.group_fields ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_assets.group_operations ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant ON mdm_assets.group_fields USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_assets.group_operations USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));
