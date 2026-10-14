-- Windows registration receipt identity; one shared writer implementation.
BEGIN;
CREATE TABLE mdm_windows.operations (
    tenant_id uuid NOT NULL,
    actor text NOT NULL,
    instance text NOT NULL,
    operation_id uuid NOT NULL,
    digest text NOT NULL,
    result text NOT NULL,
    CONSTRAINT operations_digest_check CHECK ((length(digest) = 64)),
    CONSTRAINT operations_result_check CHECK ((length(result) <= 2048))
);

ALTER TABLE ONLY mdm_windows.operations FORCE ROW LEVEL SECURITY;

ALTER TABLE ONLY mdm_windows.operations
    ADD CONSTRAINT operations_pkey PRIMARY KEY (tenant_id, actor, operation_id);

ALTER TABLE mdm_windows.operations ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant ON mdm_windows.operations USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));
GRANT SELECT,INSERT ON TABLE mdm_windows.operations TO mdm_access;
COMMIT;
