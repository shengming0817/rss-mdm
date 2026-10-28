-- Resource application receipts, installed by the privileged host.
BEGIN;
CREATE SCHEMA mdm_resource_catalog;
CREATE TABLE mdm_resource_catalog.operations (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    fingerprint bytea NOT NULL,
    response jsonb NOT NULL,
    actor text NOT NULL,
    CONSTRAINT operations_actor_check CHECK ((length(actor) > 0)),
    CONSTRAINT operations_fingerprint_check CHECK ((octet_length(fingerprint) = 32)),
    CONSTRAINT operations_response_check CHECK ((octet_length((response)::text) <= 8388608))
);
ALTER TABLE ONLY mdm_resource_catalog.operations FORCE ROW LEVEL SECURITY;
ALTER TABLE ONLY mdm_resource_catalog.operations
    ADD CONSTRAINT operations_pkey PRIMARY KEY (tenant_id, actor, id);
ALTER TABLE mdm_resource_catalog.operations ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_resource_catalog.operations USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));
REVOKE ALL ON SCHEMA mdm_resource_catalog FROM PUBLIC;
REVOKE ALL ON mdm_resource_catalog.operations FROM PUBLIC;
GRANT USAGE ON SCHEMA mdm_resource_catalog TO mdm_resource_runtime;
GRANT SELECT,INSERT ON mdm_resource_catalog.operations TO mdm_resource_runtime;
COMMIT;
