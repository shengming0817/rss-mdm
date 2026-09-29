-- Fresh installation: agent-channel owns these objects.
BEGIN;
SET LOCAL check_function_bodies = false;

CREATE SCHEMA mdm_agent;

CREATE TABLE mdm_agent.bindings (
    tenant_id uuid NOT NULL,
    registration uuid NOT NULL,
    wire_version smallint NOT NULL,
    capabilities text NOT NULL,
    platform text NOT NULL,
    architecture text NOT NULL,
    CONSTRAINT agent_binding_profile CHECK (((wire_version = 4) AND (capabilities = ANY (ARRAY['["inventory.basic.v4"]'::text, '["inventory.basic.v4","task.execute.v4"]'::text, '["inventory.basic.v4","software.execute.v4"]'::text, '["inventory.basic.v4","task.execute.v4","software.execute.v4"]'::text, '["inventory.basic.v4","mdm.enrollment.v4"]'::text, '["inventory.basic.v4","task.execute.v4","mdm.enrollment.v4"]'::text, '["inventory.basic.v4","software.execute.v4","mdm.enrollment.v4"]'::text, '["inventory.basic.v4","task.execute.v4","software.execute.v4","mdm.enrollment.v4"]'::text])))),
    CONSTRAINT agent_bindings_architecture_check CHECK ((architecture = ANY (ARRAY['x86_64'::text, 'aarch64'::text]))),
    CONSTRAINT agent_bindings_platform_check CHECK ((platform = ANY (ARRAY['windows'::text, 'macos'::text])))
);

ALTER TABLE ONLY mdm_agent.bindings FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_agent.operations (
    tenant_id uuid NOT NULL,
    actor text NOT NULL,
    instance text NOT NULL,
    operation_id uuid NOT NULL,
    digest text NOT NULL,
    result text NOT NULL,
    CONSTRAINT operations_digest_check CHECK ((length(digest) = 64)),
    CONSTRAINT operations_result_check CHECK ((length(result) <= 2048))
);

ALTER TABLE ONLY mdm_agent.operations FORCE ROW LEVEL SECURITY;

ALTER TABLE ONLY mdm_agent.bindings
    ADD CONSTRAINT agent_bindings_pkey PRIMARY KEY (tenant_id, registration);

ALTER TABLE ONLY mdm_agent.operations
    ADD CONSTRAINT operations_pkey PRIMARY KEY (tenant_id, actor, operation_id);

ALTER TABLE mdm_agent.bindings ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_agent.operations ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant ON mdm_agent.bindings USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_agent.operations USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));
COMMIT;
