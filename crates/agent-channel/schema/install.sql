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
    execution_context jsonb NOT NULL,
    CONSTRAINT agent_execution_context CHECK (jsonb_typeof(execution_context)='object' AND (execution_context->>'revision')::bigint>0 AND octet_length(execution_context::text)<=8192),
    CONSTRAINT agent_binding_profile CHECK (wire_version=5 AND capabilities ~ '^\["inventory\.collect\.v5"(,"task\.execute\.v5")?(,"software\.msi\.system\.v5")?(,"software\.msi\.user\.v5")?(,"software\.pkg\.system\.v5")?(,"software\.bundle\.windows\.system\.v5")?(,"software\.bundle\.windows\.user\.v5")?(,"software\.bundle\.macos\.system\.v5")?(,"software\.bundle\.macos\.user\.v5")?(,"software\.winget\.system\.v5")?(,"software\.winget\.user\.v5")?(,"software\.brew\.bottle\.user\.v5")?(,"software\.exe\.system\.v5")?(,"software\.exe\.user\.v5")?(,"software\.dmg\.app\.system\.v5")?(,"software\.dmg\.app\.user\.v5")?(,"software\.dmg\.pkg\.system\.v5")?(,"software\.msix\.registration\.user\.v5")?(,"software\.msix\.provisioning\.system\.v5")?(,"mdm\.enrollment\.v5")?\]$'),
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
