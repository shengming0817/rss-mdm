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
    CONSTRAINT agent_binding_profile CHECK (wire_version=1 AND capabilities ~ '^\["inventory\.collect\.v1"(,"task\.execute\.v1")?(,"software\.msi\.system\.v1")?(,"software\.msi\.user\.v1")?(,"software\.pkg\.system\.v1")?(,"software\.bundle\.windows\.system\.v1")?(,"software\.bundle\.windows\.user\.v1")?(,"software\.bundle\.macos\.system\.v1")?(,"software\.bundle\.macos\.user\.v1")?(,"software\.winget\.system\.v1")?(,"software\.winget\.user\.v1")?(,"software\.brew\.bottle\.user\.v1")?(,"software\.exe\.system\.v1")?(,"software\.exe\.user\.v1")?(,"software\.dmg\.app\.system\.v1")?(,"software\.dmg\.app\.user\.v1")?(,"software\.dmg\.pkg\.system\.v1")?(,"software\.msix\.registration\.user\.v1")?(,"software\.msix\.provisioning\.system\.v1")?(,"mdm\.enrollment\.v1")?(,"device\.unmanage\.v1")?(,"inventory\.native\.v1")?(,"credentials\.windows\.v1")?(,"telemetry\.collect\.v1")?\]$'),
    CONSTRAINT agent_bindings_architecture_check CHECK ((architecture = ANY (ARRAY['x86_64'::text, 'aarch64'::text]))),
    CONSTRAINT agent_bindings_platform_check CHECK ((platform = ANY (ARRAY['windows'::text, 'macos'::text])))
);

ALTER TABLE ONLY mdm_agent.bindings FORCE ROW LEVEL SECURITY;

ALTER TABLE ONLY mdm_agent.bindings
    ADD CONSTRAINT agent_bindings_pkey PRIMARY KEY (tenant_id, registration);

ALTER TABLE mdm_agent.bindings ENABLE ROW LEVEL SECURITY;


CREATE POLICY tenant ON mdm_agent.bindings USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

COMMIT;
