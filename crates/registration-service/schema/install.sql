-- Fresh installation: registration-service owns these objects.
BEGIN;
SET LOCAL check_function_bodies = false;

CREATE SCHEMA mdm_access;

CREATE FUNCTION mdm_access.capture_asset_authority() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'mdm_access'
    AS $$
DECLARE r jsonb; d jsonb; previous jsonb; k text; i text; dev text; reg uuid; v bigint; t uuid;
BEGIN
 IF TG_OP='DELETE' THEN r=to_jsonb(OLD); ELSE r=to_jsonb(NEW); END IF;
 IF TG_OP='UPDATE' THEN previous=to_jsonb(OLD); END IF;
 t=(r->>'tenant_id')::uuid;
 CASE TG_TABLE_NAME
 WHEN 'devices' THEN
  k='device'; i=r->>'id'; dev=i; d=jsonb_build_object('id',i);
 WHEN 'registrations' THEN
  k='registration'; i=r->>'id'; reg=i::uuid; dev=r->>'device';
  d=jsonb_build_object('id',i,'device',dev,'channel',r->>'channel','generation',r->'generation','state',r->>'state');
 WHEN 'report_sources' THEN
  k='source'; reg=(r->>'registration')::uuid;
  i=jsonb_build_array(r->>'registration',r->>'source')::text;
  d=jsonb_build_object('registration',reg,'source',r->>'source','epoch',r->>'epoch','coverage',r->>'coverage','enabled',r->'enabled');
  -- Collection sequence/command allocation is not an asset change.
  IF previous IS NOT NULL AND d=jsonb_build_object('registration',(previous->>'registration')::uuid,'source',previous->>'source','epoch',previous->>'epoch','coverage',previous->>'coverage','enabled',previous->'enabled') THEN RETURN NULL; END IF;
 WHEN 'credentials' THEN
  k='credential'; i=r->>'id'; reg=(r->>'registration')::uuid;
  -- Credential locators and secrets never enter asset history.
  d=jsonb_build_object('id',i,'registration',reg,'channel',r->>'channel','state',r->>'state');
 ELSE RAISE EXCEPTION 'unexpected asset authority';
 END CASE;
 IF TG_OP='UPDATE' AND NEW IS NOT DISTINCT FROM OLD THEN RETURN NULL; END IF;
 IF dev IS NULL THEN SELECT device INTO dev FROM mdm_access.registrations WHERE tenant_id=t AND id=reg; END IF;
 v=mdm.record_asset_change(t,k,jsonb_build_object('device',dev,'registration',reg,'identity',i),ARRAY[]::text[]);
 IF TG_OP='DELETE' THEN d=NULL; END IF;
 INSERT INTO mdm_access.asset_authority_history VALUES(t,k,i,dev,reg,v,d);
 RETURN NULL;
END $$;

CREATE TABLE mdm_access.asset_authority_history (
    tenant_id uuid NOT NULL,
    kind text NOT NULL,
    identity text NOT NULL,
    device text,
    registration uuid,
    revision bigint NOT NULL,
    document jsonb,
    CONSTRAINT asset_authority_history_document_check CHECK (((document IS NULL) OR (octet_length((document)::text) <= 16384))),
    CONSTRAINT asset_authority_history_identity_check CHECK (((octet_length(identity) >= 1) AND (octet_length(identity) <= 1024))),
    CONSTRAINT asset_authority_history_kind_check CHECK ((kind = ANY (ARRAY['device'::text, 'registration'::text, 'source'::text, 'credential'::text])))
);

ALTER TABLE ONLY mdm_access.asset_authority_history FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_access.credentials (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    registration uuid NOT NULL,
    channel text NOT NULL,
    locator text NOT NULL,
    state text NOT NULL,
    CONSTRAINT credentials_channel_check CHECK ((channel = ANY (ARRAY['agent'::text, 'mdm'::text]))),
    CONSTRAINT credentials_locator_check CHECK ((locator ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT credentials_state_check CHECK ((state = ANY (ARRAY['active'::text, 'superseded'::text, 'revoked'::text])))
);

ALTER TABLE ONLY mdm_access.credentials FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_access.devices (
    tenant_id uuid NOT NULL,
    id text NOT NULL,
    CONSTRAINT devices_id_check CHECK ((((octet_length(id) >= 1) AND (octet_length(id) <= 256)) AND (id !~ '[[:cntrl:]]'::text)))
);

ALTER TABLE ONLY mdm_access.devices FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_access.grants (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    actor text NOT NULL,
    instance text NOT NULL,
    device text NOT NULL,
    purpose text NOT NULL,
    state text NOT NULL,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    CONSTRAINT grants_actor_check CHECK (((length(actor) >= 1) AND (length(actor) <= 255))),
    CONSTRAINT grants_check CHECK (((expires_at > created_at) AND (expires_at <= (created_at + '00:05:00'::interval)))),
    CONSTRAINT grants_client_check CHECK (((length(instance) >= 1) AND (length(instance) <= 255))),
    CONSTRAINT grants_device_check CHECK ((((octet_length(device) >= 1) AND (octet_length(device) <= 256)) AND (device !~ '[[:cntrl:]]'::text))),
    CONSTRAINT grants_purpose_check CHECK ((purpose = 'enrollment'::text)),
    CONSTRAINT grants_state_check CHECK ((state = ANY (ARRAY['available'::text, 'consumed'::text, 'revoked'::text])))
);

ALTER TABLE ONLY mdm_access.grants FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_access.registration_operations (
    tenant_id uuid NOT NULL,
    actor text NOT NULL,
    instance text NOT NULL,
    operation_id uuid NOT NULL,
    digest text NOT NULL,
    result text NOT NULL,
    CONSTRAINT operations_digest_check CHECK ((length(digest) = 64)),
    CONSTRAINT operations_result_check CHECK ((length(result) <= 2048))
);

ALTER TABLE ONLY mdm_access.registration_operations FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_access.registrations (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    device text NOT NULL,
    channel text NOT NULL,
    generation bigint NOT NULL,
    request_id uuid NOT NULL,
    state text NOT NULL,
    CONSTRAINT registrations_channel_check CHECK ((channel = ANY (ARRAY['agent'::text, 'mdm'::text]))),
    CONSTRAINT registrations_generation_check CHECK ((generation > 0)),
    CONSTRAINT registrations_state_check CHECK ((state = ANY (ARRAY['active'::text, 'superseded'::text, 'revoked'::text])))
);

ALTER TABLE ONLY mdm_access.registrations FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_access.report_sources (
    tenant_id uuid NOT NULL,
    registration uuid NOT NULL,
    source text NOT NULL,
    epoch uuid NOT NULL,
    coverage text NOT NULL,
    enabled boolean NOT NULL,
    next_command bigint DEFAULT 1024 NOT NULL,
    next_sequence bigint DEFAULT 0 NOT NULL,
    CONSTRAINT report_sources_next_command_check CHECK (((next_command >= 1024) AND (next_command <= '4294967296'::bigint))),
    CONSTRAINT report_sources_next_sequence_check CHECK ((next_sequence >= 0)),
    CONSTRAINT report_sources_source_check CHECK (((length(source) >= 1) AND (length(source) <= 255)))
);

ALTER TABLE ONLY mdm_access.report_sources FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_access.requests (
    authority_kind text NOT NULL DEFAULT 'password' CHECK(authority_kind IN('password','managed_installation')),
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    grant_id uuid NOT NULL,
    state text DEFAULT 'cancelled'::text NOT NULL,
    expected_generation bigint,
    password_digest text,
    password_version bigint DEFAULT 0 NOT NULL,
    credential_ref uuid,
    expires_at timestamp with time zone,
    issuance_operation uuid,
    source text NOT NULL,
    CONSTRAINT enrollment_shape CHECK ((state = 'cancelled') OR (expected_generation IS NOT NULL AND expires_at IS NOT NULL AND issuance_operation IS NOT NULL AND ((authority_kind='password' AND password_digest IS NOT NULL AND password_version>0 AND credential_ref IS NOT NULL) OR (authority_kind='managed_installation' AND source='agent.builtin' AND expected_generation=0 AND password_digest IS NULL AND password_version=0 AND credential_ref IS NULL)))),
    CONSTRAINT requests_expected_generation_check CHECK ((expected_generation >= 0)),
    CONSTRAINT requests_password_digest_check CHECK ((password_digest ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT requests_password_version_check CHECK ((password_version >= 0)),
    CONSTRAINT requests_source_check CHECK ((source = ANY (ARRAY['agent.builtin'::text, 'mdm.windows'::text, 'mdm.apple'::text]))),
    CONSTRAINT requests_state_check CHECK ((state = ANY (ARRAY['pending'::text, 'bound'::text, 'cancelled'::text])))
);

CREATE UNIQUE INDEX managed_installation_enrollment ON mdm_access.requests(tenant_id,issuance_operation) WHERE authority_kind='managed_installation';

ALTER TABLE ONLY mdm_access.requests FORCE ROW LEVEL SECURITY;

ALTER TABLE ONLY mdm_access.asset_authority_history
    ADD CONSTRAINT asset_authority_history_pkey PRIMARY KEY (tenant_id, kind, identity, revision);

ALTER TABLE ONLY mdm_access.credentials
    ADD CONSTRAINT credentials_pkey PRIMARY KEY (tenant_id, id);

ALTER TABLE ONLY mdm_access.credentials
    ADD CONSTRAINT credentials_tenant_id_channel_locator_key UNIQUE (tenant_id, channel, locator);

ALTER TABLE ONLY mdm_access.devices
    ADD CONSTRAINT devices_pkey PRIMARY KEY (tenant_id, id);

ALTER TABLE ONLY mdm_access.requests
    ADD CONSTRAINT enrollment_issuance_operation UNIQUE (tenant_id, issuance_operation);

ALTER TABLE ONLY mdm_access.grants
    ADD CONSTRAINT grants_pkey PRIMARY KEY (tenant_id, id);

ALTER TABLE ONLY mdm_access.registration_operations
    ADD CONSTRAINT operations_pkey PRIMARY KEY (tenant_id, actor, operation_id);

ALTER TABLE ONLY mdm_access.registrations
    ADD CONSTRAINT registrations_pkey PRIMARY KEY (tenant_id, id);

ALTER TABLE ONLY mdm_access.registrations
    ADD CONSTRAINT registrations_tenant_id_device_channel_generation_key UNIQUE (tenant_id, device, channel, generation);

ALTER TABLE ONLY mdm_access.registrations
    ADD CONSTRAINT registrations_tenant_id_id_channel_key UNIQUE (tenant_id, id, channel);

ALTER TABLE ONLY mdm_access.registrations
    ADD CONSTRAINT registrations_tenant_id_request_id_key UNIQUE (tenant_id, request_id);

ALTER TABLE ONLY mdm_access.report_sources
    ADD CONSTRAINT report_sources_pkey PRIMARY KEY (tenant_id, registration, source);

ALTER TABLE ONLY mdm_access.requests
    ADD CONSTRAINT requests_pkey PRIMARY KEY (tenant_id, id);

ALTER TABLE ONLY mdm_access.requests
    ADD CONSTRAINT requests_tenant_id_grant_id_key UNIQUE (tenant_id, grant_id);

CREATE INDEX asset_authority_by_device ON mdm_access.asset_authority_history USING btree (tenant_id, device, kind, identity, revision);

CREATE INDEX asset_authority_by_registration ON mdm_access.asset_authority_history USING btree (tenant_id, registration, kind, identity, revision);

CREATE INDEX asset_authority_changes ON mdm_access.asset_authority_history USING btree (tenant_id, revision, device);

CREATE INDEX asset_authority_device_watermark ON mdm_access.asset_authority_history USING btree (tenant_id, device, revision DESC);

CREATE UNIQUE INDEX one_active_credential ON mdm_access.credentials USING btree (tenant_id, registration) WHERE (state = 'active'::text);

CREATE UNIQUE INDEX one_active_registration ON mdm_access.registrations USING btree (tenant_id, device, channel) WHERE (state = 'active'::text);

CREATE INDEX registration_control_page ON mdm_access.registrations USING btree (tenant_id, device, id);

ALTER TABLE mdm_access.asset_authority_history ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_access.credentials ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_access.devices ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_access.grants ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_access.registration_operations ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_access.registrations ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_access.report_sources ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_access.requests ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant ON mdm_access.asset_authority_history USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_access.credentials USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_access.devices USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_access.grants USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_access.registration_operations USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_access.registrations USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_access.report_sources USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_access.requests USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));
COMMIT;
