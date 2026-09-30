-- Fresh installation: windows-channel owns these objects.
BEGIN;
SET LOCAL check_function_bodies = false;

CREATE SCHEMA mdm_windows;

CREATE TABLE mdm_access.enrollment_certificates (
    tenant_id uuid NOT NULL,
    request_id uuid NOT NULL,
    certificate bytea NOT NULL,
    server_nonce bytea NOT NULL,
    CONSTRAINT enrollment_certificates_certificate_check CHECK (((octet_length(certificate) >= 1) AND (octet_length(certificate) <= 32768))),
    CONSTRAINT enrollment_certificates_server_nonce_check CHECK (((octet_length(server_nonce) >= 16) AND (octet_length(server_nonce) <= 64)))
);

ALTER TABLE ONLY mdm_access.enrollment_certificates FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_access.enrollment_intents (
    tenant_id uuid NOT NULL,
    request_id uuid NOT NULL,
    enrollment_type text NOT NULL,
    csr bytea NOT NULL,
    tbs bytea NOT NULL,
    issuer bytea NOT NULL,
    configuration text NOT NULL,
    registration uuid NOT NULL,
    credential uuid NOT NULL,
    epoch uuid NOT NULL,
    secrets bytea NOT NULL,
    CONSTRAINT enrollment_intents_configuration_check CHECK ((configuration ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT enrollment_intents_csr_check CHECK (((octet_length(csr) >= 1) AND (octet_length(csr) <= 32768))),
    CONSTRAINT enrollment_intents_enrollment_type_check CHECK ((enrollment_type = ANY (ARRAY['Full'::text, 'Device'::text]))),
    CONSTRAINT enrollment_intents_issuer_check CHECK (((octet_length(issuer) >= 1) AND (octet_length(issuer) <= 32768))),
    CONSTRAINT enrollment_intents_secrets_check CHECK (((octet_length(secrets) >= 28) AND (octet_length(secrets) <= 4096))),
    CONSTRAINT enrollment_intents_tbs_check CHECK (((octet_length(tbs) >= 1) AND (octet_length(tbs) <= 32768)))
);

ALTER TABLE ONLY mdm_access.enrollment_intents FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_access.management_messages (
    tenant_id uuid NOT NULL,
    registration uuid NOT NULL,
    session_id text NOT NULL,
    message_id bigint NOT NULL,
    digest text NOT NULL,
    response bytea NOT NULL,
    CONSTRAINT management_messages_digest_check CHECK ((digest ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT management_messages_response_check CHECK (((octet_length(response) >= 1) AND (octet_length(response) <= 262144)))
);

ALTER TABLE ONLY mdm_access.management_messages FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_access.management_sessions (
    tenant_id uuid NOT NULL,
    registration uuid NOT NULL,
    session_id text NOT NULL,
    generation bigint NOT NULL,
    credential uuid NOT NULL,
    state text NOT NULL,
    last_message bigint NOT NULL,
    client_authenticated boolean NOT NULL,
    correlation text NOT NULL,
    nonce bytea NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    run_id uuid,
    CONSTRAINT management_sessions_correlation_check CHECK ((octet_length(correlation) <= 32768)),
    CONSTRAINT management_sessions_last_message_check CHECK ((last_message > 0)),
    CONSTRAINT management_sessions_nonce_check CHECK (((octet_length(nonce) >= 16) AND (octet_length(nonce) <= 64))),
    CONSTRAINT management_sessions_session_id_check CHECK (((length(session_id) >= 1) AND (length(session_id) <= 128))),
    CONSTRAINT management_sessions_state_check CHECK ((state = ANY (ARRAY['challenge'::text, 'collecting'::text, 'complete'::text, 'superseded'::text])))
);

ALTER TABLE ONLY mdm_access.management_sessions FORCE ROW LEVEL SECURITY;

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

ALTER TABLE ONLY mdm_access.enrollment_certificates
    ADD CONSTRAINT enrollment_certificates_pkey PRIMARY KEY (tenant_id, request_id);

ALTER TABLE ONLY mdm_access.enrollment_intents
    ADD CONSTRAINT enrollment_intents_pkey PRIMARY KEY (tenant_id, request_id);

ALTER TABLE ONLY mdm_access.management_messages
    ADD CONSTRAINT management_messages_pkey PRIMARY KEY (tenant_id, registration, session_id, message_id);

ALTER TABLE ONLY mdm_access.management_sessions
    ADD CONSTRAINT management_sessions_pkey PRIMARY KEY (tenant_id, registration, session_id);

ALTER TABLE ONLY mdm_windows.operations
    ADD CONSTRAINT operations_pkey PRIMARY KEY (tenant_id, actor, operation_id);

CREATE INDEX management_retention ON mdm_access.management_sessions USING btree (tenant_id, expires_at, registration, session_id);

CREATE UNIQUE INDEX one_advancing_management_session ON mdm_access.management_sessions USING btree (tenant_id, registration) WHERE (state = ANY (ARRAY['challenge'::text, 'collecting'::text]));

ALTER TABLE mdm_access.enrollment_certificates ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_access.enrollment_intents ENABLE ROW LEVEL SECURITY;

CREATE POLICY expired_only ON mdm_access.management_messages AS RESTRICTIVE FOR DELETE USING ((EXISTS ( SELECT 1
   FROM mdm_access.management_sessions s
  WHERE ((s.tenant_id = management_messages.tenant_id) AND (s.registration = management_messages.registration) AND (s.session_id = management_messages.session_id) AND (s.expires_at < clock_timestamp())))));

CREATE POLICY expired_only ON mdm_access.management_sessions AS RESTRICTIVE FOR DELETE USING ((expires_at < clock_timestamp()));

ALTER TABLE mdm_access.management_messages ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_access.management_sessions ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant ON mdm_access.enrollment_certificates USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_access.enrollment_intents USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_access.management_messages USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_access.management_sessions USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

ALTER TABLE mdm_windows.operations ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant ON mdm_windows.operations USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));
CREATE TABLE mdm_windows.collections (
 tenant_id uuid NOT NULL,
 id uuid NOT NULL,
 registration uuid NOT NULL,
 session_id text NOT NULL,
 request_message bigint NOT NULL CHECK(request_message BETWEEN 1 AND 8),
 first_command bigint NOT NULL CHECK(first_command BETWEEN 1024 AND 4294967294),
 request bytea NOT NULL CHECK(octet_length(request) BETWEEN 1 AND 32768),
 channel_state jsonb CHECK(octet_length(channel_state::text)<=8192),
 PRIMARY KEY(tenant_id,id)
);
CREATE INDEX windows_collection_session ON mdm_windows.collections(tenant_id,registration,session_id,first_command,id);
ALTER TABLE mdm_windows.collections ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_windows.collections FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_windows.collections
 USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)
 WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
COMMIT;
