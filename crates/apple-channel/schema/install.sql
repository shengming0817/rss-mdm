-- Fresh installation: apple-channel owns these objects.
BEGIN;
SET LOCAL check_function_bodies = false;

CREATE SCHEMA mdm_apple;

CREATE TABLE mdm_apple.attempts (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    registration uuid NOT NULL,
    generation bigint NOT NULL,
    operation uuid,
    collection uuid,
    certificate uuid,
    phase text NOT NULL,
    request bytea NOT NULL,
    state text NOT NULL,
    response bytea,
    response_digest bytea,
    received_at bigint,
    next_attempt timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    deadline timestamp with time zone NOT NULL,
    collection_sequence bigint,
    CONSTRAINT attempts_check CHECK ((((phase = 'collect'::text) AND (collection IS NOT NULL) AND (operation IS NULL) AND (certificate IS NULL)) OR ((phase = ANY (ARRAY['execute'::text, 'observe'::text])) AND (operation IS NOT NULL) AND (collection IS NULL) AND (certificate IS NULL)) OR ((phase = 'renew'::text) AND (certificate IS NOT NULL) AND (collection IS NULL) AND (operation IS NULL)))),
    CONSTRAINT attempts_check1 CHECK (((response IS NULL) = (response_digest IS NULL))),
    CONSTRAINT attempts_collection_sequence_check CHECK ((((phase = 'collect'::text) = (collection_sequence IS NOT NULL)) AND ((collection_sequence IS NULL) OR (collection_sequence > 0)))),
    CONSTRAINT attempts_generation_check CHECK ((generation > 0)),
    CONSTRAINT attempts_phase_check CHECK ((phase = ANY (ARRAY['collect'::text, 'execute'::text, 'observe'::text, 'renew'::text]))),
    CONSTRAINT attempts_request_check CHECK (((octet_length(request) >= 1) AND (octet_length(request) <= 1048576))),
    CONSTRAINT attempts_response_check CHECK ((octet_length(response) <= 1048576)),
    CONSTRAINT attempts_response_digest_check CHECK ((octet_length(response_digest) = 32)),
    CONSTRAINT attempts_state_check CHECK ((state = ANY (ARRAY['pending'::text, 'sent'::text, 'not_now'::text, 'acknowledged'::text, 'error'::text, 'superseded'::text])))
);

ALTER TABLE ONLY mdm_apple.attempts FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_apple.devices (
    tenant_id uuid NOT NULL,
    registration uuid NOT NULL,
    udid text NOT NULL,
    state text NOT NULL,
    token bytea,
    magic text,
    token_revision bigint DEFAULT 0 NOT NULL,
    push_id uuid,
    push_lease_until timestamp with time zone,
    next_push timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    push_configuration bytea,
    push_failures integer DEFAULT 0 NOT NULL,
    identity_health smallint DEFAULT 0 NOT NULL,
    push_status integer,
    push_outcome text,
    CONSTRAINT devices_check CHECK (((state <> 'active'::text) OR ((token IS NOT NULL) AND (magic IS NOT NULL)))),
    CONSTRAINT devices_identity_health_check CHECK (((identity_health >= 0) AND (identity_health <= 2))),
    CONSTRAINT devices_magic_check CHECK (((length(magic) >= 1) AND (length(magic) <= 1024))),
    CONSTRAINT devices_push_configuration_check CHECK ((octet_length(push_configuration) = 32)),
    CONSTRAINT devices_push_failures_check CHECK (((push_failures >= 0) AND (push_failures <= 6))),
    CONSTRAINT devices_push_outcome_check CHECK ((push_outcome = ANY (ARRAY['accepted'::text, 'retryable'::text, 'unregistered'::text, 'rejected'::text]))),
    CONSTRAINT devices_state_check CHECK ((state = ANY (ARRAY['pending_token'::text, 'active'::text, 'retired'::text]))),
    CONSTRAINT devices_token_check CHECK (((octet_length(token) >= 1) AND (octet_length(token) <= 512))),
    CONSTRAINT devices_token_revision_check CHECK ((token_revision >= 0)),
    CONSTRAINT devices_udid_check CHECK (((length(udid) >= 1) AND (length(udid) <= 255)))
);

ALTER TABLE ONLY mdm_apple.devices FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_apple.scep_attempts (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    enrollment uuid NOT NULL,
    password_version bigint NOT NULL,
    configuration bytea NOT NULL,
    state text NOT NULL,
    transaction_id text,
    csr_digest bytea,
    spki bytea,
    issuer bytea NOT NULL,
    serial bytea,
    fingerprint bytea,
    certificate bytea,
    registration uuid,
    expires_at timestamp with time zone NOT NULL,
    renewal_of uuid,
    generation bigint,
    challenge_hash bytea,
    not_before bigint,
    not_after bigint,
    CONSTRAINT scep_attempts_certificate_check CHECK ((octet_length(certificate) <= 32768)),
    CONSTRAINT scep_attempts_challenge_hash_check CHECK ((octet_length(challenge_hash) = 32)),
    CONSTRAINT scep_attempts_check CHECK ((((renewal_of IS NULL) AND (generation IS NULL) AND (challenge_hash IS NULL)) OR ((renewal_of IS NOT NULL) AND (registration IS NOT NULL) AND (generation IS NOT NULL) AND (challenge_hash IS NOT NULL)))),
    CONSTRAINT scep_attempts_check1 CHECK ((((not_before IS NULL) AND (not_after IS NULL)) OR ((not_before > 0) AND (not_after > not_before)))),
    CONSTRAINT scep_attempts_check2 CHECK ((((state = 'prepared'::text) AND (transaction_id IS NULL) AND (csr_digest IS NULL) AND (spki IS NULL)) OR (state = 'superseded'::text) OR ((transaction_id IS NOT NULL) AND (csr_digest IS NOT NULL) AND (spki IS NOT NULL)))),
    CONSTRAINT scep_attempts_check3 CHECK ((((fingerprint IS NULL) AND (serial IS NULL) AND (certificate IS NULL)) OR ((fingerprint IS NOT NULL) AND (serial IS NOT NULL) AND (certificate IS NOT NULL)))),
    CONSTRAINT scep_attempts_check4 CHECK (((state <> 'bound'::text) OR (registration IS NOT NULL))),
    CONSTRAINT scep_attempts_configuration_check CHECK ((octet_length(configuration) = 32)),
    CONSTRAINT scep_attempts_csr_digest_check CHECK ((octet_length(csr_digest) = 32)),
    CONSTRAINT scep_attempts_fingerprint_check CHECK ((octet_length(fingerprint) = 32)),
    CONSTRAINT scep_attempts_generation_check CHECK ((generation > 0)),
    CONSTRAINT scep_attempts_issuer_check CHECK ((octet_length(issuer) = 32)),
    CONSTRAINT scep_attempts_password_version_check CHECK ((password_version > 0)),
    CONSTRAINT scep_attempts_spki_check CHECK ((octet_length(spki) = 32)),
    CONSTRAINT scep_attempts_state_check CHECK ((state = ANY (ARRAY['prepared'::text, 'consumed'::text, 'bound'::text, 'superseded'::text]))),
    CONSTRAINT scep_attempts_transaction_id_check CHECK (((length(transaction_id) >= 1) AND (length(transaction_id) <= 255)))
);

ALTER TABLE ONLY mdm_apple.scep_attempts FORCE ROW LEVEL SECURITY;

ALTER TABLE ONLY mdm_apple.attempts
    ADD CONSTRAINT attempts_pkey PRIMARY KEY (tenant_id, id);

ALTER TABLE ONLY mdm_apple.attempts
    ADD CONSTRAINT attempts_tenant_id_certificate_key UNIQUE (tenant_id, certificate);

ALTER TABLE ONLY mdm_apple.attempts
    ADD CONSTRAINT attempts_tenant_id_collection_key UNIQUE (tenant_id, collection);

ALTER TABLE ONLY mdm_apple.attempts
    ADD CONSTRAINT attempts_tenant_id_operation_phase_key UNIQUE (tenant_id, operation, phase);

ALTER TABLE ONLY mdm_apple.devices
    ADD CONSTRAINT devices_pkey PRIMARY KEY (tenant_id, registration);

ALTER TABLE ONLY mdm_apple.scep_attempts
    ADD CONSTRAINT scep_attempts_pkey PRIMARY KEY (tenant_id, id);

ALTER TABLE ONLY mdm_apple.scep_attempts
    ADD CONSTRAINT scep_attempts_tenant_id_enrollment_password_version_key UNIQUE (tenant_id, enrollment, password_version);

ALTER TABLE ONLY mdm_apple.scep_attempts
    ADD CONSTRAINT scep_attempts_tenant_id_fingerprint_key UNIQUE (tenant_id, fingerprint);

ALTER TABLE ONLY mdm_apple.scep_attempts
    ADD CONSTRAINT scep_attempts_tenant_id_issuer_serial_key UNIQUE (tenant_id, issuer, serial);

CREATE UNIQUE INDEX apple_active_udid ON mdm_apple.devices USING btree (tenant_id, udid) WHERE (state <> 'retired'::text);

CREATE INDEX apple_attempt_delivery ON mdm_apple.attempts USING btree (tenant_id, registration, next_attempt, id) WHERE (state = ANY (ARRAY['pending'::text, 'sent'::text, 'not_now'::text]));

CREATE UNIQUE INDEX scep_live_key ON mdm_apple.scep_attempts USING btree (tenant_id, spki) WHERE (state = ANY (ARRAY['consumed'::text, 'bound'::text]));

CREATE UNIQUE INDEX scep_one_renewal ON mdm_apple.scep_attempts USING btree (tenant_id, renewal_of) WHERE ((renewal_of IS NOT NULL) AND (state = ANY (ARRAY['prepared'::text, 'consumed'::text])));

CREATE INDEX scep_renewal_due ON mdm_apple.scep_attempts USING btree (tenant_id, not_after, id) WHERE (state = 'bound'::text);

CREATE UNIQUE INDEX scep_transaction ON mdm_apple.scep_attempts USING btree (tenant_id, transaction_id) WHERE (transaction_id IS NOT NULL);

ALTER TABLE mdm_apple.attempts ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_apple.devices ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_apple.scep_attempts ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant ON mdm_apple.attempts USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_apple.devices USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_apple.scep_attempts USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));
COMMIT;
