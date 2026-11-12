-- Configuration storage is owned exclusively by Policy.
BEGIN;
CREATE SCHEMA mdm_planning;
CREATE TABLE mdm_planning.configuration_claims (
    tenant_id uuid NOT NULL,
    policy uuid NOT NULL,
    device uuid NOT NULL,
    version uuid NOT NULL,
    operation uuid,
    user_key text NOT NULL, platform text NOT NULL, object_kind text NOT NULL, object_key text NOT NULL
);

CREATE TABLE mdm_planning.configuration_devices (
    tenant_id uuid NOT NULL,
    device uuid NOT NULL,
    input_revision bigint DEFAULT 1 NOT NULL,
    observed_revision bigint DEFAULT 0 NOT NULL,
    CONSTRAINT configuration_devices_input_revision_check CHECK ((input_revision > 0)),
    CONSTRAINT configuration_devices_observed_revision_check CHECK ((observed_revision >= 0))
);

CREATE TABLE mdm_planning.configuration_objects (
    tenant_id uuid NOT NULL, device uuid NOT NULL, user_key text NOT NULL,
    platform text NOT NULL CHECK(platform IN ('windows','macos')),
    object_kind text NOT NULL CHECK(object_kind IN ('csp','mi','profile','payload','declaration')),
    object_key text NOT NULL CHECK(octet_length(object_key) BETWEEN 1 AND 2048),
    operation uuid, digest bytea CHECK(digest IS NULL OR octet_length(digest)=32),
    diagnosis text CHECK(diagnosis IN ('waiting_scope','waiting_registration','windows_declared_enrollment_not_ready','waiting_capability','not_applicable','configuration_conflict','native_group_conflict','removal_blocked_by_shared_unit','removing','unassigned')),
    PRIMARY KEY(tenant_id,device,user_key,platform,object_kind,object_key)
);

ALTER TABLE ONLY mdm_planning.configuration_claims FORCE ROW LEVEL SECURITY;

ALTER TABLE ONLY mdm_planning.configuration_devices FORCE ROW LEVEL SECURITY;

ALTER TABLE ONLY mdm_planning.configuration_objects FORCE ROW LEVEL SECURITY;

ALTER TABLE ONLY mdm_planning.configuration_claims
    ADD CONSTRAINT configuration_claims_pkey PRIMARY KEY (tenant_id, policy, device, user_key, platform, object_kind, object_key);

ALTER TABLE ONLY mdm_planning.configuration_devices
    ADD CONSTRAINT configuration_devices_pkey PRIMARY KEY (tenant_id, device);

ALTER TABLE mdm_planning.configuration_claims ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_planning.configuration_devices ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_planning.configuration_objects ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant ON mdm_planning.configuration_claims USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_planning.configuration_devices USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_planning.configuration_objects USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE FUNCTION mdm_planning.configuration_device_key(p_device uuid) RETURNS text
 LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE SET search_path TO 'pg_catalog'
 AS $$ SELECT encode(sha256(convert_to(p_device::text,'UTF8')),'hex') $$;
REVOKE ALL ON FUNCTION mdm_planning.configuration_device_key(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mdm_planning.configuration_device_key(uuid) TO mdm_access,mdm_policy_runtime,mdm_command_runtime;
CREATE INDEX configuration_device_recovery ON mdm_planning.configuration_devices(tenant_id,mdm_planning.configuration_device_key(device));
CREATE TABLE mdm_planning.configuration_operations (
    tenant_id uuid NOT NULL
  , id uuid NOT NULL
  , command_id text GENERATED ALWAYS AS (CAST(id AS text)) STORED
  , device uuid NOT NULL
  , request bytea NOT NULL CHECK (octet_length(request) BETWEEN 68 AND 33554500)
  , input_context jsonb NOT NULL CHECK (jsonb_typeof(input_context) = 'object'
                                    AND octet_length(CAST(input_context AS text)) <= 4096)
  , fingerprint bytea NOT NULL CHECK (octet_length(fingerprint) = 32)
  , generation bigint NOT NULL CHECK (generation > 0)
  , epoch bigint NOT NULL CHECK (epoch > 0)
  , authority jsonb NOT NULL CHECK (octet_length(CAST(authority AS text)) <= 1048576)
  , revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0)
  , observed_command_version bigint NOT NULL DEFAULT 1 CHECK (observed_command_version > 0)
  , dispatch_fingerprint bytea NOT NULL CHECK (octet_length(dispatch_fingerprint) = 32)
  , dispatch_failure jsonb CHECK (dispatch_failure IS NULL
                               OR (jsonb_typeof(dispatch_failure) = 'object'
                               AND octet_length(CAST(dispatch_failure AS text)) <= 8192))
  , gateway_accepted boolean NOT NULL DEFAULT FALSE
  , policy_version uuid NOT NULL
  , PRIMARY KEY (tenant_id, id)
  , FOREIGN KEY (tenant_id, command_id) REFERENCES rss_device_command.commands (tenant_id, command_id)
  , FOREIGN KEY (tenant_id, device) REFERENCES mdm_access.command_authorities (tenant_id, device)
  , FOREIGN KEY (tenant_id, device) REFERENCES mdm_access.devices (tenant_id, id)
  , FOREIGN KEY (tenant_id, policy_version) REFERENCES mdm_policy.versions (tenant_id, id)
  , CHECK (COALESCE(authority ->> 'kind' IN ('policy', 'retirement')
                AND authority ->> 'tenant' = CAST(tenant_id AS text)
                AND (authority ->> 'device')::uuid = device
                AND authority ->> 'version' = CAST(policy_version AS text)
                  , FALSE))
);
CREATE TABLE mdm_planning.configuration_receipts (
    tenant_id uuid NOT NULL
  , id uuid NOT NULL
  , actor text NOT NULL
  , fingerprint bytea NOT NULL CHECK (octet_length(fingerprint) = 32)
  , PRIMARY KEY (tenant_id, actor, id)
  , FOREIGN KEY (tenant_id, id) REFERENCES mdm_planning.configuration_operations (tenant_id, id)
);
CREATE TABLE mdm_planning.configuration_recovery (
    tenant_id uuid NOT NULL
  , device uuid NOT NULL
  , authority_epoch bigint NOT NULL
  , recovery_after text
  , PRIMARY KEY (tenant_id, device)
  , FOREIGN KEY (tenant_id, device) REFERENCES mdm_access.command_authorities (tenant_id, device)
);
ALTER TABLE mdm_planning.configuration_operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_planning.configuration_operations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_planning.configuration_operations USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
ALTER TABLE mdm_planning.configuration_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_planning.configuration_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_planning.configuration_receipts USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
ALTER TABLE mdm_planning.configuration_recovery ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_planning.configuration_recovery FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_planning.configuration_recovery USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
COMMIT;

CREATE FUNCTION mdm_planning.configuration_windows_pending_operations(p_device uuid, p_after uuid) RETURNS SETOF mdm_planning.configuration_operations
 LANGUAGE sql SECURITY DEFINER SET search_path TO 'pg_catalog'
 AS $$
 SELECT o.* FROM mdm_planning.configuration_operations o
 JOIN rss_device_command.commands d ON d.tenant_id=o.tenant_id AND d.command_id=o.id::text
 JOIN mdm_access.devices r ON(r.tenant_id,r.id)=(o.tenant_id,o.device)
 WHERE o.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
  AND o.device=p_device AND o.id>p_after
  AND r.state='active' AND o.gateway_accepted AND o.dispatch_failure IS NULL
  AND o.input_context->>'platform'='windows' AND d.status IN ('published','received')
  AND (o.input_context->>'deadline')::bigint>extract(epoch FROM clock_timestamp())
 ORDER BY o.id LIMIT 64;
$$;
REVOKE ALL ON FUNCTION mdm_planning.configuration_windows_pending_operations(uuid,uuid) FROM PUBLIC;

-- Discovery starts with work, never with every installed push channel. Authority
-- is still rechecked by the configuration owner in the eventual claimant's transaction.
CREATE FUNCTION mdm_planning.configuration_windows_wake_candidates(p_after uuid) RETURNS TABLE(device uuid)
 LANGUAGE sql SECURITY DEFINER SET search_path TO 'pg_catalog'
 AS $$
 SELECT o.device FROM mdm_planning.configuration_operations o
 JOIN rss_device_command.commands d ON d.tenant_id=o.tenant_id AND d.command_id=o.id::text
 JOIN mdm_access.devices r ON(r.tenant_id,r.id)=(o.tenant_id,o.device)
 WHERE o.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
  AND (p_after IS NULL OR o.device>p_after) AND r.state='active'
  AND o.gateway_accepted AND o.dispatch_failure IS NULL
  AND o.input_context->>'platform'='windows' AND d.status IN ('published','received')
  AND (o.input_context->>'deadline')::bigint>extract(epoch FROM clock_timestamp())
 ORDER BY device LIMIT 32;
$$;
REVOKE ALL ON FUNCTION mdm_planning.configuration_windows_wake_candidates(uuid) FROM PUBLIC;
