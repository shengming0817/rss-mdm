-- Fresh installation: Device owns fixed controls and accepted unmanage work.
BEGIN;

SET LOCAL check_function_bodies = false;

-- The registration owner participates on its original audit connection. Narrow
-- product functions preserve the shared command component's exclusive runtime ACL.
CREATE FUNCTION mdm_devices.retirement_commands(p_device uuid, p_after text) RETURNS SETOF rss_device_command.commands
 LANGUAGE sql SECURITY DEFINER SET search_path TO 'pg_catalog'
 AS $$
 SELECT a.device_id FROM (
  SELECT DISTINCT d.device_id FROM mdm_devices.control_operations o
  JOIN rss_device_command.commands d ON(d.tenant_id,d.command_id)=(o.tenant_id,o.id::text)
  JOIN mdm_access.devices r ON(r.tenant_id,r.id)=(o.tenant_id,o.device)
  WHERE o.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
   AND o.device=p_device AND (r.state<>'active' OR (r.retirement IS NOT NULL AND NOT EXISTS(SELECT 1 FROM mdm_devices.retirement_work w WHERE(w.tenant_id,w.execution)=(o.tenant_id,o.id)) AND NOT EXISTS(SELECT 1 FROM mdm_windows.attempts a WHERE(a.tenant_id,a.operation)=(o.tenant_id,o.id) AND a.phase='execute') AND NOT EXISTS(SELECT 1 FROM mdm_apple.attempts a WHERE(a.tenant_id,a.operation)=(o.tenant_id,o.id) AND a.phase='execute' AND a.state<>'pending'))) AND d.terminal_at IS NULL
  ORDER BY d.device_id
 ) scope CROSS JOIN LATERAL rss_device_command.lock_authority(nullif(current_setting('rss.tenant_id',true),'')::uuid,scope.device_id) a;
 SELECT d.* FROM mdm_devices.control_operations o
 JOIN rss_device_command.commands d ON(d.tenant_id,d.command_id)=(o.tenant_id,o.id::text)
 JOIN mdm_access.devices r ON(r.tenant_id,r.id)=(o.tenant_id,o.device)
 WHERE o.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
  AND o.device=p_device AND (r.state<>'active' OR (r.retirement IS NOT NULL AND NOT EXISTS(SELECT 1 FROM mdm_devices.retirement_work w WHERE(w.tenant_id,w.execution)=(o.tenant_id,o.id)) AND NOT EXISTS(SELECT 1 FROM mdm_windows.attempts a WHERE(a.tenant_id,a.operation)=(o.tenant_id,o.id) AND a.phase='execute') AND NOT EXISTS(SELECT 1 FROM mdm_apple.attempts a WHERE(a.tenant_id,a.operation)=(o.tenant_id,o.id) AND a.phase='execute' AND a.state<>'pending'))) AND d.terminal_at IS NULL
  AND d.command_id COLLATE "C" > p_after ORDER BY d.command_id COLLATE "C" LIMIT 64;
$$;

REVOKE ALL ON FUNCTION mdm_devices.retirement_commands(uuid,text) FROM PUBLIC;

CREATE FUNCTION mdm_devices.save_retired_command(p_device uuid, p_run uuid, p_previous bigint, p_terminal bigint) RETURNS boolean
 LANGUAGE sql SECURITY DEFINER SET search_path TO 'pg_catalog'
 AS $$
 SELECT a.device_id FROM mdm_devices.control_operations o
 JOIN rss_device_command.commands d ON(d.tenant_id,d.command_id)=(o.tenant_id,o.id::text)
 JOIN mdm_access.devices r ON(r.tenant_id,r.id)=(o.tenant_id,o.device)
 CROSS JOIN LATERAL rss_device_command.lock_authority(o.tenant_id,d.device_id) a
 WHERE o.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
  AND o.device=p_device AND o.id=p_run AND (r.state<>'active' OR (r.retirement IS NOT NULL AND NOT EXISTS(SELECT 1 FROM mdm_devices.retirement_work w WHERE(w.tenant_id,w.execution)=(o.tenant_id,o.id)) AND NOT EXISTS(SELECT 1 FROM mdm_windows.attempts a WHERE(a.tenant_id,a.operation)=(o.tenant_id,o.id) AND a.phase='execute') AND NOT EXISTS(SELECT 1 FROM mdm_apple.attempts a WHERE(a.tenant_id,a.operation)=(o.tenant_id,o.id) AND a.phase='execute' AND a.state<>'pending')));
 SELECT coalesce((SELECT rss_device_command.save(d.tenant_id,d.device_id,d.command_id,p_previous,'cancelled',d.published_at,d.received_at,p_terminal)
 FROM mdm_devices.control_operations o
 JOIN rss_device_command.commands d ON(d.tenant_id,d.command_id)=(o.tenant_id,o.id::text)
 JOIN mdm_access.devices r ON(r.tenant_id,r.id)=(o.tenant_id,o.device)
 WHERE o.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
  AND o.device=p_device AND o.id=p_run AND (r.state<>'active' OR (r.retirement IS NOT NULL AND NOT EXISTS(SELECT 1 FROM mdm_devices.retirement_work w WHERE(w.tenant_id,w.execution)=(o.tenant_id,o.id)) AND NOT EXISTS(SELECT 1 FROM mdm_windows.attempts a WHERE(a.tenant_id,a.operation)=(o.tenant_id,o.id) AND a.phase='execute') AND NOT EXISTS(SELECT 1 FROM mdm_apple.attempts a WHERE(a.tenant_id,a.operation)=(o.tenant_id,o.id) AND a.phase='execute' AND a.state<>'pending')))
  AND d.version=p_previous AND d.terminal_at IS NULL),false);
$$;

REVOKE ALL ON FUNCTION mdm_devices.save_retired_command(uuid,uuid,bigint,bigint) FROM PUBLIC;

-- Retirement uses the action owner reducer and a narrow CAS projection on the
-- original audit connection. The application role retains read-only table access.
CREATE FUNCTION mdm_devices.save_retired_action(p_device uuid, p_run uuid, p_previous jsonb, p_state jsonb) RETURNS boolean
 LANGUAGE sql SECURITY DEFINER SET search_path TO 'pg_catalog'
 AS $$
 WITH changed AS (
  UPDATE mdm_devices.unmanage_runs a SET state=p_state
  WHERE a.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
   AND a.device=p_device AND a.id=p_run AND a.state=p_previous
   AND a.state->>'execution' IN ('not_started','running','waiting_reboot','unknown')
   AND a.state->>'cancellation'='none'
   AND EXISTS(SELECT 1 FROM mdm_access.devices r
    WHERE (r.tenant_id,r.id)=(a.tenant_id,a.device) AND (r.state<>'active' OR (r.retirement IS NOT NULL AND NOT EXISTS(SELECT 1 FROM mdm_devices.retirement_work w WHERE(w.tenant_id,w.execution)=(a.tenant_id,a.id)))))
  RETURNING a.id
 ) SELECT EXISTS(SELECT 1 FROM changed);
$$;

REVOKE ALL ON FUNCTION mdm_devices.save_retired_action(uuid,uuid,jsonb,jsonb) FROM PUBLIC;

CREATE TABLE mdm_devices.unmanage_receipts (
    tenant_id uuid NOT NULL,
    actor text NOT NULL,
    id uuid NOT NULL,
    fingerprint bytea NOT NULL,
    response jsonb NOT NULL,
    audit_details jsonb,
    CONSTRAINT unmanage_receipts_fingerprint_check CHECK ((octet_length(fingerprint) = 32)),
    CONSTRAINT unmanage_receipts_response_check CHECK ((octet_length((response)::text) <= 6291456))
);

ALTER TABLE ONLY mdm_devices.unmanage_receipts FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_devices.unmanage_runs (
    origin jsonb NOT NULL CHECK (origin IN ('"system"', '"policy"', '"human"', '"ai"'))
  , source_objects jsonb NOT NULL
  , tenant_id uuid NOT NULL
  , id uuid NOT NULL
  , source_kind text DEFAULT CAST('policy' AS text) NOT NULL
  , policy_version uuid
  , device uuid NOT NULL
  , occurrence text NOT NULL
  , created_at bigint NOT NULL
  , available_at bigint NOT NULL
  , deadline bigint NOT NULL
  , state jsonb NOT NULL
  , gateway_accepted boolean DEFAULT FALSE NOT NULL
  , dispatch_fingerprint bytea NOT NULL
  , dispatch_failure jsonb CHECK (dispatch_failure IS NULL
                               OR (jsonb_typeof(dispatch_failure) = 'object'
                               AND octet_length(CAST(dispatch_failure AS text)) <= 8192))
  , result jsonb
  , CONSTRAINT unmanage_runs_available_at_check CHECK (available_at >= 0)
  , CONSTRAINT unmanage_runs_check CHECK (source_kind = 'policy'
                                      AND policy_version IS NOT NULL)
  , CONSTRAINT unmanage_runs_check1 CHECK (deadline > available_at)
  , CONSTRAINT unmanage_runs_created_at_check CHECK (created_at >= 0)
  , CONSTRAINT unmanage_runs_dispatch_fingerprint_check CHECK (octet_length(dispatch_fingerprint) = 32)
  , CONSTRAINT unmanage_runs_occurrence_check CHECK (octet_length(occurrence) >= 1
                                                 AND octet_length(occurrence) <= 256)
  , CONSTRAINT unmanage_runs_result_check CHECK (octet_length(CAST(result AS text)) <= 1114112)
  , CONSTRAINT unmanage_runs_state_check CHECK (octet_length(CAST(state AS text)) <= 4096)
);

ALTER TABLE ONLY mdm_devices.unmanage_runs FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_devices.control_recovery (
 tenant_id uuid NOT NULL,device uuid NOT NULL,authority_epoch bigint NOT NULL CHECK(authority_epoch>0),recovery_after text,
 PRIMARY KEY(tenant_id,device)
);

ALTER TABLE mdm_devices.control_recovery ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_devices.control_recovery FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant ON mdm_devices.control_recovery USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);

GRANT SELECT,INSERT ON mdm_devices.control_recovery TO mdm_command_runtime;

GRANT UPDATE(authority_epoch,recovery_after) ON mdm_devices.control_recovery TO mdm_command_runtime;

CREATE TABLE mdm_devices.control_operations (
    tenant_id uuid NOT NULL
  , id uuid NOT NULL
  , device uuid NOT NULL
  , request bytea NOT NULL
  , input_context jsonb NOT NULL CHECK (jsonb_typeof(input_context) = 'object'
                                    AND octet_length(CAST(input_context AS text)) <= 4096)
  , fingerprint bytea NOT NULL
  , generation bigint NOT NULL
  , epoch bigint NOT NULL
  , authority jsonb NOT NULL
  , revision bigint DEFAULT 1 NOT NULL
  , observed_command_version bigint NOT NULL DEFAULT 1 CHECK (observed_command_version > 0)
  , dispatch_fingerprint bytea NOT NULL
  , dispatch_failure jsonb CHECK (dispatch_failure IS NULL
                               OR (jsonb_typeof(dispatch_failure) = 'object'
                               AND octet_length(CAST(dispatch_failure AS text)) <= 8192))
  , gateway_accepted boolean DEFAULT FALSE NOT NULL
  , source_kind text DEFAULT CAST('direct' AS text) NOT NULL
  , policy_version uuid
  , CONSTRAINT operation_authority_source CHECK (COALESCE(CASE source_kind
                                                            WHEN CAST('direct' AS text)
                                                              THEN authority ->> CAST('kind' AS text) = CAST('device_control' AS text)
                                                            WHEN CAST('policy' AS text)
                                                              THEN authority ->> CAST('kind' AS text) = 'retirement'
                                                               AND authority ->> CAST('tenant' AS text) = CAST(tenant_id AS text)
                                                               AND authority ->> CAST('device' AS text) = device
                                                               AND authority ->> CAST('version' AS text) = CAST(policy_version AS text)
                                                            ELSE CAST(NULL AS boolean)
                                                          END
                                                        , FALSE))
  , CONSTRAINT operation_source CHECK ((source_kind = CAST('direct' AS text)
                                    AND policy_version IS NULL)
                                    OR (source_kind = CAST('policy' AS text)
                                    AND policy_version IS NOT NULL))
  , CONSTRAINT control_operations_authority_check CHECK (octet_length(CAST(authority AS text)) <= 1048576)
  , CONSTRAINT control_operations_dispatch_fingerprint_check CHECK (octet_length(dispatch_fingerprint) = 32)
  , CONSTRAINT control_operations_epoch_check CHECK (epoch > 0)
  , CONSTRAINT control_operations_fingerprint_check CHECK (octet_length(fingerprint) = 32)
  , CONSTRAINT control_operations_generation_check CHECK (generation > 0)
  , CONSTRAINT control_operations_request_check CHECK (octet_length(request) BETWEEN 68 AND 33554500)
  , CONSTRAINT control_operations_revision_check CHECK (revision > 0)
  , CONSTRAINT control_operations_source_kind_check CHECK (source_kind = ANY(ARRAY[CAST('direct' AS text)
                                                                                 , CAST('policy' AS text)]))
);

ALTER TABLE ONLY mdm_devices.control_operations FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_devices.unmanage_policy_recovery (
    input_revision bigint NOT NULL DEFAULT 1 CHECK(input_revision>0),
    input_consumed bigint NOT NULL DEFAULT 0 CHECK(input_consumed>=0),
    input_window bigint NOT NULL DEFAULT 0 CHECK(input_window>=input_consumed),
    tenant_id uuid NOT NULL,
    policy uuid NOT NULL,
    recovery_after uuid
);

ALTER TABLE ONLY mdm_devices.unmanage_policy_recovery FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_devices.control_requests (
    tenant_id uuid NOT NULL,
    actor text NOT NULL CHECK(length(actor)>0),
    instance uuid,
    id uuid NOT NULL,
    operation uuid NOT NULL,
    fingerprint bytea NOT NULL,
    response jsonb NOT NULL,
    CONSTRAINT control_requests_fingerprint_check CHECK ((octet_length(fingerprint) = 32))
);

ALTER TABLE ONLY mdm_devices.control_requests FORCE ROW LEVEL SECURITY;

ALTER TABLE ONLY mdm_devices.unmanage_receipts
    ADD CONSTRAINT unmanage_receipts_pkey PRIMARY KEY (tenant_id, actor, id);

ALTER TABLE ONLY mdm_devices.unmanage_runs
    ADD CONSTRAINT unmanage_runs_pkey PRIMARY KEY (tenant_id, id);

ALTER TABLE ONLY mdm_devices.unmanage_runs
    ADD CONSTRAINT unmanage_runs_tenant_id_policy_version_occurrence_device_key UNIQUE (tenant_id, policy_version, occurrence, device);

ALTER TABLE ONLY mdm_devices.control_operations
    ADD CONSTRAINT control_operations_pkey PRIMARY KEY (tenant_id, id);

ALTER TABLE ONLY mdm_devices.unmanage_policy_recovery
    ADD CONSTRAINT unmanage_policy_recovery_pkey PRIMARY KEY (tenant_id, policy);

ALTER TABLE ONLY mdm_devices.control_requests
    ADD CONSTRAINT control_requests_pkey PRIMARY KEY (tenant_id, actor, id);

CREATE INDEX collection_starts
  ON mdm_devices.unmanage_runs (tenant_id
                              , policy_version
                              , device
                              , (CAST(state ->> 'startedAt' AS bigint)) DESC)
  WHERE state ->> 'startedAt' IS NOT NULL;

CREATE INDEX action_due
  ON mdm_devices.unmanage_runs (tenant_id
                              , device
                              , available_at
                              , id);

ALTER TABLE mdm_devices.unmanage_receipts ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_devices.unmanage_runs ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_devices.control_operations ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_devices.unmanage_policy_recovery ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_devices.control_requests ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant ON mdm_devices.unmanage_receipts USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_devices.unmanage_runs USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_devices.control_operations USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_devices.unmanage_policy_recovery USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_devices.control_requests USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

-- Actual native wire ranges within one logical attempt; original input remains on the operation.

-- Wake eligibility reads published work without giving the Windows role access
-- to shared command storage. Reauthorization and user scope remain checked in Rust.
CREATE FUNCTION mdm_devices.windows_pending_operations(p_device uuid, p_after uuid) RETURNS SETOF mdm_devices.control_operations
 LANGUAGE sql SECURITY DEFINER SET search_path TO 'pg_catalog'
 AS $$
 SELECT o.* FROM mdm_devices.control_operations o
 JOIN rss_device_command.commands d ON d.tenant_id=o.tenant_id AND d.command_id=o.id::text
 JOIN mdm_access.devices r ON(r.tenant_id,r.id)=(o.tenant_id,o.device)
 WHERE o.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
  AND o.device=p_device AND o.id>p_after
  AND r.state='active' AND o.gateway_accepted AND o.dispatch_failure IS NULL
  AND o.input_context->>'platform'='windows' AND d.status IN ('published','received')
  AND (o.input_context->>'deadline')::bigint>extract(epoch FROM clock_timestamp())
 ORDER BY o.id LIMIT 64;
$$;

REVOKE ALL ON FUNCTION mdm_devices.windows_pending_operations(uuid,uuid) FROM PUBLIC;

-- Discovery starts with work, never with every installed push channel. Authority
-- is still rechecked by the Device service in the eventual claimant's transaction.
CREATE FUNCTION mdm_devices.windows_wake_candidates(p_after uuid) RETURNS TABLE(device uuid)
 LANGUAGE sql SECURITY DEFINER SET search_path TO 'pg_catalog'
 AS $$
 SELECT o.device FROM mdm_devices.control_operations o
 JOIN rss_device_command.commands d ON d.tenant_id=o.tenant_id AND d.command_id=o.id::text
 JOIN mdm_access.devices r ON(r.tenant_id,r.id)=(o.tenant_id,o.device)
 WHERE o.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
  AND (p_after IS NULL OR o.device>p_after) AND r.state='active'
  AND o.gateway_accepted AND o.dispatch_failure IS NULL
  AND o.input_context->>'platform'='windows' AND d.status IN ('published','received')
  AND (o.input_context->>'deadline')::bigint>extract(epoch FROM clock_timestamp())
 ORDER BY device LIMIT 32;
$$;

REVOKE ALL ON FUNCTION mdm_devices.windows_wake_candidates(uuid) FROM PUBLIC;

CREATE INDEX windows_wake_operations
  ON mdm_devices.control_operations (tenant_id
                                   , device
                                   , id)
  WHERE gateway_accepted
    AND dispatch_failure IS NULL
    AND input_context ->> 'platform' = 'windows';

COMMIT;

GRANT UPDATE(request) ON mdm_devices.control_operations TO mdm_command_runtime;

-- A recovery identity hashes explicit UTF-8, independent of client_encoding.
-- PostgreSQL marks textsend STABLE because its wire bytes depend on that setting;
-- convert_to with this fixed destination is deterministic for the stored text.
CREATE FUNCTION mdm_devices.recovery_key(p_device uuid) RETURNS text
 LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE SET search_path TO 'pg_catalog'
 AS $$ SELECT encode(sha256(convert_to(p_device::text,'UTF8')),'hex'); $$;

REVOKE ALL ON FUNCTION mdm_devices.recovery_key(uuid) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION mdm_devices.recovery_key(uuid) TO mdm_command_runtime,mdm_policy_runtime;

CREATE INDEX command_device_recovery ON mdm_devices.control_recovery(tenant_id,mdm_devices.recovery_key(device));
