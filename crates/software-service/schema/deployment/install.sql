-- Fresh installation: execution owns these objects.
BEGIN;
SET LOCAL check_function_bodies = false;

CREATE SCHEMA mdm_software_deployment;

CREATE FUNCTION mdm_software_deployment.installation_status(p_operation uuid) RETURNS text
 LANGUAGE sql SECURITY DEFINER SET search_path TO 'pg_catalog'
 AS $$
 SELECT d.status FROM mdm_software_deployment.operations o
 JOIN rss_device_command.commands d ON(d.tenant_id,d.command_id)=(o.tenant_id,o.id::text)
 WHERE o.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
 AND o.id=p_operation AND o.authority->>'kind'='agent_install';
$$;

REVOKE ALL ON FUNCTION mdm_software_deployment.installation_status(uuid) FROM PUBLIC;

-- The registration owner participates on its original audit connection. Narrow
-- product functions preserve the shared command component's exclusive runtime ACL.
CREATE FUNCTION mdm_software_deployment.retirement_commands(p_registration uuid, p_after text) RETURNS SETOF rss_device_command.commands
 LANGUAGE sql SECURITY DEFINER SET search_path TO 'pg_catalog'
 AS $$
 SELECT a.device_id FROM (
  SELECT DISTINCT d.device_id FROM mdm_software_deployment.operations o
  JOIN rss_device_command.commands d ON(d.tenant_id,d.command_id)=(o.tenant_id,o.id::text)
  JOIN mdm_access.registrations r ON(r.tenant_id,r.id)=(o.tenant_id,o.registration)
  WHERE o.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
   AND o.registration=p_registration AND (r.state<>'active' OR (EXISTS(SELECT 1 FROM mdm_access.devices x WHERE(x.tenant_id,x.id)=(r.tenant_id,r.device) AND x.retirement IS NOT NULL) AND NOT EXISTS(SELECT 1 FROM mdm_devices.retirement_work w WHERE(w.tenant_id,w.execution)=(o.tenant_id,o.id)) AND NOT EXISTS(SELECT 1 FROM mdm_windows.attempts a WHERE(a.tenant_id,a.operation)=(o.tenant_id,o.id) AND a.phase='execute') AND NOT EXISTS(SELECT 1 FROM mdm_apple.attempts a WHERE(a.tenant_id,a.operation)=(o.tenant_id,o.id) AND a.phase='execute' AND a.state<>'pending'))) AND d.terminal_at IS NULL
  ORDER BY d.device_id
 ) scope CROSS JOIN LATERAL rss_device_command.lock_authority(nullif(current_setting('rss.tenant_id',true),'')::uuid,scope.device_id) a;
 SELECT d.* FROM mdm_software_deployment.operations o
 JOIN rss_device_command.commands d ON(d.tenant_id,d.command_id)=(o.tenant_id,o.id::text)
 JOIN mdm_access.registrations r ON(r.tenant_id,r.id)=(o.tenant_id,o.registration)
 WHERE o.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
  AND o.registration=p_registration AND (r.state<>'active' OR (EXISTS(SELECT 1 FROM mdm_access.devices x WHERE(x.tenant_id,x.id)=(r.tenant_id,r.device) AND x.retirement IS NOT NULL) AND NOT EXISTS(SELECT 1 FROM mdm_devices.retirement_work w WHERE(w.tenant_id,w.execution)=(o.tenant_id,o.id)) AND NOT EXISTS(SELECT 1 FROM mdm_windows.attempts a WHERE(a.tenant_id,a.operation)=(o.tenant_id,o.id) AND a.phase='execute') AND NOT EXISTS(SELECT 1 FROM mdm_apple.attempts a WHERE(a.tenant_id,a.operation)=(o.tenant_id,o.id) AND a.phase='execute' AND a.state<>'pending'))) AND d.terminal_at IS NULL
  AND d.command_id COLLATE "C" > p_after ORDER BY d.command_id COLLATE "C" LIMIT 64;
$$;
REVOKE ALL ON FUNCTION mdm_software_deployment.retirement_commands(uuid,text) FROM PUBLIC;

CREATE FUNCTION mdm_software_deployment.save_retired_command(p_registration uuid, p_run uuid, p_previous bigint, p_terminal bigint) RETURNS boolean
 LANGUAGE sql SECURITY DEFINER SET search_path TO 'pg_catalog'
 AS $$
 SELECT a.device_id FROM mdm_software_deployment.operations o
 JOIN rss_device_command.commands d ON(d.tenant_id,d.command_id)=(o.tenant_id,o.id::text)
 JOIN mdm_access.registrations r ON(r.tenant_id,r.id)=(o.tenant_id,o.registration)
 CROSS JOIN LATERAL rss_device_command.lock_authority(o.tenant_id,d.device_id) a
 WHERE o.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
  AND o.registration=p_registration AND o.id=p_run AND (r.state<>'active' OR (EXISTS(SELECT 1 FROM mdm_access.devices x WHERE(x.tenant_id,x.id)=(r.tenant_id,r.device) AND x.retirement IS NOT NULL) AND NOT EXISTS(SELECT 1 FROM mdm_devices.retirement_work w WHERE(w.tenant_id,w.execution)=(o.tenant_id,o.id)) AND NOT EXISTS(SELECT 1 FROM mdm_windows.attempts a WHERE(a.tenant_id,a.operation)=(o.tenant_id,o.id) AND a.phase='execute') AND NOT EXISTS(SELECT 1 FROM mdm_apple.attempts a WHERE(a.tenant_id,a.operation)=(o.tenant_id,o.id) AND a.phase='execute' AND a.state<>'pending')));
 SELECT coalesce((SELECT rss_device_command.save(d.tenant_id,d.device_id,d.command_id,p_previous,'cancelled',d.published_at,d.received_at,p_terminal)
 FROM mdm_software_deployment.operations o
 JOIN rss_device_command.commands d ON(d.tenant_id,d.command_id)=(o.tenant_id,o.id::text)
 JOIN mdm_access.registrations r ON(r.tenant_id,r.id)=(o.tenant_id,o.registration)
 WHERE o.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
  AND o.registration=p_registration AND o.id=p_run AND (r.state<>'active' OR (EXISTS(SELECT 1 FROM mdm_access.devices x WHERE(x.tenant_id,x.id)=(r.tenant_id,r.device) AND x.retirement IS NOT NULL) AND NOT EXISTS(SELECT 1 FROM mdm_devices.retirement_work w WHERE(w.tenant_id,w.execution)=(o.tenant_id,o.id)) AND NOT EXISTS(SELECT 1 FROM mdm_windows.attempts a WHERE(a.tenant_id,a.operation)=(o.tenant_id,o.id) AND a.phase='execute') AND NOT EXISTS(SELECT 1 FROM mdm_apple.attempts a WHERE(a.tenant_id,a.operation)=(o.tenant_id,o.id) AND a.phase='execute' AND a.state<>'pending')))
  AND d.version=p_previous AND d.terminal_at IS NULL),false);
$$;
REVOKE ALL ON FUNCTION mdm_software_deployment.save_retired_command(uuid,uuid,bigint,bigint) FROM PUBLIC;

-- Retirement uses the action owner reducer and a narrow CAS projection on the
-- original audit connection. The application role retains read-only table access.
CREATE FUNCTION mdm_software_deployment.save_retired_action(p_registration uuid, p_run uuid, p_previous jsonb, p_state jsonb) RETURNS boolean
 LANGUAGE sql SECURITY DEFINER SET search_path TO 'pg_catalog'
 AS $$
 WITH changed AS (
  UPDATE mdm_software_deployment.action_runs a SET state=p_state
  WHERE a.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
   AND a.registration=p_registration AND a.id=p_run AND a.state=p_previous
   AND a.state->>'execution' IN ('not_started','running','waiting_reboot','unknown')
   AND a.state->>'cancellation'='none'
   AND EXISTS(SELECT 1 FROM mdm_access.registrations r
    WHERE (r.tenant_id,r.id)=(a.tenant_id,a.registration) AND (r.state<>'active' OR (EXISTS(SELECT 1 FROM mdm_access.devices x WHERE(x.tenant_id,x.id)=(r.tenant_id,r.device) AND x.retirement IS NOT NULL) AND NOT EXISTS(SELECT 1 FROM mdm_devices.retirement_work w WHERE(w.tenant_id,w.execution)=(a.tenant_id,a.id)))))
  RETURNING a.id
 ) SELECT EXISTS(SELECT 1 FROM changed);
$$;
REVOKE ALL ON FUNCTION mdm_software_deployment.save_retired_action(uuid,uuid,jsonb,jsonb) FROM PUBLIC;

CREATE TABLE mdm_software_deployment.agent_admission (
    tenant_id uuid NOT NULL,
    registration uuid NOT NULL,
    policy_after uuid
);

ALTER TABLE ONLY mdm_software_deployment.agent_admission FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_software_deployment.action_receipts (
    device text NOT NULL,
    registration uuid NOT NULL,
    generation bigint NOT NULL CHECK(generation > 0),
    tenant_id uuid NOT NULL,
    actor text NOT NULL,
    id uuid NOT NULL,
    fingerprint bytea NOT NULL,
    response jsonb NOT NULL,
    audit_details jsonb,
    CONSTRAINT action_receipts_fingerprint_check CHECK ((octet_length(fingerprint) = 32)),
    CONSTRAINT action_receipts_response_check CHECK ((octet_length((response)::text) <= 6291456))
);

ALTER TABLE ONLY mdm_software_deployment.action_receipts FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_software_deployment.action_runs (
 origin jsonb NOT NULL CHECK(origin IN ('"system"','"policy"','"human"','"ai"')),
 source_objects jsonb NOT NULL,
 tenant_id uuid NOT NULL,
 id uuid NOT NULL,
 source_kind text DEFAULT 'policy'::text NOT NULL,
 retirement uuid,
 policy_version uuid,
 device text NOT NULL,
 registration uuid NOT NULL,
 generation bigint NOT NULL,
 occurrence text NOT NULL,
 created_at bigint NOT NULL,
 available_at bigint NOT NULL,
 deadline bigint NOT NULL,
 state jsonb NOT NULL,
 gateway_accepted boolean DEFAULT false NOT NULL,
 dispatch_fingerprint bytea NOT NULL,
 dispatch_failure jsonb CHECK (dispatch_failure IS NULL OR (jsonb_typeof(dispatch_failure)='object' AND octet_length(dispatch_failure::text)<=8192)),
 result jsonb,
 invocation jsonb CHECK (invocation IS NULL OR (jsonb_typeof(invocation)='object' AND octet_length(invocation::text)<=131072)),
 CONSTRAINT action_runs_available_at_check CHECK ((available_at >= 0)),
 CONSTRAINT action_runs_check CHECK ((source_kind IN('policy','retirement')) AND (policy_version IS NOT NULL)),
 CONSTRAINT action_runs_check1 CHECK ((deadline > available_at)),
 CONSTRAINT action_runs_created_at_check CHECK ((created_at >= 0)),
 CONSTRAINT action_runs_dispatch_fingerprint_check CHECK ((octet_length(dispatch_fingerprint) = 32)),
 CONSTRAINT action_runs_generation_check CHECK ((generation > 0)),
 CONSTRAINT action_runs_occurrence_check CHECK (((octet_length(occurrence) >= 1) AND (octet_length(occurrence) <= 256))),
 CONSTRAINT action_runs_result_check CHECK ((octet_length((result)::text) <= 1114112)),
 CONSTRAINT action_runs_state_check CHECK ((octet_length((state)::text) <= 4096)),
 software_effect jsonb CHECK (software_effect IS NULL OR (jsonb_typeof(software_effect)='object' AND octet_length(software_effect::text)<=4096)),
 invocation_archive jsonb CHECK (invocation_archive IS NULL OR octet_length(invocation_archive::text)<=196608)

);

ALTER TABLE ONLY mdm_software_deployment.action_runs FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_software_deployment.device_recovery (
 tenant_id uuid NOT NULL,device text NOT NULL,authority_epoch bigint NOT NULL CHECK(authority_epoch>0),recovery_after text,
 PRIMARY KEY(tenant_id,device)
);
ALTER TABLE mdm_software_deployment.device_recovery ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_software_deployment.device_recovery FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_software_deployment.device_recovery USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON mdm_software_deployment.device_recovery TO mdm_command_runtime;
GRANT UPDATE(authority_epoch,recovery_after) ON mdm_software_deployment.device_recovery TO mdm_command_runtime;

CREATE TABLE mdm_software_deployment.operations (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    device text NOT NULL,
    request bytea NOT NULL,
    input_context jsonb NOT NULL CHECK (jsonb_typeof(input_context)='object' AND octet_length(input_context::text)<=4096),
    fingerprint bytea NOT NULL,
    registration uuid NOT NULL,
    registration_generation bigint NOT NULL,
    generation bigint NOT NULL,
    epoch bigint NOT NULL,
    authority jsonb NOT NULL,
    revision bigint DEFAULT 1 NOT NULL,
    observed_command_version bigint NOT NULL DEFAULT 1 CHECK(observed_command_version>0),
    dispatch_fingerprint bytea NOT NULL,
    dispatch_failure jsonb CHECK (dispatch_failure IS NULL OR (jsonb_typeof(dispatch_failure)='object' AND octet_length(dispatch_failure::text)<=8192)),
    gateway_accepted boolean DEFAULT false NOT NULL,
    source_kind text DEFAULT 'policy'::text NOT NULL,
 retirement uuid,
    policy_version uuid,
    CONSTRAINT operation_authority_source CHECK(authority->>'kind' IN ('agent_install','software') AND authority->>'tenant'=tenant_id::text AND authority->>'device'=device AND authority->>'version'=policy_version::text AND authority->>'operation'=id::text),
    CONSTRAINT operation_source CHECK(source_kind='policy' AND policy_version IS NOT NULL),
    CONSTRAINT operations_authority_check CHECK ((octet_length((authority)::text) <= 1048576)),
    CONSTRAINT operations_dispatch_fingerprint_check CHECK ((octet_length(dispatch_fingerprint) = 32)),
    CONSTRAINT operations_epoch_check CHECK ((epoch > 0)),
    CONSTRAINT operations_fingerprint_check CHECK ((octet_length(fingerprint) = 32)),
    CONSTRAINT operations_generation_check CHECK ((generation > 0)),
    CONSTRAINT operations_registration_generation_check CHECK ((registration_generation > 0)),
    CONSTRAINT operations_request_check CHECK ((octet_length(request) BETWEEN 68 AND 33554500)),
    CONSTRAINT operations_revision_check CHECK ((revision > 0)),
    CONSTRAINT operations_source_kind_check CHECK ((source_kind = ANY (ARRAY['policy'::text])))
);

ALTER TABLE ONLY mdm_software_deployment.operations FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_software_deployment.policy_recovery (
    input_revision bigint NOT NULL DEFAULT 1 CHECK(input_revision>0),
    input_consumed bigint NOT NULL DEFAULT 0 CHECK(input_consumed>=0),
    input_window bigint NOT NULL DEFAULT 0 CHECK(input_window>=input_consumed),
    stats_revision bigint NOT NULL DEFAULT 0 CHECK(stats_revision>=0),
    dispatch_revision bigint NOT NULL DEFAULT 0,
    dispatch_consumed bigint NOT NULL DEFAULT 0,
    dispatch_window bigint NOT NULL DEFAULT 0,
    dispatch_after text,
    CHECK(dispatch_revision>=dispatch_window AND dispatch_window>=dispatch_consumed AND dispatch_consumed>=0),
    tenant_id uuid NOT NULL,
    policy uuid NOT NULL,
    recovery_after uuid
);

ALTER TABLE ONLY mdm_software_deployment.policy_recovery FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_software_deployment.requests (
    tenant_id uuid NOT NULL,
    actor text NOT NULL CHECK(length(actor)>0),
    id uuid NOT NULL,
    operation uuid NOT NULL,
    fingerprint bytea NOT NULL,
    response jsonb NOT NULL,
    CONSTRAINT requests_fingerprint_check CHECK ((octet_length(fingerprint) = 32))
);

ALTER TABLE ONLY mdm_software_deployment.requests FORCE ROW LEVEL SECURITY;

ALTER TABLE ONLY mdm_software_deployment.agent_admission
    ADD CONSTRAINT agent_admission_pkey PRIMARY KEY (tenant_id, registration);

ALTER TABLE ONLY mdm_software_deployment.action_receipts
    ADD CONSTRAINT action_receipts_pkey PRIMARY KEY (tenant_id, actor, id);

ALTER TABLE ONLY mdm_software_deployment.action_runs
    ADD CONSTRAINT action_runs_pkey PRIMARY KEY (tenant_id, id);

ALTER TABLE ONLY mdm_software_deployment.action_runs
    ADD CONSTRAINT action_runs_tenant_id_policy_version_occurrence_device_key UNIQUE (tenant_id, policy_version, occurrence, device);

ALTER TABLE ONLY mdm_software_deployment.operations
    ADD CONSTRAINT operations_pkey PRIMARY KEY (tenant_id, id);

ALTER TABLE ONLY mdm_software_deployment.policy_recovery
    ADD CONSTRAINT policy_recovery_pkey PRIMARY KEY (tenant_id, policy);

ALTER TABLE ONLY mdm_software_deployment.requests
    ADD CONSTRAINT requests_pkey PRIMARY KEY (tenant_id, actor, id);

CREATE INDEX collection_starts ON mdm_software_deployment.action_runs(tenant_id,policy_version,device,registration,generation,((state->>'startedAt')::bigint) DESC) WHERE state->>'startedAt' IS NOT NULL;

CREATE INDEX action_due ON mdm_software_deployment.action_runs USING btree (tenant_id, registration, available_at, id);

CREATE INDEX action_runs_software_stage_latest ON mdm_software_deployment.action_runs USING btree (tenant_id, policy_version, device, created_at DESC, id DESC);

ALTER TABLE mdm_software_deployment.agent_admission ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_software_deployment.action_receipts ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_software_deployment.action_runs ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_software_deployment.operations ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_software_deployment.policy_recovery ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_software_deployment.requests ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant ON mdm_software_deployment.agent_admission USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_software_deployment.action_receipts USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_software_deployment.action_runs USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_software_deployment.operations USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_software_deployment.policy_recovery USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_software_deployment.requests USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

-- Actual native wire ranges within one logical attempt; original input remains on the operation.

-- Wake eligibility reads published work without giving the Windows role access
-- to shared command storage. Reauthorization and user scope remain checked in Rust.
CREATE FUNCTION mdm_software_deployment.windows_pending_operations(p_registration uuid, p_generation bigint, p_after uuid) RETURNS SETOF mdm_software_deployment.operations
 LANGUAGE sql SECURITY DEFINER SET search_path TO 'pg_catalog'
 AS $$
 SELECT o.* FROM mdm_software_deployment.operations o
 JOIN rss_device_command.commands d ON d.tenant_id=o.tenant_id AND d.command_id=o.id::text
 JOIN mdm_access.registrations r ON(r.tenant_id,r.id,r.generation)=(o.tenant_id,o.registration,o.registration_generation)
 WHERE o.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
  AND o.registration=p_registration AND o.registration_generation=p_generation AND o.id>p_after
  AND r.state='active' AND o.gateway_accepted AND o.dispatch_failure IS NULL
  AND o.input_context->>'platform'='windows' AND d.status IN ('published','received')
  AND (o.input_context->>'deadline')::bigint>extract(epoch FROM clock_timestamp())
 ORDER BY o.id LIMIT 64;
$$;
REVOKE ALL ON FUNCTION mdm_software_deployment.windows_pending_operations(uuid,bigint,uuid) FROM PUBLIC;

-- Discovery starts with work, never with every installed push channel. Authority
-- is still rechecked by Software in the eventual claimant's transaction.
CREATE FUNCTION mdm_software_deployment.windows_wake_candidates(p_after uuid) RETURNS TABLE(registration uuid)
 LANGUAGE sql SECURITY DEFINER SET search_path TO 'pg_catalog'
 AS $$
 SELECT o.registration FROM mdm_software_deployment.operations o
 JOIN rss_device_command.commands d ON d.tenant_id=o.tenant_id AND d.command_id=o.id::text
 JOIN mdm_access.registrations r ON(r.tenant_id,r.id,r.generation)=(o.tenant_id,o.registration,o.registration_generation)
 WHERE o.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
  AND o.registration>p_after AND r.state='active'
  AND o.gateway_accepted AND o.dispatch_failure IS NULL
  AND o.input_context->>'platform'='windows' AND d.status IN ('published','received')
  AND (o.input_context->>'deadline')::bigint>extract(epoch FROM clock_timestamp())
 ORDER BY registration LIMIT 32;
$$;
REVOKE ALL ON FUNCTION mdm_software_deployment.windows_wake_candidates(uuid) FROM PUBLIC;
CREATE INDEX windows_wake_operations ON mdm_software_deployment.operations(tenant_id,registration,registration_generation,id)
 WHERE gateway_accepted AND dispatch_failure IS NULL AND input_context->>'platform'='windows';

CREATE INDEX action_software_effect ON mdm_software_deployment.action_runs(tenant_id,device) WHERE software_effect IS NOT NULL;
COMMIT;

CREATE TABLE mdm_software_deployment.software_stage_stats (
 gate_open boolean NOT NULL DEFAULT false,
 tenant_id uuid NOT NULL, version uuid NOT NULL, stage integer NOT NULL CHECK(stage>=0),
 input jsonb NOT NULL CHECK(octet_length(input::text)<=65536), cursor text,
 generation uuid NOT NULL, membership_complete boolean NOT NULL,
 ready boolean NOT NULL, counts jsonb NOT NULL CHECK(octet_length(counts::text)<=4096),
 PRIMARY KEY(tenant_id,version,stage)
);
CREATE TABLE mdm_software_deployment.software_binding_revisions(tenant_id uuid PRIMARY KEY,revision bigint NOT NULL CHECK(revision>=0));
ALTER TABLE mdm_software_deployment.software_stage_stats ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_software_deployment.software_stage_stats FORCE ROW LEVEL SECURITY;
ALTER TABLE mdm_software_deployment.software_binding_revisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_software_deployment.software_binding_revisions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_software_deployment.software_stage_stats USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY tenant ON mdm_software_deployment.software_binding_revisions USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE TABLE mdm_software_deployment.software_stats_members (
 tenant_id uuid NOT NULL,version uuid NOT NULL,stage integer NOT NULL,
 device text COLLATE "C" NOT NULL,generation uuid NOT NULL,target jsonb NOT NULL,
 counts jsonb NOT NULL CHECK(octet_length(counts::text)<=4096),waiting_until bigint,
 PRIMARY KEY(tenant_id,version,stage,device)
);
CREATE INDEX software_stats_expirations ON mdm_software_deployment.software_stats_members(tenant_id,version,stage,generation,waiting_until,device) WHERE waiting_until IS NOT NULL;
CREATE TABLE mdm_software_deployment.software_result_changes (
 tenant_id uuid NOT NULL,policy uuid NOT NULL,device text COLLATE "C" NOT NULL,revision bigint NOT NULL CHECK(revision>0),
 PRIMARY KEY(tenant_id,policy,device)
);
CREATE INDEX software_result_changes_cursor ON mdm_software_deployment.software_result_changes(tenant_id,policy,revision);
CREATE TABLE mdm_software_deployment.software_binding_changes (
 tenant_id uuid NOT NULL,device text COLLATE "C" NOT NULL,revision bigint NOT NULL CHECK(revision>0),
 PRIMARY KEY(tenant_id,device)
);
CREATE INDEX software_binding_changes_cursor ON mdm_software_deployment.software_binding_changes(tenant_id,revision);
ALTER TABLE mdm_software_deployment.software_stats_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_software_deployment.software_stats_members FORCE ROW LEVEL SECURITY;
ALTER TABLE mdm_software_deployment.software_result_changes ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_software_deployment.software_result_changes FORCE ROW LEVEL SECURITY;
ALTER TABLE mdm_software_deployment.software_binding_changes ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_software_deployment.software_binding_changes FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_software_deployment.software_stats_members USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY tenant ON mdm_software_deployment.software_result_changes USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY tenant ON mdm_software_deployment.software_binding_changes USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE FUNCTION mdm_software_deployment.advance_software_results() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE p uuid; v bigint;
BEGIN
 IF TG_OP='UPDATE' AND NEW.state IS NOT DISTINCT FROM OLD.state AND NEW.result IS NOT DISTINCT FROM OLD.result THEN RETURN NEW; END IF;
 INSERT INTO mdm_software_deployment.policy_recovery(tenant_id,policy,stats_revision) SELECT NEW.tenant_id,policy,1 FROM mdm_policy.versions WHERE tenant_id=NEW.tenant_id AND id=NEW.policy_version AND frozen->>'kind'='software'
 ON CONFLICT(tenant_id,policy) DO UPDATE SET stats_revision=mdm_software_deployment.policy_recovery.stats_revision+1 RETURNING policy,stats_revision INTO p,v;
 IF FOUND THEN INSERT INTO mdm_software_deployment.software_result_changes VALUES(NEW.tenant_id,p,NEW.device,v) ON CONFLICT(tenant_id,policy,device) DO UPDATE SET revision=EXCLUDED.revision; END IF;
 RETURN NEW;
END;$$;
CREATE FUNCTION mdm_software_deployment.advance_software_bindings() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE t uuid; d text; v bigint;
BEGIN
 IF TG_OP='UPDATE' AND NEW IS NOT DISTINCT FROM OLD THEN RETURN NEW; END IF;
 t=coalesce(NEW.tenant_id,OLD.tenant_id);
 INSERT INTO mdm_software_deployment.software_binding_revisions VALUES(t,1) ON CONFLICT(tenant_id) DO UPDATE SET revision=mdm_software_deployment.software_binding_revisions.revision+1 RETURNING revision INTO v;
 SELECT device INTO d FROM mdm_access.registrations WHERE tenant_id=t AND id=coalesce(NEW.registration,OLD.registration);
 IF d IS NOT NULL THEN INSERT INTO mdm_software_deployment.software_binding_changes VALUES(t,d,v) ON CONFLICT(tenant_id,device) DO UPDATE SET revision=EXCLUDED.revision; END IF;
 RETURN coalesce(NEW,OLD);
END;$$;
REVOKE ALL ON FUNCTION mdm_software_deployment.advance_software_results(),mdm_software_deployment.advance_software_bindings() FROM PUBLIC;
CREATE TRIGGER software_results AFTER INSERT OR UPDATE OF state,result ON mdm_software_deployment.action_runs FOR EACH ROW EXECUTE FUNCTION mdm_software_deployment.advance_software_results();

GRANT UPDATE(request) ON mdm_software_deployment.operations TO mdm_command_runtime;

-- A recovery identity hashes explicit UTF-8, independent of client_encoding.
-- PostgreSQL marks textsend STABLE because its wire bytes depend on that setting;
-- convert_to with this fixed destination is deterministic for the stored text.
CREATE FUNCTION mdm_software_deployment.recovery_key(p_device text) RETURNS text
 LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE SET search_path TO 'pg_catalog'
 AS $$ SELECT encode(sha256(convert_to(p_device,'UTF8')),'hex'); $$;
REVOKE ALL ON FUNCTION mdm_software_deployment.recovery_key(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mdm_software_deployment.recovery_key(text) TO mdm_command_runtime,mdm_policy_runtime;
CREATE INDEX command_device_recovery ON mdm_software_deployment.device_recovery(tenant_id,mdm_software_deployment.recovery_key(device));

CREATE TABLE mdm_software_deployment.agent_install_inputs(
 tenant_id uuid NOT NULL,device text NOT NULL,input_revision bigint NOT NULL DEFAULT 1 CHECK(input_revision>0),observed_revision bigint NOT NULL DEFAULT 0 CHECK(observed_revision>=0),
 PRIMARY KEY(tenant_id,device),FOREIGN KEY(tenant_id,device) REFERENCES mdm_access.devices(tenant_id,id)
);
ALTER TABLE mdm_software_deployment.agent_install_inputs ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_software_deployment.agent_install_inputs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_software_deployment.agent_install_inputs USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE INDEX agent_install_input_recovery ON mdm_software_deployment.agent_install_inputs(tenant_id,mdm_software_deployment.recovery_key(device));
GRANT SELECT,INSERT ON mdm_software_deployment.agent_install_inputs TO mdm_command_runtime,mdm_policy_runtime;
GRANT UPDATE(input_revision,observed_revision) ON mdm_software_deployment.agent_install_inputs TO mdm_command_runtime;
GRANT UPDATE(input_revision) ON mdm_software_deployment.agent_install_inputs TO mdm_policy_runtime;
