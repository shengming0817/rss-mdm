BEGIN;
CREATE TABLE mdm_recovery.native_actions (
    tenant_id uuid NOT NULL
  , operation uuid NOT NULL
  , device text NOT NULL
  , action text NOT NULL CHECK (action IN ('configure_filevault', 'collect_filevault', 'rotate_filevault', 'set_recovery_lock', 'clear_recovery_lock', 'verify_recovery_lock', 'lock_pin'))
  , inputs_purged boolean NOT NULL DEFAULT FALSE
  , reconciles uuid
  , coordinates jsonb CHECK (octet_length(CAST(coordinates AS text)) <= 4096)
  , recipient text NOT NULL
  , PRIMARY KEY (tenant_id, operation)
  , FOREIGN KEY (tenant_id, device) REFERENCES mdm_access.devices (tenant_id, id)
);
ALTER TABLE mdm_recovery.native_actions ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_recovery.native_actions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_recovery.native_actions USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);


REVOKE ALL ON mdm_recovery.native_actions FROM PUBLIC;
GRANT SELECT,INSERT ON mdm_recovery.native_actions TO mdm_access,mdm_command_runtime;
GRANT UPDATE(inputs_purged) ON mdm_recovery.native_actions TO mdm_command_runtime;
COMMIT;
BEGIN;
SET LOCAL check_function_bodies=false;
CREATE FUNCTION mdm_recovery_tasks.native_status(p_operation uuid) RETURNS text
 LANGUAGE sql SECURITY DEFINER SET search_path TO 'pg_catalog'
 AS $$
 SELECT d.status FROM mdm_recovery_tasks.operations o
 JOIN rss_device_command.commands d ON(d.tenant_id,d.command_id)=(o.tenant_id,o.id::text)
 WHERE o.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
 AND o.id=p_operation;
$$;

REVOKE ALL ON FUNCTION mdm_recovery_tasks.native_status(uuid) FROM PUBLIC;

-- The registration owner participates on its original audit connection. Narrow
-- product functions preserve the shared command component's exclusive runtime ACL.
CREATE FUNCTION mdm_recovery_tasks.retirement_commands(p_device text, p_after text) RETURNS SETOF rss_device_command.commands
 LANGUAGE sql SECURITY DEFINER SET search_path TO 'pg_catalog'
 AS $$
 SELECT a.device_id FROM (
  SELECT DISTINCT d.device_id FROM mdm_recovery_tasks.operations o
  JOIN rss_device_command.commands d ON(d.tenant_id,d.command_id)=(o.tenant_id,o.id::text)
  JOIN mdm_access.devices r ON(r.tenant_id,r.id)=(o.tenant_id,o.device)
  WHERE o.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
   AND o.device=p_device AND (r.state<>'active' OR (r.retirement IS NOT NULL AND NOT EXISTS(SELECT 1 FROM mdm_devices.retirement_work w WHERE(w.tenant_id,w.execution)=(o.tenant_id,o.id)) AND NOT EXISTS(SELECT 1 FROM mdm_apple.attempts a WHERE(a.tenant_id,a.operation)=(o.tenant_id,o.id) AND a.phase='execute' AND a.state<>'pending'))) AND d.terminal_at IS NULL
  ORDER BY d.device_id
 ) scope CROSS JOIN LATERAL rss_device_command.lock_authority(nullif(current_setting('rss.tenant_id',true),'')::uuid,scope.device_id) a;
 SELECT d.* FROM mdm_recovery_tasks.operations o
 JOIN rss_device_command.commands d ON(d.tenant_id,d.command_id)=(o.tenant_id,o.id::text)
 JOIN mdm_access.devices r ON(r.tenant_id,r.id)=(o.tenant_id,o.device)
 WHERE o.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
  AND o.device=p_device AND (r.state<>'active' OR (r.retirement IS NOT NULL AND NOT EXISTS(SELECT 1 FROM mdm_devices.retirement_work w WHERE(w.tenant_id,w.execution)=(o.tenant_id,o.id)) AND NOT EXISTS(SELECT 1 FROM mdm_apple.attempts a WHERE(a.tenant_id,a.operation)=(o.tenant_id,o.id) AND a.phase='execute' AND a.state<>'pending'))) AND d.terminal_at IS NULL
  AND d.command_id COLLATE "C" > p_after ORDER BY d.command_id COLLATE "C" LIMIT 64;
$$;

REVOKE ALL ON FUNCTION mdm_recovery_tasks.retirement_commands(text,text) FROM PUBLIC;

CREATE FUNCTION mdm_recovery_tasks.save_retired_command(p_device text, p_run uuid, p_previous bigint, p_terminal bigint) RETURNS boolean
 LANGUAGE sql SECURITY DEFINER SET search_path TO 'pg_catalog'
 AS $$
 SELECT a.device_id FROM mdm_recovery_tasks.operations o
 JOIN rss_device_command.commands d ON(d.tenant_id,d.command_id)=(o.tenant_id,o.id::text)
 JOIN mdm_access.devices r ON(r.tenant_id,r.id)=(o.tenant_id,o.device)
 CROSS JOIN LATERAL rss_device_command.lock_authority(o.tenant_id,d.device_id) a
 WHERE o.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
  AND o.device=p_device AND o.id=p_run AND (r.state<>'active' OR (r.retirement IS NOT NULL AND NOT EXISTS(SELECT 1 FROM mdm_devices.retirement_work w WHERE(w.tenant_id,w.execution)=(o.tenant_id,o.id)) AND NOT EXISTS(SELECT 1 FROM mdm_apple.attempts a WHERE(a.tenant_id,a.operation)=(o.tenant_id,o.id) AND a.phase='execute' AND a.state<>'pending')));
 SELECT coalesce((SELECT rss_device_command.save(d.tenant_id,d.device_id,d.command_id,p_previous,'cancelled',d.published_at,d.received_at,p_terminal)
 FROM mdm_recovery_tasks.operations o
 JOIN rss_device_command.commands d ON(d.tenant_id,d.command_id)=(o.tenant_id,o.id::text)
 JOIN mdm_access.devices r ON(r.tenant_id,r.id)=(o.tenant_id,o.device)
 WHERE o.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
  AND o.device=p_device AND o.id=p_run AND (r.state<>'active' OR (r.retirement IS NOT NULL AND NOT EXISTS(SELECT 1 FROM mdm_devices.retirement_work w WHERE(w.tenant_id,w.execution)=(o.tenant_id,o.id)) AND NOT EXISTS(SELECT 1 FROM mdm_apple.attempts a WHERE(a.tenant_id,a.operation)=(o.tenant_id,o.id) AND a.phase='execute' AND a.state<>'pending')))
  AND d.version=p_previous AND d.terminal_at IS NULL),false);
$$;

REVOKE ALL ON FUNCTION mdm_recovery_tasks.save_retired_command(text,uuid,bigint,bigint) FROM PUBLIC;

CREATE TABLE mdm_recovery_tasks.device_recovery (
 tenant_id uuid NOT NULL,device text NOT NULL,authority_epoch bigint NOT NULL CHECK(authority_epoch>0),recovery_after text,
 PRIMARY KEY(tenant_id,device)
);

ALTER TABLE mdm_recovery_tasks.device_recovery ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_recovery_tasks.device_recovery FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant ON mdm_recovery_tasks.device_recovery USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);

GRANT SELECT,INSERT ON mdm_recovery_tasks.device_recovery TO mdm_command_runtime;

GRANT UPDATE(authority_epoch,recovery_after) ON mdm_recovery_tasks.device_recovery TO mdm_command_runtime;

CREATE TABLE mdm_recovery_tasks.operations (
    tenant_id uuid NOT NULL
  , id uuid NOT NULL
  , device text NOT NULL
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
  , CONSTRAINT operation_authority_source CHECK (authority ->> 'device' = device
                                             AND authority ->> 'registration' = CAST(device AS text)
                                             AND authority ->> 'operation' = CAST(id AS text))
  , CONSTRAINT operations_authority_check CHECK (octet_length(CAST(authority AS text)) <= 1048576)
  , CONSTRAINT operations_dispatch_fingerprint_check CHECK (octet_length(dispatch_fingerprint) = 32)
  , CONSTRAINT operations_epoch_check CHECK (epoch > 0)
  , CONSTRAINT operations_fingerprint_check CHECK (octet_length(fingerprint) = 32)
  , CONSTRAINT operations_generation_check CHECK (generation > 0)
  , CONSTRAINT operations_request_check CHECK (octet_length(request) BETWEEN 68 AND 33554500)
  , CONSTRAINT operations_revision_check CHECK (revision > 0)
);

ALTER TABLE ONLY mdm_recovery_tasks.operations FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_recovery_tasks.requests (
    tenant_id uuid NOT NULL,
    actor text NOT NULL CHECK(length(actor)>0),
    id uuid NOT NULL,
    operation uuid NOT NULL,
    fingerprint bytea NOT NULL,
    response jsonb NOT NULL,
    CONSTRAINT requests_fingerprint_check CHECK ((octet_length(fingerprint) = 32))
);

ALTER TABLE ONLY mdm_recovery_tasks.requests FORCE ROW LEVEL SECURITY;

ALTER TABLE ONLY mdm_recovery_tasks.operations
    ADD CONSTRAINT operations_pkey PRIMARY KEY (tenant_id, id);

ALTER TABLE ONLY mdm_recovery_tasks.requests
    ADD CONSTRAINT requests_pkey PRIMARY KEY (tenant_id, actor, id);

ALTER TABLE mdm_recovery_tasks.operations ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_recovery_tasks.requests ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant ON mdm_recovery_tasks.operations USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_recovery_tasks.requests USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

-- Actual native wire ranges within one logical attempt; original input remains on the operation.

-- A recovery identity hashes explicit UTF-8, independent of client_encoding.
-- PostgreSQL marks textsend STABLE because its wire bytes depend on that setting;
-- convert_to with this fixed destination is deterministic for the stored text.
CREATE FUNCTION mdm_recovery_tasks.recovery_key(p_device text) RETURNS text
 LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE SET search_path TO 'pg_catalog'
 AS $$ SELECT encode(sha256(convert_to(p_device,'UTF8')),'hex'); $$;

REVOKE ALL ON FUNCTION mdm_recovery_tasks.recovery_key(text) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION mdm_recovery_tasks.recovery_key(text) TO mdm_access,mdm_policy_runtime,mdm_command_runtime;

CREATE INDEX command_device_recovery ON mdm_recovery_tasks.device_recovery(tenant_id,mdm_recovery_tasks.recovery_key(device));
COMMIT;
