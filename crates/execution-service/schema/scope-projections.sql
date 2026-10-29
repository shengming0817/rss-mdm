-- Execution owns channel projections, qualification and entry continuity.
BEGIN;
SET LOCAL check_function_bodies=false;
CREATE TABLE mdm_commands.scope_projection_runs (
 tenant_id uuid NOT NULL,id uuid NOT NULL,scope uuid NOT NULL,previous_resolution uuid,next_entry bigint NOT NULL CHECK(next_entry>0),
 phase text NOT NULL CHECK(phase IN('sources','project','ready','published')),
 source_cursor text COLLATE "C",projection_cursor text COLLATE "C",
 channel_hashes jsonb NOT NULL DEFAULT jsonb_build_object('agent',repeat('0',64),'mdm',repeat('0',64)),
 agent_revision bigint NOT NULL DEFAULT 0 CHECK(agent_revision>=0),mdm_revision bigint NOT NULL DEFAULT 0 CHECK(mdm_revision>=0),
 PRIMARY KEY(tenant_id,id)
);
ALTER TABLE mdm_commands.scope_projection_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_commands.scope_projection_runs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_commands.scope_projection_runs USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON mdm_commands.scope_projection_runs TO mdm_flow_runtime;
GRANT UPDATE(phase,source_cursor,projection_cursor,channel_hashes,agent_revision,mdm_revision) ON mdm_commands.scope_projection_runs TO mdm_flow_runtime;
GRANT SELECT ON mdm_commands.scope_projection_runs TO mdm_command_runtime,mdm_access;
CREATE TABLE mdm_commands.scope_channel_results (
 tenant_id uuid NOT NULL,
 run uuid NOT NULL,
 channel text NOT NULL CHECK(channel IN('agent','mdm')),
 device text COLLATE "C" NOT NULL CHECK(octet_length(device)<=256),
 matched boolean NOT NULL,
 pending boolean NOT NULL,
 target jsonb NOT NULL CHECK(octet_length(target::text)<=1024),
 entry_revision bigint NOT NULL CHECK(entry_revision>=0),
 PRIMARY KEY(tenant_id,run,channel,device)
);

ALTER TABLE mdm_commands.scope_channel_results ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_commands.scope_channel_results FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant ON mdm_commands.scope_channel_results USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);

CREATE INDEX scope_channel_results_cursor ON mdm_commands.scope_channel_results(tenant_id,run,((channel||':'||device) COLLATE "C"));

CREATE FUNCTION mdm_commands.guard_scope_channel_result() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE p text;
BEGIN
 SELECT phase INTO STRICT p FROM mdm_commands.scope_projection_runs WHERE tenant_id=NEW.tenant_id AND id=NEW.run;
 IF p NOT IN('sources','project') THEN RAISE EXCEPTION 'scope channel result is immutable' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END;$$;

REVOKE ALL ON FUNCTION mdm_commands.guard_scope_channel_result() FROM PUBLIC;

CREATE TRIGGER scope_channel_result_guard BEFORE INSERT OR UPDATE ON mdm_commands.scope_channel_results FOR EACH ROW EXECUTE FUNCTION mdm_commands.guard_scope_channel_result();

CREATE FUNCTION mdm_commands.channel_admission(p_scope uuid,p_channel text,p_device text) RETURNS jsonb
 LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE tenant uuid:=nullif(current_setting('rss.tenant_id',true),'')::uuid;
 status jsonb; current_run uuid; frozen jsonb; evaluation record; published record;
BEGIN
 IF p_channel NOT IN('agent','mdm') THEN RAISE EXCEPTION 'invalid scope channel' USING ERRCODE='23514'; END IF;
 status=mdm_scope.scope_state(p_scope,NULL);
 IF status->>'state'<>'fresh' THEN RETURN status; END IF;
 SELECT s.resolution,r.input INTO current_run,frozen FROM mdm_scope.scopes s
 JOIN mdm_scope.scope_runs r ON(r.tenant_id,r.id)=(s.tenant_id,s.resolution)
 WHERE s.tenant_id=tenant AND s.id=p_scope AND NOT s.deleted;
 IF NOT FOUND THEN RAISE EXCEPTION 'scope resolution unavailable' USING ERRCODE='23514'; END IF;
 -- The ordinal source identity is the immutable Scope input's identity, never a current group expansion.
 WITH evidence AS MATERIALIZED (
  SELECT m.source,m.unknown,m.input FROM mdm_scope.scope_source_members m
  WHERE m.tenant_id=tenant AND m.run=current_run
   AND m.input->'members' @> jsonb_build_array(jsonb_build_object('device',p_device,'channel',p_channel))
  ORDER BY m.source,m.device LIMIT 16001
 ), evidence_state AS MATERIALIZED (
  SELECT e.source,CASE WHEN e.unknown OR e.input->>'verified' IS DISTINCT FROM 'true' THEN false
   ELSE mdm_devices.object_current(e.input,p_channel) IS NOT NULL END AS valid FROM evidence e
 ), memberships AS (
  SELECT src.value->'reference' AS reference,
   EXISTS(SELECT FROM evidence_state e WHERE e.source=src.ordinal-1 AND e.valid) AS known,
   EXISTS(SELECT FROM evidence_state e WHERE e.source=src.ordinal-1 AND NOT e.valid) AS uncertain
  FROM jsonb_array_elements(frozen->'sources') WITH ORDINALITY src(value,ordinal)
 ), selected AS (
  SELECT *,coalesce(frozen#>'{definition,targets}' @> jsonb_build_array(reference),false) AS target,
   coalesce(frozen#>'{definition,limitations}' @> jsonb_build_array(reference),false) AS limitation,
   coalesce(frozen#>'{definition,exclusions}' @> jsonb_build_array(reference),false) AS exclusion
  FROM memberships
 )
 SELECT (SELECT count(*) FROM evidence)>16000 AS overflow,
  coalesce(bool_or(target AND known),false) AS target_known,
  coalesce(bool_or(target AND NOT known AND uncertain),false) AS target_unknown,
  coalesce(bool_or(limitation AND known),false) AS limit_known,
  coalesce(bool_or(limitation AND NOT known AND uncertain),false) AS limit_unknown,
  coalesce(bool_or(exclusion AND known),false) AS exclude_known,
  coalesce(bool_or(exclusion AND NOT known AND uncertain),false) AS exclude_unknown
 INTO evaluation FROM selected;
 IF evaluation.overflow THEN
  RAISE EXCEPTION 'invalid scope source evidence' USING ERRCODE='23514';
 END IF;
 IF NOT evaluation.target_known AND NOT evaluation.target_unknown THEN
  RETURN jsonb_build_object('state','excluded');
 END IF;
 IF evaluation.exclude_known THEN RETURN jsonb_build_object('state','excluded'); END IF;
 -- A known exclusion wins; genuinely unknown candidates still wait.
 IF NOT evaluation.target_known
  OR (frozen#>'{definition,limitations}' IS NOT NULL AND frozen#>'{definition,limitations}'<>'null'::jsonb
   AND NOT evaluation.limit_known AND evaluation.limit_unknown)
  OR (NOT evaluation.exclude_known AND evaluation.exclude_unknown) THEN
  RETURN jsonb_build_object('state','pending');
 END IF;
 IF evaluation.exclude_known OR (frozen#>'{definition,limitations}' IS NOT NULL
  AND frozen#>'{definition,limitations}'<>'null'::jsonb AND NOT evaluation.limit_known) THEN
  RETURN jsonb_build_object('state','excluded');
 END IF;
 -- A source-algebra match still needs the exact published per-channel admission.
 SELECT matched,pending,entry_revision INTO published FROM mdm_commands.scope_channel_results
 WHERE tenant_id=tenant AND run=current_run AND channel=p_channel AND device=p_device;
 IF FOUND AND published.pending THEN RETURN jsonb_build_object('state','pending'); END IF;
 IF FOUND AND published.matched AND NOT published.pending AND published.entry_revision>0 THEN
  RETURN jsonb_build_object('state','eligible','entry',published.entry_revision);
 END IF;
 RETURN jsonb_build_object('state','excluded');
END $$;

REVOKE ALL ON FUNCTION mdm_commands.channel_admission(uuid,text,text) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION mdm_commands.channel_admission(uuid,text,text) TO mdm_access,mdm_flow_runtime,mdm_command_runtime;
COMMIT;
