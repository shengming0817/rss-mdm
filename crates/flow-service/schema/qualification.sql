-- Lock-free owner kernels shared by query projections and locked admission.
CREATE FUNCTION mdm_planning.scope_state(p_scope uuid, p_device text) RETURNS jsonb
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
DECLARE s record; token record; head record; member record; tenant uuid:=nullif(current_setting('rss.tenant_id',true),'')::uuid;
BEGIN
 SELECT x.deleted,x.revision,x.resolution,r.phase,r.definition_revision,r.asset_watermark,r.input INTO s
 FROM mdm_planning.scopes x LEFT JOIN mdm_planning.scope_runs r ON(r.tenant_id,r.id)=(x.tenant_id,x.resolution)
 WHERE x.tenant_id=tenant AND x.id=p_scope;
 IF NOT FOUND OR s.deleted THEN RETURN jsonb_build_object('state','excluded'); END IF;
 IF s.phase IS DISTINCT FROM 'published' OR s.definition_revision IS DISTINCT FROM s.revision THEN RETURN jsonb_build_object('state','pending'); END IF;
 -- Only explicit definition changes invalidate a complete publication.
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(s.input->'sources') src
 LEFT JOIN mdm_group.groups g ON g.tenant_id=tenant AND g.id=CASE WHEN src->'reference'->>'kind'='group' THEN (src->'reference'->>'id')::uuid END
 LEFT JOIN mdm_group.source_state h ON h.tenant_id=tenant AND h.group_id=g.id
 WHERE src->'reference'->>'kind'='group' AND (g.id IS NULL OR g.deleted OR h.definition_version IS DISTINCT FROM (src->'coordinates'->>'definitionVersion')::bigint))
 THEN RETURN jsonb_build_object('state','pending'); END IF;
 RETURN jsonb_build_object('state','fresh');
END;
$$;

REVOKE ALL ON FUNCTION mdm_planning.scope_state(uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mdm_planning.scope_state(uuid,text) TO mdm_access,mdm_flow_runtime,mdm_command_runtime;

CREATE FUNCTION mdm_planning.channel_admission(p_scope uuid,p_channel text,p_device text) RETURNS jsonb
 LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE tenant uuid:=nullif(current_setting('rss.tenant_id',true),'')::uuid;
 status jsonb; current_run uuid; frozen jsonb; evaluation record; published record;
BEGIN
 IF p_channel NOT IN('agent','mdm') THEN RAISE EXCEPTION 'invalid scope channel' USING ERRCODE='23514'; END IF;
 status=mdm_planning.scope_state(p_scope,NULL);
 IF status->>'state'<>'fresh' THEN RETURN status; END IF;
 SELECT s.resolution,r.input INTO current_run,frozen FROM mdm_planning.scopes s
 JOIN mdm_planning.scope_runs r ON(r.tenant_id,r.id)=(s.tenant_id,s.resolution)
 WHERE s.tenant_id=tenant AND s.id=p_scope AND NOT s.deleted;
 IF NOT FOUND THEN RAISE EXCEPTION 'scope resolution unavailable' USING ERRCODE='23514'; END IF;
 -- The ordinal source identity is the immutable Scope input's identity, never a current group expansion.
 WITH evidence AS MATERIALIZED (
  SELECT m.source,m.unknown,m.input FROM mdm_planning.scope_source_members m
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
 SELECT matched,pending,entry_revision INTO published FROM mdm_planning.scope_channel_results
 WHERE tenant_id=tenant AND run=current_run AND channel=p_channel AND device=p_device;
 IF FOUND AND published.pending THEN RETURN jsonb_build_object('state','pending'); END IF;
 IF FOUND AND published.matched AND NOT published.pending AND published.entry_revision>0 THEN
  RETURN jsonb_build_object('state','eligible','entry',published.entry_revision);
 END IF;
 RETURN jsonb_build_object('state','excluded');
END $$;
REVOKE ALL ON FUNCTION mdm_planning.channel_admission(uuid,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mdm_planning.channel_admission(uuid,text,text) TO mdm_access,mdm_flow_runtime,mdm_command_runtime;
