BEGIN;
CREATE SCHEMA mdm_policy_projection;
REVOKE ALL ON SCHEMA mdm_policy_projection FROM PUBLIC;
-- A narrow owner projection. Callers never decode aggregate/candidate documents.
CREATE FUNCTION mdm_policy_projection.execution_admission(p_policy text,p_candidate text,p_revision bigint,p_saved boolean)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $admission$
SELECT EXISTS(
 SELECT 1 FROM mdm_policy.candidates c JOIN mdm_policy.aggregates a
 ON (a.tenant_id,a.id)=(c.tenant_id,c.policy)
 WHERE c.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
 AND c.id=p_candidate AND c.policy=p_policy AND a.revision=p_revision
 AND CASE WHEN p_saved THEN c.phase='saved' AND EXISTS(
  SELECT 1 FROM mdm_policy.current_plans p WHERE (p.tenant_id,p.policy,p.candidate)=(c.tenant_id,c.policy,c.id))
 ELSE c.phase='ready' AND c.expected_revision=p_revision END
 AND NOT EXISTS(SELECT 1 FROM mdm_policy.candidate_references r
 LEFT JOIN mdm_policy.reference_heads h ON (h.tenant_id,h.id)=(r.tenant_id,r.reference)
 WHERE (r.tenant_id,r.candidate)=(c.tenant_id,c.id)
 AND (h.revision IS NULL OR h.revision<>r.revision OR h.observed_input<h.required_input)))
$admission$;
REVOKE ALL ON FUNCTION mdm_policy_projection.execution_admission(text,text,bigint,boolean) FROM PUBLIC;
COMMIT;
