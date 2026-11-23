-- Observe the selected version and its shared cooldown once for this claim.
WITH material AS MATERIALIZED (
  SELECT mdm_wns.provider_wait(w.revision) AS wait_seconds
  FROM mdm_wns.versions w JOIN mdm_wns.heads h
    ON (h.tenant_id,h.desired_revision)=(w.tenant_id,w.revision)
  WHERE w.tenant_id=$1::uuid AND w.revision=$6 AND w.selected AND NOT w.revoked AND w.qualified_at IS NOT NULL
  FOR SHARE OF h,w
), claimed AS (
  UPDATE mdm_windows.push_channels SET lease_id=$5,
    outcome=CASE WHEN outcome='rejected' AND material_revision IS DISTINCT FROM $6 THEN NULL ELSE outcome END,
    material_revision=$6, lease_until=clock_timestamp()+interval '30 seconds', settled_id=NULL
  WHERE tenant_id=$1::uuid AND device=$2 AND revision=$3 AND configuration=$4
    AND attempt_until>clock_timestamp() AND next_push<=clock_timestamp()
    AND (lease_until IS NULL OR lease_until<=clock_timestamp())
    AND (outcome IS NULL OR outcome IN ('accepted','retryable','unknown') OR (outcome='rejected' AND material_revision IS DISTINCT FROM $6))
    AND EXISTS(SELECT FROM material WHERE wait_seconds IS NULL)
  RETURNING uri
)
SELECT (SELECT uri FROM claimed),(SELECT wait_seconds FROM material)
