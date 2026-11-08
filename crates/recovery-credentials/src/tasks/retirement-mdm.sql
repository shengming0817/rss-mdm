SELECT a.id,a.state
FROM mdm_recovery_tasks.runs a
WHERE a.tenant_id=$1::uuid AND a.device=$2 AND a.id>$3
 AND a.state->>'execution' IN ('not_started','running','waiting_reboot','unknown')
 AND a.state->>'cancellation'='none'
 AND EXISTS(
  SELECT 1 FROM mdm_access.devices r
  WHERE (r.tenant_id,r.id)=(a.tenant_id,a.device)
   AND (r.state<>'active' OR (
    r.retirement IS NOT NULL
    AND NOT EXISTS(SELECT 1 FROM mdm_devices.retirement_work w
     WHERE (w.tenant_id,w.execution)=(a.tenant_id,a.id))
   ))
 )
ORDER BY a.id LIMIT 64
