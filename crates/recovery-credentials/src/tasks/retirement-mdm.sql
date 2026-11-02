SELECT a.id,a.state
FROM mdm_recovery_tasks.runs a
WHERE a.tenant_id=$1::uuid AND a.registration=$2 AND a.id>$3
 AND a.state->>'execution' IN ('not_started','running','waiting_reboot','unknown')
 AND a.state->>'cancellation'='none'
 AND EXISTS(
  SELECT 1 FROM mdm_access.registrations r
  WHERE (r.tenant_id,r.id)=(a.tenant_id,a.registration)
   AND (r.state<>'active' OR (
    EXISTS(SELECT 1 FROM mdm_access.devices d
     WHERE (d.tenant_id,d.id)=(r.tenant_id,r.device) AND d.retirement IS NOT NULL)
    AND NOT EXISTS(SELECT 1 FROM mdm_devices.retirement_work w
     WHERE (w.tenant_id,w.execution)=(a.tenant_id,a.id))
   ))
 )
ORDER BY a.id LIMIT 64
