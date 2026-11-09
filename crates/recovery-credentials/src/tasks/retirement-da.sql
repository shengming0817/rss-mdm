SELECT a.id,a.state
FROM rss_da.credential_runs a
WHERE a.tenant_id=$1::uuid AND a.device=$2 AND a.id>$3
 AND a.state->>'execution' IN ('not_started','running','waiting_reboot','unknown')
 AND a.state->>'cancellation'='none'
 AND EXISTS(
  SELECT FROM rss_da.agent_delivery d
  WHERE (d.tenant_id,d.agent_device)=
   (a.tenant_id,a.device)
   AND a.material_binding @> jsonb_build_object(
    'device',d.da_device,
    'subject',jsonb_build_object('kind','rss_login'))
   AND NOT d.enabled
  FOR SHARE OF d
 )
ORDER BY a.id LIMIT 64
