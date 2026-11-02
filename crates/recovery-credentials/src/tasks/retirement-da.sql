SELECT a.id,a.state
FROM rss_da.credential_runs a
WHERE a.tenant_id=$1::uuid AND a.registration=$2 AND a.id>$3
 AND a.state->>'execution' IN ('not_started','running','waiting_reboot','unknown')
 AND a.state->>'cancellation'='none'
 AND EXISTS(
  SELECT FROM rss_da.agent_delivery d
  WHERE (d.tenant_id,d.agent_device,d.agent_registration,d.agent_generation)=
   (a.tenant_id,a.device,a.registration,a.generation)
   AND a.material_binding @> jsonb_build_object(
    'device',d.da_device,'registration',d.da_registration,'generation',d.da_generation,
    'subject',jsonb_build_object('kind','rss_login'))
   AND NOT d.enabled
  FOR SHARE OF d
 )
ORDER BY a.id LIMIT 64
