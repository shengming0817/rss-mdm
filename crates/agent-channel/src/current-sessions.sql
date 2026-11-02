SELECT b.tenant_id,i.instance_id AS installation,r.device,r.id AS registration,r.generation,
 b.platform,b.capabilities,b.execution_context
FROM mdm_agent.bindings b
JOIN mdm_access.registrations r ON (r.tenant_id,r.id)=(b.tenant_id,b.registration)
JOIN mdm_access.devices d ON (d.tenant_id,d.id)=(r.tenant_id,r.device)
CROSS JOIN public.mdm_installation i
WHERE b.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
 AND r.channel='agent' AND r.purpose='primary' AND r.state='active' AND d.retirement IS NULL
 AND EXISTS(SELECT FROM mdm_access.credentials k JOIN mdm_access.certificate_issuances c ON(c.tenant_id,c.credential)=(k.tenant_id,k.id)
  WHERE (k.tenant_id,k.registration)=(r.tenant_id,r.id) AND k.state='active'
   AND c.not_before<=extract(epoch FROM statement_timestamp()) AND c.not_after>extract(epoch FROM statement_timestamp()))
