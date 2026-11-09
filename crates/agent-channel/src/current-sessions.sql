SELECT b.tenant_id,i.instance_id AS installation,r.id AS device,
 b.platform,b.capabilities,b.execution_context
FROM mdm_agent.bindings b
JOIN mdm_access.devices r ON (r.tenant_id,r.id)=(b.tenant_id,b.device)
CROSS JOIN public.mdm_installation i
WHERE b.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
 AND r.channel='agent' AND r.purpose='primary' AND r.state='active' AND r.retirement IS NULL
 AND EXISTS(SELECT FROM mdm_access.credentials k JOIN mdm_access.certificate_issuances c ON(c.tenant_id,c.credential)=(k.tenant_id,k.id)
  WHERE (k.tenant_id,k.device)=(r.tenant_id,r.id) AND k.state='active' AND k.purpose='primary'
   AND c.not_before<=extract(epoch FROM statement_timestamp()) AND c.not_after>extract(epoch FROM statement_timestamp()))
