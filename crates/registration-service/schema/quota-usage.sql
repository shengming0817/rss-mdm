-- One read snapshot of active registrations and live reservations. Renewal/recovery
-- retain the original registration; organization authority is exempt from personal quotas.
WITH agent AS (
 SELECT g.device,g.id,g.expires_at,
 EXISTS(SELECT 1 FROM mdm_access.registrations r WHERE r.tenant_id=g.tenant_id AND r.agent_grant_id=g.id AND r.state='active') AS active,
 g.state IN('available','consumed') AND g.expires_at>clock_timestamp() AND
 NOT EXISTS(SELECT 1 FROM mdm_access.registrations r WHERE r.tenant_id=g.tenant_id AND r.agent_grant_id=g.id) AS reserved
 FROM mdm_access.agent_grants g
 WHERE g.tenant_id=$1::uuid AND g.instance=$2 AND g.actor=$3 AND g.source IN('download','browser')
), native AS (
 SELECT g.device,q.id,q.source,q.expires_at,
 EXISTS(SELECT 1 FROM mdm_access.registrations r WHERE r.tenant_id=q.tenant_id AND r.request_id=q.id AND r.state='active' AND r.purpose='primary') AS active,
 q.state='pending' AND q.expires_at>clock_timestamp() AND
 NOT EXISTS(SELECT 1 FROM mdm_access.registrations r WHERE r.tenant_id=q.tenant_id AND r.request_id=q.id AND r.purpose='primary') AS reserved
 FROM mdm_access.requests q JOIN mdm_access.grants g ON(g.tenant_id,g.id)=(q.tenant_id,q.grant_id)
 WHERE q.tenant_id=$1::uuid AND g.instance=$2 AND g.actor=$3 AND q.self_service
), usage AS (
 SELECT 'agent' AS channel,device,id,expires_at,active,reserved FROM agent
 UNION ALL
 SELECT CASE source WHEN 'mdm.windows' THEN 'windows_mdm' ELSE 'macos_mdm' END,device,id,expires_at,active,reserved FROM native
)
SELECT channel,count(*) FILTER(WHERE active)::bigint AS active,count(*) FILTER(WHERE reserved)::bigint AS reserved FROM usage GROUP BY channel
