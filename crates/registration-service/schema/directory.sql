-- Fixed registration directory relation; caller authorization precedes paging.
BEGIN;
-- Raw narrow source rows, before deduplication or value decoding. UNION ALL
-- allows the caller's overflow probe to stop at its explicit source-row budget.
CREATE VIEW mdm_access.directory_inputs WITH (security_barrier=true) AS
SELECT tenant_id,NULL::timestamptz AS expires_at FROM mdm_access.devices WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
UNION ALL
SELECT tenant_id,CASE WHEN state='pending' THEN expires_at END AS expires_at FROM mdm_access.requests WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
UNION ALL
SELECT tenant_id,NULL::timestamptz AS expires_at FROM mdm_access.grants WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
UNION ALL
SELECT tenant_id,NULL::timestamptz AS expires_at FROM mdm_access.registrations WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
UNION ALL
SELECT tenant_id,NULL::timestamptz AS expires_at FROM mdm_access.credentials WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
UNION ALL
SELECT tenant_id,NULL::timestamptz AS expires_at FROM mdm_access.agent_grants WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
UNION ALL
SELECT tenant_id,NULL::timestamptz AS expires_at FROM mdm_access.registration_users WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
UNION ALL
SELECT tenant_id,NULL::timestamptz AS expires_at FROM mdm_access.report_sources WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid;
REVOKE ALL ON mdm_access.directory_inputs FROM PUBLIC;
GRANT SELECT ON mdm_access.directory_inputs TO mdm_access,mdm_identity_runtime;
CREATE VIEW mdm_access.directory_metadata WITH (security_barrier=true) AS

WITH targets AS (
 SELECT id FROM mdm_access.devices WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
 UNION SELECT g.device FROM mdm_access.requests q JOIN mdm_access.grants g ON(g.tenant_id,g.id)=(q.tenant_id,q.grant_id)
 WHERE q.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND q.issuance_operation IS NOT NULL
), visible AS (
 SELECT id FROM targets
), heads AS (
 SELECT d.id,
 CASE WHEN EXISTS(SELECT 1 FROM mdm_access.registrations r JOIN mdm_access.credentials c ON(c.tenant_id,c.registration)=(r.tenant_id,r.id) WHERE r.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND r.device=d.id AND r.state='active' AND c.state='active') THEN 'active'
 WHEN EXISTS(SELECT 1 FROM mdm_access.requests q JOIN mdm_access.grants g ON(g.tenant_id,g.id)=(q.tenant_id,q.grant_id) WHERE q.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND g.device=d.id AND q.state='pending' AND q.expires_at>statement_timestamp() AND NOT EXISTS(SELECT 1 FROM mdm_access.registrations r WHERE (r.tenant_id,r.request_id)=(q.tenant_id,q.id))) THEN 'pending'
 WHEN EXISTS(SELECT 1 FROM mdm_access.registrations r WHERE r.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND r.device=d.id AND r.state='revoked') THEN 'revoked'
 WHEN EXISTS(SELECT 1 FROM mdm_access.registrations r WHERE r.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND r.device=d.id AND r.state='superseded') THEN 'superseded'
 WHEN EXISTS(SELECT 1 FROM mdm_access.devices r WHERE r.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND r.id=d.id) THEN 'registered'
 WHEN EXISTS(SELECT 1 FROM mdm_access.requests q JOIN mdm_access.grants g ON(g.tenant_id,g.id)=(q.tenant_id,q.grant_id) WHERE q.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND g.device=d.id AND q.state='cancelled') THEN 'cancelled'
 ELSE 'expired' END AS status
 FROM visible d
)
SELECT nullif(current_setting('rss.tenant_id',true),'')::uuid AS tenant_id,id,status FROM heads;
REVOKE ALL ON mdm_access.directory_metadata FROM PUBLIC;
GRANT SELECT ON mdm_access.directory_metadata TO mdm_access,mdm_identity_runtime;
CREATE VIEW mdm_access.directory_channels WITH (security_barrier=true) AS
SELECT DISTINCT ON(r.tenant_id,r.device,r.channel) r.tenant_id,r.device,r.channel,r.id,r.generation,r.state,r.last_communication_received_at,q.windows_profile,coalesce(q.source,'agent.builtin') AS source,
 CASE q.source WHEN 'mdm.windows' THEN 'windows' WHEN 'mdm.apple' THEN 'macos' ELSE g.platform END AS platform
FROM mdm_access.registrations r LEFT JOIN mdm_access.requests q ON(q.tenant_id,q.id)=(r.tenant_id,r.request_id)
LEFT JOIN mdm_access.agent_grants g ON(g.tenant_id,g.id)=(r.tenant_id,r.agent_grant_id)
WHERE r.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND r.purpose='primary'
ORDER BY r.tenant_id,r.device,r.channel,r.generation DESC;
CREATE VIEW mdm_access.directory_enrollments WITH (security_barrier=true) AS
SELECT DISTINCT ON(q.tenant_id,g.device,q.source) q.tenant_id,g.device,q.source,q.id,q.state,q.expires_at,
 CASE q.source WHEN 'mdm.windows' THEN 'windows' WHEN 'mdm.apple' THEN 'macos' END AS platform
FROM mdm_access.requests q JOIN mdm_access.grants g ON(g.tenant_id,g.id)=(q.tenant_id,q.grant_id)
WHERE q.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND q.issuance_operation IS NOT NULL
ORDER BY q.tenant_id,g.device,q.source,q.expires_at DESC,q.id DESC;
REVOKE ALL ON mdm_access.directory_channels,mdm_access.directory_enrollments FROM PUBLIC;
GRANT SELECT ON mdm_access.directory_channels,mdm_access.directory_enrollments TO mdm_access,mdm_identity_runtime;
CREATE VIEW mdm_access.directory_endpoints WITH (security_barrier=true) AS
SELECT nullif(current_setting('rss.tenant_id',true),'')::uuid AS tenant_id,d.id,d.status,jsonb_build_object('id',d.id,'status',d.status,
 'primaryMdmRegistration',(SELECT jsonb_build_object('registrationId',r.id,'generation',r.generation,'source',q.source) FROM mdm_access.registrations r JOIN mdm_access.requests q ON(q.tenant_id,q.id)=(r.tenant_id,r.request_id) WHERE r.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND r.device=d.id AND r.channel='mdm' AND r.purpose='primary' AND r.state='active'),
 'channels',coalesce((SELECT jsonb_agg(jsonb_build_object('registrationId',r.id,'channel',r.channel,'generation',r.generation,'status',r.state,'source',r.source,'platform',r.platform,'lastCommunicationReceivedAt',floor(extract(epoch FROM r.last_communication_received_at))::bigint,
 'children',coalesce((SELECT jsonb_agg(jsonb_build_object('registrationId',child.id,'purpose',child.purpose,'generation',child.generation,'status',child.state,'ready',child.ready,'parentRegistrationId',child.parent_id,'parentGeneration',child.parent_generation) ORDER BY child.purpose) FROM
 (SELECT DISTINCT ON(c.purpose) c.id,c.purpose,c.generation,c.state,c.ready,c.parent_id,c.parent_generation FROM mdm_access.registrations c WHERE c.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND c.device=d.id AND c.parent_id=r.id AND c.parent_generation=r.generation ORDER BY c.purpose,c.generation DESC) child),'[]'::jsonb),
 'userContext',CASE WHEN r.windows_profile='Full' THEN jsonb_build_object('id',r.id,'parentRegistrationId',r.id,'parentGeneration',r.generation,'registrationStatus',r.state) END) ORDER BY r.channel) FROM
 mdm_access.directory_channels r WHERE r.tenant_id=d.tenant_id AND r.device=d.id),'[]'::jsonb),
 'enrollments',coalesce((SELECT jsonb_agg(jsonb_build_object('enrollmentId',q.id,'source',q.source,'platform',CASE q.source WHEN 'mdm.windows' THEN 'windows' WHEN 'mdm.apple' THEN 'macos' END,'status',CASE WHEN q.state='pending' AND q.expires_at<=statement_timestamp() THEN 'expired' ELSE q.state END,'expiresAt',floor(extract(epoch FROM q.expires_at))::bigint) ORDER BY q.source) FROM
 mdm_access.directory_enrollments q WHERE q.tenant_id=d.tenant_id AND q.device=d.id),'[]'::jsonb)) AS summary FROM mdm_access.directory_metadata d;
REVOKE ALL ON mdm_access.directory_endpoints FROM PUBLIC;
GRANT SELECT ON mdm_access.directory_endpoints TO mdm_access,mdm_identity_runtime;

CREATE VIEW mdm_access.directory_users WITH (security_barrier=true) AS
SELECT coalesce(r.tenant_id,u.tenant_id) AS tenant_id,coalesce(r.device,u.device) AS device,
 CASE WHEN r.instance IS NOT NULL AND r.principal IS NOT NULL THEN
  jsonb_build_object('tenantId',r.tenant_id,'instanceId',r.instance,'principalId',r.principal) END AS registration_user,
 coalesce(r.revision,0) AS registration_revision,u.session_reference,
 coalesce(u.revision,0) AS current_revision,u.confirmed_at,
 qualified.valid_until IS NOT NULL AS registration_valid,qualified.valid_until
FROM mdm_access.registration_users r FULL JOIN mdm_access.current_users u USING(tenant_id,device)
LEFT JOIN LATERAL (
 SELECT min(least(i.not_after,p.valid_until)) AS valid_until
 FROM mdm_access.registrations g JOIN mdm_access.credentials k ON(k.tenant_id,k.registration)=(g.tenant_id,g.id)
 JOIN mdm_access.agent_issuances i ON(i.tenant_id,i.credential)=(k.tenant_id,k.id)
 JOIN mdm_pki.current_certificates p ON p.tenant_id=k.tenant_id AND p.purpose='agent' AND p.fingerprint=decode(k.locator,'hex')
 WHERE g.tenant_id=u.tenant_id AND g.id=u.registration AND g.device=u.device AND g.generation=u.generation
  AND g.channel='agent' AND g.purpose='primary' AND g.state='active' AND k.state='active'
  AND i.not_before<=extract(epoch FROM statement_timestamp()) AND i.not_after>extract(epoch FROM statement_timestamp())
) qualified ON true
WHERE coalesce(r.tenant_id,u.tenant_id)=NULLIF(current_setting('rss.tenant_id',true),'')::uuid;
REVOKE ALL ON mdm_access.directory_users FROM PUBLIC;
GRANT SELECT ON mdm_access.directory_users TO mdm_access,mdm_identity_runtime;
CREATE INDEX directory_registration_channel ON mdm_access.registrations(tenant_id,device,channel,purpose,generation DESC);
CREATE INDEX directory_grant_device ON mdm_access.grants(tenant_id,device,id);
CREATE INDEX directory_request_expiry ON mdm_access.requests(tenant_id,expires_at) WHERE state='pending';
CREATE TABLE mdm_access.directory_revisions(tenant_id uuid PRIMARY KEY,revision bigint NOT NULL CHECK(revision>0));
ALTER TABLE mdm_access.directory_revisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_access.directory_revisions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_access.directory_revisions USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON mdm_access.directory_revisions FROM PUBLIC;
GRANT SELECT ON mdm_access.directory_revisions TO mdm_access;
CREATE FUNCTION mdm_access.advance_directory_revision() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='UPDATE' AND NEW IS NOT DISTINCT FROM OLD THEN RETURN NEW; END IF;
 INSERT INTO mdm_access.directory_revisions VALUES(CASE WHEN TG_OP='DELETE' THEN OLD.tenant_id ELSE NEW.tenant_id END,1)
 ON CONFLICT(tenant_id) DO UPDATE SET revision=mdm_access.directory_revisions.revision+1;
 RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
END $$;
REVOKE ALL ON FUNCTION mdm_access.advance_directory_revision() FROM PUBLIC;
CREATE TRIGGER identity_directory_revision AFTER INSERT OR UPDATE OR DELETE ON mdm_access.devices FOR EACH ROW EXECUTE FUNCTION mdm_access.advance_directory_revision();
CREATE TRIGGER identity_directory_revision AFTER INSERT OR UPDATE OR DELETE ON mdm_access.registrations FOR EACH ROW EXECUTE FUNCTION mdm_access.advance_directory_revision();
CREATE TRIGGER identity_directory_revision AFTER INSERT OR UPDATE OR DELETE ON mdm_access.credentials FOR EACH ROW EXECUTE FUNCTION mdm_access.advance_directory_revision();
CREATE TRIGGER identity_directory_revision AFTER INSERT OR UPDATE OR DELETE ON mdm_access.grants FOR EACH ROW EXECUTE FUNCTION mdm_access.advance_directory_revision();
CREATE TRIGGER identity_directory_revision AFTER INSERT OR UPDATE OR DELETE ON mdm_access.requests FOR EACH ROW EXECUTE FUNCTION mdm_access.advance_directory_revision();
CREATE TRIGGER identity_directory_revision AFTER INSERT OR UPDATE OR DELETE ON mdm_access.agent_grants FOR EACH ROW EXECUTE FUNCTION mdm_access.advance_directory_revision();
COMMIT;
