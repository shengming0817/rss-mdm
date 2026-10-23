-- Native evidence is interpreted once by Apple; readers share exact current qualification.
BEGIN;
CREATE VIEW mdm_apple.profile_qualifications WITH (security_barrier=true) AS
SELECT p.tenant_id,p.operation,
 CASE WHEN p.dispatched_at IS NOT NULL AND o.accepted AND o.state='acknowledged'
  AND (NOT p.present OR sha256(p.manifest)=p.manifest_cipher_digest AND p.manifest_digest IS NOT NULL)
  AND p.verification_evidence=e.current_evidence THEN p.verification ELSE 'unknown' END AS verification,
 o.id AS observe_id,o.response_digest AS observe_digest,x.id AS execute_id,
 x.response_digest AS execute_digest,e.current_evidence,p.verification_evidence AS evidence
FROM mdm_apple.profiles p
LEFT JOIN LATERAL (
 SELECT id,state,accepted,response_digest,sha256(response) AS cipher
 FROM mdm_apple.attempts a
 WHERE (a.tenant_id,a.operation,a.registration,a.generation,a.user_key)=
  (p.tenant_id,p.operation,p.registration,p.generation,p.user_key) AND a.phase='observe'
 ORDER BY ordinal DESC LIMIT 1
) o ON true
LEFT JOIN LATERAL (
 SELECT id,state,accepted,response_digest
 FROM mdm_apple.attempts a
 WHERE (a.tenant_id,a.operation,a.registration,a.generation,a.user_key)=
  (p.tenant_id,p.operation,p.registration,p.generation,p.user_key) AND a.phase='execute'
 ORDER BY ordinal DESC LIMIT 1
) x ON true
CROSS JOIN LATERAL (
 SELECT jsonb_build_object(
  'profile',jsonb_build_array(p.device,p.user_key,p.registration,p.generation,p.identifier,
    p.profile,p.version,p.present,p.dispatched_at,CASE WHEN sha256(p.manifest)=p.manifest_cipher_digest THEN encode(p.manifest_digest,'hex') ELSE 'unverified' END),
  'observe',jsonb_build_object('id',o.id,'state',o.state,'accepted',o.accepted,
    'digest',encode(o.response_digest,'hex'),'cipher',encode(o.cipher,'hex')),
  'execute',jsonb_build_object('id',x.id,'state',x.state,'accepted',x.accepted,
    'digest',encode(x.response_digest,'hex')),
  'previous',CASE WHEN NOT p.present AND x.accepted AND x.state='error' THEN
   coalesce((SELECT jsonb_agg(jsonb_build_object('operation',old.operation,
     'manifest',CASE WHEN sha256(old.manifest)=old.manifest_cipher_digest THEN encode(old.manifest_digest,'hex') ELSE 'unverified' END) ORDER BY old.operation) FROM (
    SELECT operation,manifest,manifest_digest,manifest_cipher_digest FROM mdm_apple.profiles old
    WHERE old.tenant_id=p.tenant_id AND old.device=p.device AND old.user_key=p.user_key
     AND old.registration=p.registration AND old.generation=p.generation
     AND old.identifier=p.identifier AND old.profile=p.profile AND old.operation<>p.operation
     AND old.retired_at IS NULL AND old.present AND old.observed_at IS NOT NULL
     AND old.dispatched_at IS NOT NULL ORDER BY operation LIMIT 2
   ) old),'[]'::jsonb) ELSE '[]'::jsonb END
 ) AS current_evidence
) e
WHERE p.tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid;
REVOKE ALL ON mdm_apple.profile_qualifications FROM PUBLIC;
COMMIT;
