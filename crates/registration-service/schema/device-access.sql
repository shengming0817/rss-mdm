-- Device Access association authority. Fresh installation only; never stores OS passwords.
BEGIN;
CREATE TABLE mdm_access.device_access_bindings (
 tenant_id uuid NOT NULL,
 id uuid NOT NULL,
 device text NOT NULL,
 registration uuid NOT NULL,
 registration_generation bigint NOT NULL CHECK(registration_generation>0),
 instance uuid NOT NULL,
 principal uuid NOT NULL,
 generation bigint NOT NULL CHECK(generation>0),
 revision bigint NOT NULL CHECK(revision>0),
 state text NOT NULL CHECK(state IN('pending','active','revoked')),
 account jsonb,
 document jsonb NOT NULL CHECK(octet_length(document::text)<=16384),
 PRIMARY KEY(tenant_id,id),
 FOREIGN KEY(tenant_id,registration) REFERENCES mdm_access.registrations(tenant_id,id),
 FOREIGN KEY(tenant_id,device) REFERENCES mdm_access.devices(tenant_id,id)
);
-- Authority metadata must not permit two live bindings for the same native account.
CREATE UNIQUE INDEX device_access_live_account ON mdm_access.device_access_bindings(tenant_id,device,registration,(account->>'platform'),(coalesce(account->>'sid',account->>'generatedUid'))) WHERE state<>'revoked' AND account IS NOT NULL;
CREATE UNIQUE INDEX device_access_live_person ON mdm_access.device_access_bindings(tenant_id,device,registration,instance,principal) WHERE state<>'revoked';
CREATE INDEX device_access_history ON mdm_access.device_access_bindings(tenant_id,device,registration);
CREATE TABLE mdm_access.device_access_ceremonies (
 tenant_id uuid NOT NULL,
 id uuid NOT NULL,
 device text NOT NULL,
 registration uuid NOT NULL,
 generation bigint NOT NULL CHECK(generation>0),
 instance uuid NOT NULL,
 principal uuid NOT NULL,
 nonce_digest bytea NOT NULL CHECK(octet_length(nonce_digest)=32),
 session jsonb NOT NULL CHECK(octet_length(session::text)<=1024),
 policy uuid NOT NULL,
 policy_version uuid NOT NULL,
 expires_at timestamptz NOT NULL,
 consumed uuid,
 PRIMARY KEY(tenant_id,id),
 FOREIGN KEY(tenant_id,registration) REFERENCES mdm_access.registrations(tenant_id,id)
);
CREATE INDEX device_access_ceremonies_expiry ON mdm_access.device_access_ceremonies(tenant_id,expires_at);
CREATE TABLE mdm_access.device_access_results (
 tenant_id uuid NOT NULL,
 task uuid NOT NULL,
 attempt uuid NOT NULL,
 event uuid NOT NULL,
 binding uuid NOT NULL,
 digest bytea NOT NULL CHECK(octet_length(digest)=32),
 document jsonb NOT NULL CHECK(octet_length(document::text)<=8192),
 PRIMARY KEY(tenant_id,task,attempt,event),
 FOREIGN KEY(tenant_id,binding) REFERENCES mdm_access.device_access_bindings(tenant_id,id)
);
CREATE INDEX device_access_results_binding ON mdm_access.device_access_results(tenant_id,binding);
ALTER TABLE mdm_access.device_access_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_access.device_access_bindings FORCE ROW LEVEL SECURITY;
ALTER TABLE mdm_access.device_access_ceremonies ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_access.device_access_ceremonies FORCE ROW LEVEL SECURITY;
ALTER TABLE mdm_access.device_access_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_access.device_access_results FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_access.device_access_bindings USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY tenant ON mdm_access.device_access_ceremonies USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY tenant ON mdm_access.device_access_results USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON mdm_access.device_access_bindings,mdm_access.device_access_ceremonies,mdm_access.device_access_results TO mdm_access;
GRANT UPDATE(instance,principal,generation,revision,state,account,document) ON mdm_access.device_access_bindings TO mdm_access;
GRANT UPDATE(consumed) ON mdm_access.device_access_ceremonies TO mdm_access;
CREATE POLICY expired_only ON mdm_access.device_access_ceremonies AS RESTRICTIVE FOR DELETE USING(expires_at<clock_timestamp() AND consumed IS NULL);
GRANT DELETE ON mdm_access.device_access_ceremonies TO mdm_access;
GRANT SELECT ON mdm_access.device_access_bindings,mdm_access.device_access_results TO mdm_command_runtime;
GRANT INSERT ON mdm_access.device_access_results TO mdm_command_runtime;
GRANT UPDATE(instance,principal,generation,revision,state,account,document) ON mdm_access.device_access_bindings TO mdm_command_runtime;
CREATE TABLE mdm_access.device_access_subject_denials (
 tenant_id uuid NOT NULL, instance uuid NOT NULL, principal uuid NOT NULL,
 operation uuid NOT NULL, denied boolean NOT NULL,
 PRIMARY KEY(tenant_id,instance,principal)
);
CREATE TABLE mdm_access.device_access_lifecycles (
 tenant_id uuid NOT NULL, operation uuid NOT NULL, actor text NOT NULL, instance text NOT NULL,
 device text NOT NULL, document jsonb NOT NULL CHECK(octet_length(document::text)<=16777216),
 PRIMARY KEY(tenant_id,operation), FOREIGN KEY(tenant_id,device) REFERENCES mdm_access.devices(tenant_id,id)
);
ALTER TABLE mdm_access.device_access_subject_denials ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_access.device_access_subject_denials FORCE ROW LEVEL SECURITY;
ALTER TABLE mdm_access.device_access_lifecycles ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_access.device_access_lifecycles FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_access.device_access_subject_denials USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY tenant ON mdm_access.device_access_lifecycles USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT ON mdm_access.device_access_subject_denials,mdm_access.device_access_lifecycles TO mdm_access,mdm_command_runtime,mdm_identity_runtime;
GRANT INSERT ON mdm_access.device_access_subject_denials,mdm_access.device_access_lifecycles TO mdm_identity_runtime;
GRANT UPDATE(operation,denied) ON mdm_access.device_access_subject_denials TO mdm_identity_runtime;
GRANT UPDATE(document) ON mdm_access.device_access_lifecycles TO mdm_identity_runtime;
COMMIT;

-- Persisted login-readiness predicate. The pure Binding model remains usable without PostgreSQL;
-- every persistent credential consumer evaluates this same owner function.
CREATE FUNCTION mdm_access.access_binding_ready(document jsonb) RETURNS boolean
 LANGUAGE sql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT coalesce(document->>'state'='active' AND document#>>'{configuration,enabled}'='true'
  AND document->'account' IS NOT NULL AND document->'account'<>'null'::jsonb
  AND (document->>'appliedRevision')::bigint=(document->>'revision')::bigint
  AND CASE document#>>'{effect,state}'
   WHEN 'applied' THEN document#>'{effect,mac}' IS NULL OR document#>'{effect,mac}'='null'::jsonb
    OR (document#>>'{effect,mac,secureToken}'='present'
     AND (document#>>'{configuration,mac,authentication}'<>'password' OR
       (document#>>'{effect,mac,passwordSync}'='present' AND document#>>'{effect,mac,keychainSync}'='present'))
     AND (document#>>'{configuration,mac,filevault}'='local' OR (document#>>'{effect,mac,filevaultUnlock}'='present' AND document#>>'{effect,mac,volumeOwner}'='present')))
   ELSE false END,false)
$$;
REVOKE ALL ON FUNCTION mdm_access.access_binding_ready(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mdm_access.access_binding_ready(jsonb) TO mdm_access,mdm_flow_runtime,mdm_command_runtime;
