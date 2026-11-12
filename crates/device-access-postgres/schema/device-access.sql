-- Device Access association authority. Fresh installation only; never stores OS passwords.
BEGIN;
CREATE TABLE rss_da.bindings (
    tenant_id uuid NOT NULL
  , id uuid NOT NULL
  , device uuid NOT NULL
  , instance uuid NOT NULL
  , principal uuid NOT NULL
  , generation bigint NOT NULL CHECK (generation > 0)
  , revision bigint NOT NULL CHECK (revision > 0)
  , state text NOT NULL CHECK (state IN ('pending', 'active', 'revoked'))
  , account jsonb
  , document jsonb NOT NULL CHECK (octet_length(CAST(document AS text)) <= 16384)
  , PRIMARY KEY (tenant_id, id)
  , FOREIGN KEY (tenant_id, device) REFERENCES rss_da.devices (tenant_id, id)
);
-- Authority metadata must not permit two live bindings for the same native account.
CREATE UNIQUE INDEX device_access_live_account
  ON rss_da.bindings (tenant_id
                    , device
                    , (account ->> 'platform')
                    , (COALESCE(account ->> 'sid'
                              , account ->> 'generatedUid')))
  WHERE state <> 'revoked'
    AND account IS NOT NULL;
CREATE UNIQUE INDEX device_access_live_person
  ON rss_da.bindings (tenant_id
                    , device
                    , instance
                    , principal)
  WHERE state <> 'revoked';
CREATE INDEX device_access_history
  ON rss_da.bindings (tenant_id
                    , device);
CREATE TABLE rss_da.ceremonies (
    tenant_id uuid NOT NULL
  , id uuid NOT NULL
  , device uuid NOT NULL
  , instance uuid NOT NULL
  , principal uuid NOT NULL
  , nonce_digest bytea NOT NULL CHECK (octet_length(nonce_digest) = 32)
  , session jsonb NOT NULL CHECK (octet_length(CAST(session AS text)) <= 1024)
  , policy uuid NOT NULL
  , policy_version uuid NOT NULL
  , expires_at timestamptz NOT NULL
  , consumed uuid
  , PRIMARY KEY (tenant_id, id)
  , FOREIGN KEY (tenant_id, device) REFERENCES rss_da.devices (tenant_id, id)
);
CREATE INDEX device_access_ceremonies_expiry ON rss_da.ceremonies(tenant_id,expires_at);
CREATE TABLE rss_da.results (
    tenant_id uuid NOT NULL
  , task uuid NOT NULL
  , attempt uuid NOT NULL
  , event uuid NOT NULL
  , binding uuid NOT NULL
  , digest bytea NOT NULL CHECK (octet_length(digest) = 32)
  , document jsonb NOT NULL CHECK (octet_length(CAST(document AS text)) <= 8192)
  , PRIMARY KEY (tenant_id, task, attempt, event)
  , FOREIGN KEY (tenant_id, binding) REFERENCES rss_da.bindings (tenant_id, id)
);
CREATE INDEX device_access_results_binding ON rss_da.results(tenant_id,binding);
ALTER TABLE rss_da.bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_da.bindings FORCE ROW LEVEL SECURITY;
ALTER TABLE rss_da.ceremonies ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_da.ceremonies FORCE ROW LEVEL SECURITY;
ALTER TABLE rss_da.results ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_da.results FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON rss_da.bindings USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY tenant ON rss_da.ceremonies USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY tenant ON rss_da.results USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON rss_da.bindings,rss_da.ceremonies,rss_da.results TO da_access;
GRANT UPDATE(instance,principal,generation,revision,state,account,document) ON rss_da.bindings TO da_access;
GRANT UPDATE(consumed) ON rss_da.ceremonies TO da_access;
CREATE POLICY expired_only ON rss_da.ceremonies AS RESTRICTIVE FOR DELETE USING(expires_at<clock_timestamp() AND consumed IS NULL);
GRANT DELETE ON rss_da.ceremonies TO da_access;
GRANT SELECT ON rss_da.bindings,rss_da.results TO da_command_runtime;
GRANT SELECT ON rss_da.bindings TO da_policy_runtime;
GRANT INSERT ON rss_da.results TO da_command_runtime;
GRANT UPDATE(instance,principal,generation,revision,state,account,document) ON rss_da.bindings TO da_command_runtime,da_policy_runtime;
CREATE TABLE rss_da.subject_denials (
 tenant_id uuid NOT NULL, instance uuid NOT NULL, principal uuid NOT NULL,
 operation uuid NOT NULL, denied boolean NOT NULL,
 PRIMARY KEY(tenant_id,instance,principal)
);
CREATE TABLE rss_da.lifecycles (
 tenant_id uuid NOT NULL, operation uuid NOT NULL, actor text NOT NULL, instance text NOT NULL,
 device uuid NOT NULL, document jsonb NOT NULL CHECK(octet_length(document::text)<=16777216),
 PRIMARY KEY(tenant_id,operation), FOREIGN KEY(tenant_id,device) REFERENCES rss_da.devices(tenant_id,id)
);
ALTER TABLE rss_da.subject_denials ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_da.subject_denials FORCE ROW LEVEL SECURITY;
ALTER TABLE rss_da.lifecycles ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_da.lifecycles FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON rss_da.subject_denials USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY tenant ON rss_da.lifecycles USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT ON rss_da.subject_denials,rss_da.lifecycles TO da_access,da_identity_runtime;
GRANT INSERT ON rss_da.subject_denials,rss_da.lifecycles TO da_identity_runtime;
GRANT UPDATE(operation,denied) ON rss_da.subject_denials TO da_identity_runtime;
GRANT UPDATE(document) ON rss_da.lifecycles TO da_identity_runtime;
COMMIT;

-- Persisted login-readiness predicate. The pure Binding model remains usable without PostgreSQL;
-- every persistent credential consumer evaluates this same owner function.
CREATE FUNCTION rss_da.access_binding_ready(document jsonb) RETURNS boolean
 LANGUAGE sql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT coalesce(document->>'state'='active' AND document#>>'{configuration,enabled}'='true'
  AND document->'account' IS NOT NULL AND document->'account'<>'null'::jsonb
  AND (document->>'appliedRevision')::bigint=(document->>'revision')::bigint
  AND CASE document#>>'{effect,state}'
   WHEN 'applied' THEN ((document#>>'{account,platform}'='windows')
     AND document#>>'{effect,windows,kind}'=document#>>'{configuration,windows,kind}'
     AND document#>>'{effect,windows,factorGeneration}'=document->>'factorGeneration'
     AND (document#>>'{configuration,windows,kind}'='rss_factor' OR
       (document#>>'{configuration,windows,kind}'='whfb'
        AND document#>>'{effect,windows,policy}'='present'
        AND document#>>'{effect,windows,registration}'='present'
        AND document#>>'{effect,windows,hardwareKey}'='present')))
    OR (coalesce(document#>>'{configuration,role}',document#>>'{effect,role}')=document#>>'{effect,role}'
     AND document#>>'{effect,mac,secureToken}'='present'
     AND (document#>>'{configuration,mac,authentication}'<>'password' OR
       (document#>>'{configuration,enabled}'='false' OR
        (document#>>'{effect,mac,platformSso,configuration}'='present'
         AND document#>>'{effect,mac,platformSso,deviceRegistered}'='present'
         AND document#>>'{effect,mac,platformSso,userRegistered}'='present'
         AND document#>>'{effect,mac,platformSso,userSourceId}'<>'00000000-0000-0000-0000-000000000000'
         AND (document#>>'{effect,mac,platformSso,userSourceVersion}')::bigint>0)))
     AND (document#>>'{configuration,mac,filevault}'='local' OR (document#>>'{effect,mac,filevaultUnlock}'='present' AND document#>>'{effect,mac,volumeOwner}'='present')))
   ELSE false END,false)
$$;
REVOKE ALL ON FUNCTION rss_da.access_binding_ready(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION rss_da.access_binding_ready(jsonb) TO da_access,da_inventory_runtime,da_scope_runtime,da_policy_runtime,da_telemetry_runtime,da_command_runtime;
