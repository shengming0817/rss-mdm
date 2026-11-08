BEGIN;
CREATE TABLE mdm_windows.renewal_intents (
    tenant_id uuid NOT NULL
  , id uuid NOT NULL
  , signing_attempt uuid NOT NULL
  , device text NOT NULL
  , previous_credential uuid NOT NULL
  , proof_digest bytea NOT NULL CHECK (octet_length(proof_digest) = 32)
  , profile bytea NOT NULL CHECK (octet_length(profile) BETWEEN 1 AND 4096)
  , configuration text NOT NULL CHECK (configuration ~ '^[0-9a-f]{64}$')
  , PRIMARY KEY (tenant_id, id)
  , UNIQUE (tenant_id, device, previous_credential)
  , FOREIGN KEY (tenant_id, device) REFERENCES mdm_access.devices (tenant_id, id)
);
ALTER TABLE mdm_windows.renewal_intents ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_windows.renewal_intents FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_windows.renewal_intents USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON mdm_windows.renewal_intents TO mdm_access;
GRANT UPDATE(signing_attempt,profile) ON mdm_windows.renewal_intents TO mdm_access;

CREATE TABLE mdm_windows.trust_deliveries (
    protocol_epoch uuid NOT NULL,
    tenant_id uuid NOT NULL
  , id uuid NOT NULL
  , device text NOT NULL
  , credential uuid NOT NULL
  , revision bigint NOT NULL CHECK (revision > 0)
  , digest text NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$')
  , session bigint NOT NULL CHECK (session > 0)
  , message bigint NOT NULL CHECK (message > 0)
  , first_command bigint NOT NULL CHECK (first_command > 0)
  , request bytea NOT NULL CHECK (octet_length(request) BETWEEN 68 AND 2097220)
  , results bytea NOT NULL CHECK (octet_length(results) BETWEEN 68 AND 2097220)
  , authority text NOT NULL CHECK (authority ~ '^[0-9a-f]{64}$')
  , confirmed boolean NOT NULL DEFAULT FALSE
  , PRIMARY KEY (tenant_id, id)
  , UNIQUE (tenant_id, device, protocol_epoch, session, revision, authority)
  , FOREIGN KEY (tenant_id, device) REFERENCES mdm_access.devices (tenant_id, id)
);
ALTER TABLE mdm_windows.trust_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_windows.trust_deliveries FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_windows.trust_deliveries USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY expired_only ON mdm_windows.trust_deliveries AS RESTRICTIVE FOR DELETE USING(EXISTS(SELECT 1 FROM mdm_access.management_sessions s WHERE s.tenant_id=trust_deliveries.tenant_id AND s.device=trust_deliveries.device AND s.protocol_epoch=trust_deliveries.protocol_epoch AND s.session_id=trust_deliveries.session::text AND s.expires_at<clock_timestamp()));
GRANT SELECT,INSERT,DELETE ON mdm_windows.trust_deliveries TO mdm_access;
GRANT UPDATE(results,confirmed) ON mdm_windows.trust_deliveries TO mdm_access;
CREATE TABLE mdm_apple.trust_deliveries (
    tenant_id uuid NOT NULL
  , id uuid NOT NULL
  , device text NOT NULL
  , revision bigint NOT NULL CHECK (revision > 0)
  , digest text NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$')
  , body bytea NOT NULL CHECK (octet_length(body) BETWEEN 1 AND 67108864)
  , profile uuid NOT NULL
  , PRIMARY KEY (tenant_id, id)
  , UNIQUE (tenant_id, device, revision)
  , FOREIGN KEY (tenant_id, device) REFERENCES mdm_access.devices (tenant_id, id)
);
ALTER TABLE mdm_apple.trust_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_apple.trust_deliveries FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_apple.trust_deliveries USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON mdm_apple.trust_deliveries TO mdm_access;

ALTER TABLE mdm_apple.attempts ADD CONSTRAINT trust_delivery FOREIGN KEY (tenant_id, trust) REFERENCES mdm_apple.trust_deliveries (tenant_id, id);

GRANT SELECT,INSERT ON mdm_windows.trust_deliveries,mdm_apple.trust_deliveries TO mdm_command_runtime;
GRANT UPDATE(results,confirmed) ON mdm_windows.trust_deliveries TO mdm_command_runtime;
COMMIT;
