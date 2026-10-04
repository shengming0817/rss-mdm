-- Apple owns organization bindings and protocol handoff materials, not device lifecycle.
BEGIN;
ALTER TABLE mdm_apple.scep_attempts RENAME COLUMN password_version TO authorization_version;
CREATE TABLE mdm_apple.account_organizations (
 tenant_id uuid NOT NULL, id uuid NOT NULL, domain text NOT NULL, server_uuid uuid NOT NULL,
 operation uuid NOT NULL, signing_key text NOT NULL, enabled boolean NOT NULL, revision bigint NOT NULL CHECK(revision>0),
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,domain), UNIQUE(tenant_id,server_uuid)
);
CREATE TABLE mdm_apple.account_bindings (
 tenant_id uuid NOT NULL, organization uuid NOT NULL, account text NOT NULL, principal uuid NOT NULL,
 operation uuid NOT NULL, instance uuid NOT NULL, enabled boolean NOT NULL, revision bigint NOT NULL CHECK(revision>0),
 PRIMARY KEY(tenant_id,organization,account), UNIQUE(tenant_id,organization,principal),
 FOREIGN KEY(tenant_id,organization) REFERENCES mdm_apple.account_organizations(tenant_id,id)
);
CREATE TABLE mdm_apple.account_flows (
 tenant_id uuid NOT NULL, id uuid NOT NULL, organization uuid NOT NULL, organization_revision bigint NOT NULL,
 request_digest text NOT NULL, account text, binding_revision bigint,
 expected_account text, target_enrollment uuid NOT NULL, cookie_hash text, enrollment uuid, authorization_version bigint, token_hash text, material bytea,
 profile bytea, expires_at timestamptz NOT NULL, revoked boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,token_hash),
 FOREIGN KEY(tenant_id,organization) REFERENCES mdm_apple.account_organizations(tenant_id,id),
 FOREIGN KEY(tenant_id,enrollment) REFERENCES mdm_access.requests(tenant_id,id),
 CHECK(revoked OR (enrollment IS NULL AND authorization_version IS NULL AND token_hash IS NULL AND material IS NULL) OR
       (enrollment IS NOT NULL AND authorization_version IS NOT NULL AND authorization_version>0 AND token_hash IS NOT NULL AND material IS NOT NULL)),
 CHECK((account IS NULL AND binding_revision IS NULL AND cookie_hash IS NULL) OR
       (account IS NOT NULL AND binding_revision IS NOT NULL AND binding_revision>0 AND cookie_hash IS NOT NULL))
);
CREATE INDEX account_flows_live ON mdm_apple.account_flows(tenant_id,expires_at) WHERE NOT revoked;
CREATE INDEX account_flows_enrollment ON mdm_apple.account_flows(tenant_id,enrollment) WHERE NOT revoked;
ALTER TABLE mdm_apple.account_organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_apple.account_organizations FORCE ROW LEVEL SECURITY;
ALTER TABLE mdm_apple.account_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_apple.account_bindings FORCE ROW LEVEL SECURITY;
ALTER TABLE mdm_apple.account_flows ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_apple.account_flows FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_apple.account_organizations USING(tenant_id = nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id = nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY tenant ON mdm_apple.account_bindings USING(tenant_id = nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id = nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY tenant ON mdm_apple.account_flows USING(tenant_id = nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id = nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON mdm_apple.account_organizations,mdm_apple.account_bindings,mdm_apple.account_flows TO mdm_access;
GRANT UPDATE(domain,server_uuid,signing_key,enabled,revision,operation) ON mdm_apple.account_organizations TO mdm_access;
GRANT UPDATE(principal,instance,enabled,revision,operation) ON mdm_apple.account_bindings TO mdm_access;
GRANT UPDATE(account,binding_revision,cookie_hash,enrollment,authorization_version,token_hash,material,profile,revoked) ON mdm_apple.account_flows TO mdm_access;
COMMIT;
