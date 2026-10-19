BEGIN;
CREATE TABLE mdm_webhook.key_heads (
 tenant_id uuid NOT NULL,reference text NOT NULL CHECK(length(reference) BETWEEN 1 AND 128),
 revision bigint NOT NULL CHECK(revision>=0),active_revision bigint,retiring_revision bigint,
 PRIMARY KEY(tenant_id,reference)
);
CREATE TABLE mdm_webhook.key_materials (
 tenant_id uuid NOT NULL,reference text NOT NULL,revision bigint NOT NULL CHECK(revision>0),
 operation_id uuid NOT NULL,configuration text NOT NULL CHECK(configuration ~ '^[0-9a-f]{64}$'),
 confirmation_endpoint text CHECK(confirmation_endpoint IS NULL OR length(confirmation_endpoint)<=2048),network_reference text CHECK(network_reference IS NULL OR length(network_reference) BETWEEN 1 AND 128),attempted_at bigint,confirmed_at bigint,failure_reason text,legacy_import boolean NOT NULL DEFAULT false,
 key_digest bytea NOT NULL CHECK(octet_length(key_digest)=32),material bytea NOT NULL CHECK(octet_length(material) BETWEEN 1 AND 4096),
 nonce bytea NOT NULL CHECK(octet_length(nonce)=32),confirmed boolean NOT NULL DEFAULT false,
 revoked boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,reference,revision),UNIQUE(tenant_id,operation_id),
 FOREIGN KEY(tenant_id,reference) REFERENCES mdm_webhook.key_heads(tenant_id,reference)
);
DO $keys$ DECLARE n text; BEGIN
 FOREACH n IN ARRAY ARRAY['key_heads','key_materials'] LOOP
  EXECUTE format('ALTER TABLE mdm_webhook.%I ENABLE ROW LEVEL SECURITY',n);
  EXECUTE format('ALTER TABLE mdm_webhook.%I FORCE ROW LEVEL SECURITY',n);
  EXECUTE format('CREATE POLICY tenant ON mdm_webhook.%I USING(tenant_id=NULLIF(current_setting(''rss.tenant_id'',true),'''')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting(''rss.tenant_id'',true),'''')::uuid)',n);
 END LOOP;
END $keys$;
GRANT SELECT,INSERT ON mdm_webhook.key_heads,mdm_webhook.key_materials TO mdm_access,mdm_command_runtime;
GRANT UPDATE(revision,active_revision,retiring_revision) ON mdm_webhook.key_heads TO mdm_access,mdm_command_runtime;
GRANT UPDATE(revoked) ON mdm_webhook.key_materials TO mdm_access,mdm_command_runtime;
CREATE POLICY insert_only ON mdm_webhook.key_materials AS RESTRICTIVE FOR INSERT WITH CHECK(current_user::text='mdm_owner'::text OR (NOT confirmed AND NOT revoked AND NOT legacy_import AND attempted_at IS NULL AND confirmed_at IS NULL AND failure_reason IS NULL));
COMMIT;
