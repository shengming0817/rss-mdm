BEGIN;
CREATE SCHEMA mdm_access AUTHORIZATION mdm_owner;
REVOKE ALL ON SCHEMA mdm_access FROM PUBLIC;
GRANT USAGE ON SCHEMA mdm_access TO mdm_access;
CREATE TABLE mdm_access.grants (
 tenant_id uuid NOT NULL, id uuid NOT NULL, actor text NOT NULL CHECK(length(actor) BETWEEN 1 AND 255),
 client text NOT NULL CHECK(length(client) BETWEEN 1 AND 255), device text NOT NULL CHECK(length(device) BETWEEN 1 AND 255),
 purpose text NOT NULL CHECK(purpose='enrollment'),
 state text NOT NULL CHECK(state IN ('available','consumed','revoked')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), expires_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,id), CHECK(expires_at > created_at AND expires_at <= created_at + interval '300 seconds')
);
CREATE TABLE mdm_access.requests (
 tenant_id uuid NOT NULL, id uuid NOT NULL, grant_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,grant_id),
 FOREIGN KEY(tenant_id,grant_id) REFERENCES mdm_access.grants(tenant_id,id)
);
CREATE TABLE mdm_access.operations (
 tenant_id uuid NOT NULL, actor text NOT NULL, client text NOT NULL, operation_id uuid NOT NULL,
 digest text NOT NULL CHECK(length(digest)=64), result text NOT NULL CHECK(length(result)<=2048),
 PRIMARY KEY(tenant_id,actor,operation_id)
);
CREATE TABLE mdm_access.audit (
 tenant_id uuid NOT NULL, id uuid NOT NULL, request_id uuid NOT NULL,
 actor text, client text, target text, operation_id uuid, registration_request uuid,
 action text NOT NULL CHECK(action IN ('grant_issue','grant_revoke','registration_accept','inventory_read','device_action','authentication','protected_request')),
 result text NOT NULL CHECK(result IN ('success','denied','failed','unknown','replay')),
 status integer NOT NULL CHECK(status BETWEEN 100 AND 599), recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id),
 CHECK(actor IS NULL OR length(actor) BETWEEN 1 AND 255), CHECK(client IS NULL OR length(client) BETWEEN 1 AND 255), CHECK(target IS NULL OR length(target) BETWEEN 1 AND 255)
);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['grants','requests','operations','audit'] LOOP
  EXECUTE format('ALTER TABLE mdm_access.%I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE mdm_access.%I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('CREATE POLICY tenant ON mdm_access.%I USING (tenant_id = nullif(current_setting(''rss.tenant_id'',true),'''')::uuid) WITH CHECK (tenant_id = nullif(current_setting(''rss.tenant_id'',true),'''')::uuid)',t);
 END LOOP;
END $$;
GRANT SELECT,INSERT ON mdm_access.grants,mdm_access.operations TO mdm_access;
GRANT INSERT ON mdm_access.requests,mdm_access.audit TO mdm_access;
GRANT UPDATE(state) ON mdm_access.grants TO mdm_access;
COMMIT;
