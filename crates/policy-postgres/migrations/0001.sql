BEGIN;
CREATE SCHEMA mdm_policy;
REVOKE ALL ON SCHEMA mdm_policy FROM PUBLIC;
CREATE TABLE mdm_policy.policies (
 tenant_id uuid NOT NULL, id uuid NOT NULL, revision bigint NOT NULL CHECK(revision>0),
 current_version uuid NOT NULL, version_number bigint NOT NULL CHECK(version_number>0),
 enabled boolean NOT NULL, definition jsonb NOT NULL CHECK(octet_length(definition::text)<=4194304),
 author jsonb NOT NULL, updated_at bigint NOT NULL CHECK(updated_at>=0), PRIMARY KEY(tenant_id,id)
);
CREATE TABLE mdm_policy.versions (
 tenant_id uuid NOT NULL,id uuid NOT NULL,policy uuid NOT NULL,number bigint NOT NULL CHECK(number>0),
 action_kind text NOT NULL CHECK(action_kind IN ('execution','native_collection','configuration','software','ensure_agent_installed','request_mdm_enrollment')),
 resource text,resource_version text,
 CHECK((resource IS NULL) = (resource_version IS NULL)),
 CHECK((action_kind='request_mdm_enrollment') = (resource IS NULL)),
 frozen jsonb NOT NULL CHECK(octet_length(frozen::text)<=25165824),
 fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),
 PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,policy,number),
 FOREIGN KEY(tenant_id,policy) REFERENCES mdm_policy.policies(tenant_id,id)
);
ALTER TABLE mdm_policy.policies ADD FOREIGN KEY(tenant_id,current_version) REFERENCES mdm_policy.versions(tenant_id,id) DEFERRABLE INITIALLY DEFERRED;
CREATE INDEX policy_scope ON mdm_policy.policies(tenant_id,((definition->>'scope')::uuid),id);
CREATE TABLE mdm_policy.triggers (
 tenant_id uuid NOT NULL,id uuid NOT NULL,version uuid NOT NULL,created_at bigint NOT NULL,deadline bigint NOT NULL CHECK(deadline>created_at),
 PRIMARY KEY(tenant_id,id),FOREIGN KEY(tenant_id,version) REFERENCES mdm_policy.versions(tenant_id,id)
);
CREATE INDEX policy_triggers_due ON mdm_policy.triggers(tenant_id,version,deadline,created_at,id);

CREATE TABLE mdm_policy.requests (
 tenant_id uuid NOT NULL,id uuid NOT NULL,fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),receipt jsonb NOT NULL CHECK(octet_length(receipt::text)<=16777216),PRIMARY KEY(tenant_id,id)
);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['policies','versions','triggers','requests'] LOOP
 EXECUTE format('ALTER TABLE mdm_policy.%I ENABLE ROW LEVEL SECURITY',t);
 EXECUTE format('ALTER TABLE mdm_policy.%I FORCE ROW LEVEL SECURITY',t);
 EXECUTE format('CREATE POLICY tenant ON mdm_policy.%I USING(tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid) WITH CHECK(tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid)',t);
 EXECUTE format('GRANT SELECT,INSERT ON mdm_policy.%I TO mdm_policy_runtime',t);
 END LOOP;
END $$;
GRANT USAGE ON SCHEMA mdm_policy TO mdm_policy_runtime;
GRANT UPDATE(revision,current_version,version_number,enabled,definition,author,updated_at) ON mdm_policy.policies TO mdm_policy_runtime;
COMMIT;
