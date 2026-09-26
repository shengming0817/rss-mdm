CREATE SCHEMA mdm_compliance;
REVOKE ALL ON SCHEMA mdm_compliance FROM PUBLIC;
GRANT USAGE ON SCHEMA mdm_compliance TO mdm_flow_runtime;
CREATE TABLE mdm_compliance.rules (
 tenant_id uuid NOT NULL, id uuid NOT NULL, revision bigint NOT NULL CHECK(revision>0),
 enabled boolean NOT NULL, desired uuid, current_run uuid,
 PRIMARY KEY(tenant_id,id)
);
CREATE TABLE mdm_compliance.versions (
 tenant_id uuid NOT NULL, rule_id uuid NOT NULL, revision bigint NOT NULL CHECK(revision>0),
 definition jsonb NOT NULL CHECK(octet_length(definition::text)<=65536),
 PRIMARY KEY(tenant_id,rule_id,revision), FOREIGN KEY(tenant_id,rule_id) REFERENCES mdm_compliance.rules(tenant_id,id)
);
CREATE TABLE mdm_compliance.fields (
 tenant_id uuid NOT NULL, rule_id uuid NOT NULL, field text NOT NULL,
 PRIMARY KEY(tenant_id,rule_id,field), FOREIGN KEY(tenant_id,rule_id) REFERENCES mdm_compliance.rules(tenant_id,id)
);
CREATE INDEX fields_by_key ON mdm_compliance.fields(tenant_id,field,rule_id);
CREATE TABLE mdm_compliance.groups (
 tenant_id uuid NOT NULL, rule_id uuid NOT NULL, group_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,rule_id,group_id), FOREIGN KEY(tenant_id,rule_id) REFERENCES mdm_compliance.rules(tenant_id,id)
);
CREATE INDEX rules_by_group ON mdm_compliance.groups(tenant_id,group_id,rule_id);
CREATE TABLE mdm_compliance.results (
 tenant_id uuid NOT NULL, task uuid NOT NULL, rule_id uuid NOT NULL, rule_revision bigint NOT NULL CHECK(rule_revision>0), device text NOT NULL,
 evaluated_at bigint NOT NULL, document jsonb NOT NULL CHECK(octet_length(document::text)<=262144),
 CONSTRAINT result_document_identity CHECK(coalesce(document->>'ruleId'=rule_id::text AND document->>'ruleVersion'=rule_revision::text,false)),
 PRIMARY KEY(tenant_id,task,device), FOREIGN KEY(tenant_id,rule_id,rule_revision) REFERENCES mdm_compliance.versions(tenant_id,rule_id,revision)
);
CREATE INDEX device_history ON mdm_compliance.results(tenant_id,device,evaluated_at,task);
CREATE TABLE mdm_compliance.operations (
 tenant_id uuid NOT NULL, id uuid NOT NULL, fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),
 response jsonb NOT NULL CHECK(octet_length(response::text)<=65536), PRIMARY KEY(tenant_id,id)
);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['rules','versions','fields','groups','results','operations'] LOOP
  EXECUTE format('ALTER TABLE mdm_compliance.%I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE mdm_compliance.%I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format($policy$CREATE POLICY tenant ON mdm_compliance.%I USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)$policy$,t);
  EXECUTE format('REVOKE ALL ON mdm_compliance.%I FROM PUBLIC',t);
  EXECUTE format('GRANT SELECT,INSERT ON mdm_compliance.%I TO mdm_flow_runtime',t);
 END LOOP;
END $$;
GRANT UPDATE(revision,enabled,desired,current_run) ON mdm_compliance.rules TO mdm_flow_runtime;
GRANT DELETE ON mdm_compliance.fields,mdm_compliance.groups TO mdm_flow_runtime;
