CREATE SCHEMA mdm_compliance;
REVOKE ALL ON SCHEMA mdm_compliance FROM PUBLIC;
GRANT USAGE ON SCHEMA mdm_compliance TO mdm_inventory_runtime;
CREATE TABLE mdm_compliance.rules (
 tenant_id uuid NOT NULL, id uuid NOT NULL, revision bigint NOT NULL CHECK(revision>0),
 enabled boolean NOT NULL, desired uuid, current_run uuid, deleted boolean NOT NULL DEFAULT false,
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
  EXECUTE format('GRANT SELECT,INSERT ON mdm_compliance.%I TO mdm_inventory_runtime',t);
 END LOOP;
END $$;
GRANT UPDATE(revision,enabled,desired,current_run,deleted) ON mdm_compliance.rules TO mdm_inventory_runtime;
GRANT DELETE ON mdm_compliance.fields,mdm_compliance.groups TO mdm_inventory_runtime;

CREATE TABLE mdm_compliance.runs (
 tenant_id uuid NOT NULL,id uuid NOT NULL,rule_id uuid NOT NULL,rule_revision bigint NOT NULL,
 input jsonb NOT NULL CHECK(octet_length(input::text)<=1048576),
 CHECK(coalesce(input->>'rule'=rule_id::text AND (input->>'revision')::bigint=rule_revision,false)),
 completed boolean NOT NULL DEFAULT false,started boolean NOT NULL DEFAULT false,
 failure text CHECK(failure IS NULL OR completed),cursor text,detail jsonb,
 PRIMARY KEY(tenant_id,id),FOREIGN KEY(tenant_id,rule_id,rule_revision) REFERENCES mdm_compliance.versions(tenant_id,rule_id,revision)
);
CREATE TABLE mdm_compliance.evaluations (
 tenant_id uuid NOT NULL,task uuid NOT NULL,binding text NOT NULL CHECK(binding ~ '^[0-9a-f]{64}$'),
 PRIMARY KEY(tenant_id,task),FOREIGN KEY(tenant_id,task) REFERENCES mdm_compliance.runs(tenant_id,id)
);
CREATE TABLE mdm_compliance.evaluation_arrays (
 tenant_id uuid NOT NULL,task uuid NOT NULL,version text NOT NULL CHECK(version ~ '^[0-9a-f]{64}$'),
 state jsonb NOT NULL CHECK(octet_length(state::text)<=1048576),
 PRIMARY KEY(tenant_id,task,version),
 FOREIGN KEY(tenant_id,task) REFERENCES mdm_compliance.evaluations(tenant_id,task) ON DELETE CASCADE
);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['runs','evaluations','evaluation_arrays'] LOOP
  EXECUTE format('ALTER TABLE mdm_compliance.%I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE mdm_compliance.%I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format($policy$CREATE POLICY tenant ON mdm_compliance.%I USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)$policy$,t);
  EXECUTE format('REVOKE ALL ON mdm_compliance.%I FROM PUBLIC',t);
  EXECUTE format('GRANT SELECT,INSERT ON mdm_compliance.%I TO mdm_inventory_runtime',t);
 END LOOP;
END $$;
GRANT UPDATE(completed,cursor,started,detail,failure) ON mdm_compliance.runs TO mdm_inventory_runtime;
GRANT UPDATE(binding) ON mdm_compliance.evaluations TO mdm_inventory_runtime;
GRANT UPDATE(state) ON mdm_compliance.evaluation_arrays TO mdm_inventory_runtime;
GRANT DELETE ON mdm_compliance.evaluations,mdm_compliance.evaluation_arrays TO mdm_inventory_runtime;
CREATE TABLE mdm_compliance.dispatch (
 tenant_id uuid PRIMARY KEY,consumed bigint NOT NULL DEFAULT 0 CHECK(consumed>=0),
 watermark bigint NOT NULL DEFAULT 0 CHECK(watermark>=consumed),cursor text
);
ALTER TABLE mdm_compliance.dispatch ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_compliance.dispatch FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_compliance.dispatch USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON mdm_compliance.dispatch FROM PUBLIC;
GRANT SELECT,INSERT ON mdm_compliance.dispatch TO mdm_inventory_runtime;
GRANT UPDATE(consumed,watermark,cursor) ON mdm_compliance.dispatch TO mdm_inventory_runtime;

GRANT USAGE ON SCHEMA mdm_compliance TO mdm_command_runtime;
GRANT SELECT ON mdm_compliance.results TO mdm_command_runtime;
