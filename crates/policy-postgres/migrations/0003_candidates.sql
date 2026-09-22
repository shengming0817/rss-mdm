BEGIN;
ALTER TABLE mdm_policy.immutable DROP CONSTRAINT immutable_kind_check;
ALTER TABLE mdm_policy.immutable ADD CONSTRAINT immutable_kind_check CHECK(kind IN ('version','payload'));
-- Relational keys allow bounded history-existence probes without loading all facts.
ALTER TABLE mdm_policy.facts ADD COLUMN device text GENERATED ALWAYS AS (substring(key FROM strpos(key,'/')+1)) STORED;
ALTER TABLE mdm_policy.facts ADD COLUMN version numeric(20,0) GENERATED ALWAYS AS (split_part(key,'/',1)::numeric) STORED;
CREATE INDEX facts_device_version ON mdm_policy.facts(tenant_id,owner,device,version);
CREATE INDEX facts_semantic_order ON mdm_policy.facts(tenant_id,owner,version,device COLLATE "C");
CREATE TABLE mdm_policy.reference_heads (
 tenant_id uuid NOT NULL, id text NOT NULL CHECK(octet_length(id) BETWEEN 1 AND 128),
 revision bigint NOT NULL CHECK(revision>=0),
 required_input bigint NOT NULL DEFAULT 0 CHECK(required_input>=0),
 observed_input bigint NOT NULL DEFAULT 0 CHECK(observed_input>=0),
 PRIMARY KEY(tenant_id,id)
);
CREATE TABLE mdm_policy.candidates (
 tenant_id uuid NOT NULL, id text NOT NULL CHECK(octet_length(id) BETWEEN 1 AND 128),
 policy text NOT NULL, expected_revision bigint NOT NULL CHECK(expected_revision>0),
 input bytea NOT NULL CHECK(octet_length(input)<=1048576), fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),
 phase text NOT NULL CHECK(phase IN ('targets','facts','ready','saved','superseded')),
 target_cursor text, fact_cursor text,
 target_count bigint NOT NULL DEFAULT 0 CHECK(target_count BETWEEN 0 AND 1000000),
 fact_count bigint NOT NULL DEFAULT 0 CHECK(fact_count>=0),
 target_root bytea NOT NULL CHECK(octet_length(target_root)=32),
 fact_root bytea NOT NULL CHECK(octet_length(fact_root)=32),
 plan_id bytea CHECK(plan_id IS NULL OR octet_length(plan_id)=32),
 PRIMARY KEY(tenant_id,id), FOREIGN KEY(tenant_id,policy) REFERENCES mdm_policy.aggregates(tenant_id,id),
 CHECK((phase IN('ready','saved'))=(plan_id IS NOT NULL))
);
CREATE TABLE mdm_policy.candidate_references (
 tenant_id uuid NOT NULL, candidate text NOT NULL, reference text NOT NULL, revision bigint NOT NULL CHECK(revision>=0),
 PRIMARY KEY(tenant_id,candidate,reference),
 FOREIGN KEY(tenant_id,candidate) REFERENCES mdm_policy.candidates(tenant_id,id),
 FOREIGN KEY(tenant_id,reference) REFERENCES mdm_policy.reference_heads(tenant_id,id)
);
CREATE INDEX candidate_references_source ON mdm_policy.candidate_references(tenant_id,reference,candidate);
CREATE TABLE mdm_policy.candidate_targets (
 tenant_id uuid NOT NULL, candidate text NOT NULL, device text COLLATE "C" NOT NULL CHECK(octet_length(device) BETWEEN 1 AND 256),
 PRIMARY KEY(tenant_id,candidate,device), FOREIGN KEY(tenant_id,candidate) REFERENCES mdm_policy.candidates(tenant_id,id)
);
CREATE TABLE mdm_policy.candidate_intents (
 tenant_id uuid NOT NULL, candidate text NOT NULL,
 kind text COLLATE "C" NOT NULL CHECK(kind IN('add','supersede','retain','cancel')),
 device text COLLATE "C" NOT NULL, execution_key text COLLATE "C" NOT NULL,
 document bytea NOT NULL CHECK(octet_length(document)<=1048576), digest bytea NOT NULL CHECK(octet_length(digest)=32),
 PRIMARY KEY(tenant_id,candidate,kind,device,execution_key),
 FOREIGN KEY(tenant_id,candidate) REFERENCES mdm_policy.candidates(tenant_id,id)
);
CREATE TABLE mdm_policy.candidate_pages (
 tenant_id uuid NOT NULL, candidate text NOT NULL, first_device text COLLATE "C" NOT NULL,
 fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),
 PRIMARY KEY(tenant_id,candidate,first_device), FOREIGN KEY(tenant_id,candidate) REFERENCES mdm_policy.candidates(tenant_id,id)
);
CREATE TABLE mdm_policy.current_plans (
 tenant_id uuid NOT NULL, policy text NOT NULL, candidate text NOT NULL,
 PRIMARY KEY(tenant_id,policy), FOREIGN KEY(tenant_id,policy) REFERENCES mdm_policy.aggregates(tenant_id,id),
 FOREIGN KEY(tenant_id,candidate) REFERENCES mdm_policy.candidates(tenant_id,id)
);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['reference_heads','candidates','candidate_references','candidate_targets','candidate_intents','candidate_pages','current_plans'] LOOP
  EXECUTE format('ALTER TABLE mdm_policy.%I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE mdm_policy.%I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('CREATE POLICY tenant ON mdm_policy.%I USING(tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid) WITH CHECK(tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid)',t);
  EXECUTE format('REVOKE ALL ON mdm_policy.%I FROM PUBLIC',t);
  EXECUTE format('GRANT SELECT,INSERT ON mdm_policy.%I TO mdm_policy_runtime',t);
 END LOOP;
END $$;
GRANT UPDATE(revision,required_input,observed_input) ON mdm_policy.reference_heads TO mdm_policy_runtime;
GRANT UPDATE(phase,target_cursor,fact_cursor,target_count,fact_count,target_root,fact_root,plan_id) ON mdm_policy.candidates TO mdm_policy_runtime;
GRANT UPDATE(candidate) ON mdm_policy.current_plans TO mdm_policy_runtime;
COMMIT;
