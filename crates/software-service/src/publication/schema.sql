BEGIN;
CREATE SCHEMA mdm_software_composition AUTHORIZATION mdm_owner;
REVOKE ALL ON SCHEMA mdm_software_composition FROM PUBLIC;
CREATE TABLE mdm_software_composition.bindings (
 tenant_id uuid NOT NULL, identity bytea PRIMARY KEY CHECK(octet_length(identity)=32),
 configuration bytea NOT NULL CHECK(octet_length(configuration) BETWEEN 1 AND 1048576),
 UNIQUE(tenant_id,identity)
);
CREATE TABLE mdm_software_composition.subjects (
 tenant_id uuid NOT NULL, record text NOT NULL CHECK(octet_length(record) BETWEEN 1 AND 128),
 resource text NOT NULL, version text NOT NULL,
 document bytea NOT NULL CHECK(octet_length(document) BETWEEN 1 AND 8388608), digest bytea NOT NULL CHECK(octet_length(digest)=32),
 PRIMARY KEY(tenant_id,record),
 FOREIGN KEY(tenant_id,record) REFERENCES mdm_software_release.aggregates(tenant_id,id),
 FOREIGN KEY(tenant_id,resource) REFERENCES mdm_resource.aggregates(tenant_id,id)
);
CREATE INDEX resource_references ON mdm_software_composition.subjects(tenant_id,resource,version,record COLLATE "C");
CREATE TABLE mdm_software_composition.authorities (
 tenant_id uuid NOT NULL, software bytea NOT NULL CHECK(octet_length(software)=32),
 record text NOT NULL,
 PRIMARY KEY(tenant_id,software), FOREIGN KEY(tenant_id,record) REFERENCES mdm_software_composition.subjects(tenant_id,record) DEFERRABLE INITIALLY DEFERRED
);
CREATE TABLE mdm_software_composition.slots (
 tenant_id uuid NOT NULL, binding bytea NOT NULL, coordinate text NOT NULL CHECK(octet_length(coordinate) BETWEEN 1 AND 512),
 operation text CHECK(octet_length(operation) BETWEEN 1 AND 128), cursor text CHECK(cursor ~ '^[0-9a-f]{40}$'),
 PRIMARY KEY(tenant_id,binding,coordinate), FOREIGN KEY(tenant_id,binding) REFERENCES mdm_software_composition.bindings(tenant_id,identity)
);
CREATE TABLE mdm_software_composition.targets (
 tenant_id uuid NOT NULL,
 expected_epoch bigint NOT NULL DEFAULT current_setting('rss.execution_epoch')::bigint CHECK(expected_epoch>0),
 id text NOT NULL CHECK(octet_length(id) BETWEEN 1 AND 128),
 record text NOT NULL,
 document bytea NOT NULL CHECK(octet_length(document) BETWEEN 1 AND 1048576),
 digest bytea NOT NULL CHECK(octet_length(digest)=32),
 call_generation bigint NOT NULL DEFAULT 0 CHECK(call_generation>=0),
 attempted boolean NOT NULL DEFAULT false,
 acknowledged boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,id),
 FOREIGN KEY(tenant_id,record) REFERENCES mdm_software_composition.subjects(tenant_id,record),
 CHECK(NOT acknowledged OR attempted),
 withdrawal_id text,
 CHECK((left(id,2)='p:' AND withdrawal_id IS NULL) OR (left(id,2)='w:' AND withdrawal_id=id))

);
CREATE TABLE mdm_software_composition.withdrawals (
 expected_epoch bigint NOT NULL DEFAULT current_setting('rss.execution_epoch')::bigint CHECK(expected_epoch>0),
 tenant_id uuid NOT NULL, id text NOT NULL CHECK(octet_length(id) BETWEEN 1 AND 128), record text NOT NULL,
 document bytea NOT NULL CHECK(octet_length(document) BETWEEN 1 AND 1048576), digest bytea NOT NULL CHECK(octet_length(digest)=32),
 complete boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,id), FOREIGN KEY(tenant_id,record) REFERENCES mdm_software_composition.subjects(tenant_id,record)
);

ALTER TABLE mdm_software_composition.targets ADD FOREIGN KEY(tenant_id,withdrawal_id) REFERENCES mdm_software_composition.withdrawals(tenant_id,id);

CREATE TABLE mdm_software_composition.projections (
 tenant_id uuid NOT NULL, binding bytea NOT NULL, coordinate text NOT NULL CHECK(octet_length(coordinate) BETWEEN 1 AND 512), publication bytea NOT NULL CHECK(octet_length(publication)=32),
 PRIMARY KEY(tenant_id,binding,coordinate), FOREIGN KEY(tenant_id,binding) REFERENCES mdm_software_composition.bindings(tenant_id,identity)
);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['bindings','subjects','authorities','slots','targets','withdrawals','projections'] LOOP
 EXECUTE format('ALTER TABLE mdm_software_composition.%I ENABLE ROW LEVEL SECURITY',t);
 EXECUTE format('ALTER TABLE mdm_software_composition.%I FORCE ROW LEVEL SECURITY',t);
 EXECUTE format('CREATE POLICY tenant ON mdm_software_composition.%I USING(tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid) WITH CHECK(tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid)',t);
 EXECUTE format('REVOKE ALL ON mdm_software_composition.%I FROM PUBLIC',t);
 END LOOP;
END $$;
GRANT USAGE ON SCHEMA mdm_software_composition TO mdm_software_driver;
GRANT SELECT,INSERT ON ALL TABLES IN SCHEMA mdm_software_composition TO mdm_software_driver;
GRANT UPDATE(record) ON mdm_software_composition.authorities TO mdm_software_driver;
GRANT UPDATE(operation,cursor) ON mdm_software_composition.slots TO mdm_software_driver;
GRANT UPDATE(attempted,acknowledged,call_generation) ON mdm_software_composition.targets TO mdm_software_driver;
GRANT UPDATE(complete) ON mdm_software_composition.withdrawals TO mdm_software_driver;
GRANT UPDATE(publication) ON mdm_software_composition.projections TO mdm_software_driver;
GRANT DELETE ON mdm_software_composition.projections TO mdm_software_driver;
GRANT USAGE ON SCHEMA mdm_access TO mdm_software_driver;
GRANT USAGE ON SCHEMA mdm_software_composition,mdm_software_release TO mdm_command_runtime,mdm_software_runtime;
GRANT SELECT ON mdm_software_composition.subjects,mdm_software_composition.targets,mdm_software_composition.projections,mdm_software_release.aggregates TO mdm_command_runtime,mdm_software_runtime;
GRANT SELECT,INSERT ON mdm_software_composition.withdrawals TO mdm_software_runtime;
GRANT SELECT ON mdm_software_composition.withdrawals TO mdm_command_runtime;
COMMIT;

CREATE INDEX publication_work_scope ON mdm_software_composition.targets(tenant_id,expected_epoch,id COLLATE "C");
CREATE INDEX withdrawal_work_scope ON mdm_software_composition.withdrawals(tenant_id,expected_epoch,id COLLATE "C") WHERE NOT complete;
CREATE POLICY work_discovery ON mdm_software_composition.targets FOR SELECT TO mdm_owner USING(true);
CREATE POLICY work_discovery ON mdm_software_composition.withdrawals FOR SELECT TO mdm_owner USING(true);
CREATE POLICY work_discovery ON mdm_software_composition.subjects FOR SELECT TO mdm_owner USING(true);
CREATE POLICY work_discovery ON mdm_software_composition.projections FOR SELECT TO mdm_owner USING(true);
CREATE FUNCTION mdm_software_composition.work_scopes(after_tenant uuid, after_epoch bigint, after_id text)
RETURNS TABLE(tenant_id uuid, expected_epoch bigint, id text, source text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 WITH work AS (
  (SELECT t.tenant_id,t.expected_epoch,t.id,t.record FROM mdm_software_composition.targets t
   WHERE left(t.id,2)='p:' AND (after_tenant IS NULL OR (t.tenant_id,t.expected_epoch,t.id COLLATE "C")>(after_tenant,after_epoch,after_id COLLATE "C"))
    AND NOT EXISTS(SELECT 1 FROM mdm_software_composition.projections p WHERE p.tenant_id=t.tenant_id AND encode(p.publication,'hex')=substring(t.id,3,64))
   ORDER BY t.tenant_id,t.expected_epoch,t.id COLLATE "C" LIMIT 32)
  UNION ALL
  (SELECT w.tenant_id,w.expected_epoch,w.id,w.record FROM mdm_software_composition.withdrawals w WHERE NOT w.complete
   AND (after_tenant IS NULL OR (w.tenant_id,w.expected_epoch,w.id COLLATE "C")>(after_tenant,after_epoch,after_id COLLATE "C"))
   ORDER BY w.tenant_id,w.expected_epoch,w.id COLLATE "C" LIMIT 32)
 ) SELECT w.tenant_id,w.expected_epoch,w.id,convert_from(s.document,'UTF8')::jsonb->>'target'
 FROM work w JOIN mdm_software_composition.subjects s ON(s.tenant_id,s.record)=(w.tenant_id,w.record)
 ORDER BY w.tenant_id,w.expected_epoch,w.id COLLATE "C" LIMIT 32
$$;
ALTER FUNCTION mdm_software_composition.work_scopes(uuid,bigint,text) OWNER TO mdm_owner;
REVOKE ALL ON FUNCTION mdm_software_composition.work_scopes(uuid,bigint,text) FROM PUBLIC;
GRANT USAGE ON SCHEMA mdm_software_composition TO mdm_access;
GRANT EXECUTE ON FUNCTION mdm_software_composition.work_scopes(uuid,bigint,text) TO mdm_access;
