BEGIN;
CREATE TABLE mdm_pki.trust_observations (
 tenant_id uuid NOT NULL, registration uuid NOT NULL, generation bigint NOT NULL CHECK(generation>0),
 sequence bigint NOT NULL CHECK(sequence>0), operation uuid NOT NULL,
 body jsonb NOT NULL CHECK(jsonb_typeof(body)='object'),
 received_at bigint NOT NULL DEFAULT floor(extract(epoch FROM clock_timestamp()))::bigint,
 PRIMARY KEY(tenant_id,registration,generation,sequence), UNIQUE(tenant_id,operation)
);
ALTER TABLE mdm_pki.trust_observations ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_pki.trust_observations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_pki.trust_observations USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON mdm_pki.trust_observations FROM PUBLIC;
GRANT SELECT,INSERT ON mdm_pki.trust_observations TO mdm_access;
COMMIT;
