CREATE SCHEMA mdm;
CREATE TABLE mdm.inventory (
 tenant_id uuid NOT NULL,
 journal text NOT NULL,
 generation text NOT NULL,
 scope text NOT NULL,
 coverage text NOT NULL,
 field text NOT NULL CHECK (field IN ('device.model','device.os.version')),
 value text NOT NULL CHECK (octet_length(value) BETWEEN 1 AND 256),
 batch_id text NOT NULL,
 observed_at bigint NOT NULL,
 received_at bigint NOT NULL,
 PRIMARY KEY(tenant_id,journal,generation,scope,coverage,field)
);
ALTER TABLE mdm.inventory ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm.inventory FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm.inventory
 USING (tenant_id = nullif(current_setting('rss.tenant_id',true),'')::uuid)
 WITH CHECK (tenant_id = nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON SCHEMA mdm FROM PUBLIC;
REVOKE ALL ON mdm.inventory FROM PUBLIC;
GRANT USAGE ON SCHEMA mdm,rss_observation,rss_projection TO mdm_runtime;
GRANT SELECT,INSERT,UPDATE,DELETE ON mdm.inventory TO mdm_runtime;
GRANT SELECT ON rss_observation.objects,rss_observation.streams,rss_observation.batches,rss_observation.journals,
 rss_projection.sources,rss_projection.events,rss_projection.checkpoints,rss_projection.receipts TO mdm_runtime;
GRANT EXECUTE ON FUNCTION
 rss_observation.activate(text,numeric,text,text),rss_observation.lock_stream(text),
 rss_observation.commit_batch(text,text,numeric,bytea,bytea,bigint,text,text,numeric,boolean),
 rss_projection.assert_tenant(uuid),
 rss_projection.initialize(uuid,text,text,text,bigint,boolean,bigint,text[],bytea[],bytea),
 rss_projection.takeover(uuid,text,text,text,uuid,bytea),
 rss_projection.lock_event(uuid,text,text,text,bigint,uuid,bigint,bigint,text,bytea,bytea),
 rss_projection.finish_event(uuid,text,text,text,bigint,uuid,bigint,bigint,text,bytea,bytea)
 TO mdm_runtime;
