CREATE TABLE rss_da.inventory_assets (
    tenant_id uuid NOT NULL,
    installation uuid NOT NULL,
    device uuid NOT NULL,
    registration_epoch uuid NOT NULL,
    kind text NOT NULL CHECK (kind IN ('status','application')),
    generation text NOT NULL,
    sequence bigint NOT NULL CHECK (sequence > 0),
    position bigint NOT NULL,
    received_at bigint NOT NULL,
    facts jsonb NOT NULL,
    PRIMARY KEY (tenant_id,installation,device,registration_epoch,kind,generation)
);
ALTER TABLE rss_da.inventory_assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_da.inventory_assets FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON rss_da.inventory_assets
 USING (tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)
 WITH CHECK (tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON rss_da.inventory_assets FROM PUBLIC;
GRANT USAGE ON SCHEMA rss_da,rss_observation,rss_projection,rss_transactional_messaging TO da_report_projection;
GRANT SELECT,INSERT ON rss_da.inventory_assets TO da_report_projection;
GRANT UPDATE(sequence,position,received_at,facts) ON rss_da.inventory_assets TO da_report_projection;
GRANT SELECT ON rss_da.inventory_assets TO da_identity_runtime;
GRANT SELECT,UPDATE(delivery_pending) ON rss_da.report_history TO da_report_projection;
GRANT SELECT ON rss_observation.streams,rss_observation.batches,rss_observation.journals,
 rss_projection.sources,rss_projection.events,rss_projection.checkpoints,rss_projection.receipts TO da_report_projection;
GRANT EXECUTE ON FUNCTION rss_transactional_messaging.check_execution(),
 rss_observation.activate(text,numeric,text,text),rss_observation.lock_stream(text),
 rss_observation.commit_batch(text,text,numeric,bytea,bytea,bigint,text,text,numeric,boolean),
 rss_projection.assert_tenant(uuid),
 rss_projection.initialize(uuid,text,text,text,bigint,boolean,bigint,text[],bytea[],bytea),
 rss_projection.takeover(uuid,text,text,text,uuid,bytea),
 rss_projection.lock_event(uuid,text,text,text,bigint,uuid,bigint,bigint,text,bytea,bytea),
 rss_projection.finish_event(uuid,text,text,text,bigint,uuid,bigint,bigint,text,bytea,bytea),
 rss_projection.lock_batch(uuid,text,text,text,bigint,uuid,bigint,bigint[],text[],bytea[],bytea),
 rss_projection.finish_batch(uuid,text,text,text,bigint,uuid,bigint,bigint[],text[],bytea[],bytea)
 TO da_report_projection;
GRANT USAGE ON SCHEMA rss_observation TO da_observation_maintenance;
GRANT EXECUTE ON FUNCTION rss_observation.reclaim(text,bigint,bigint,numeric,integer) TO da_observation_maintenance;
