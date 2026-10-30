BEGIN;
CREATE SCHEMA mdm_webhook;
CREATE TABLE mdm_webhook.subscriptions (
 tenant_id uuid NOT NULL, id uuid NOT NULL, revision bigint NOT NULL CHECK(revision>0),
 target_version bigint NOT NULL CHECK(target_version>0), enabled boolean NOT NULL DEFAULT false,
 deleted boolean NOT NULL DEFAULT false, settings jsonb NOT NULL,
 PRIMARY KEY(tenant_id,id), CHECK(NOT deleted OR NOT enabled)
);
CREATE TABLE mdm_webhook.versions (
 tenant_id uuid NOT NULL, subscription uuid NOT NULL, version bigint NOT NULL CHECK(version>0),
 settings jsonb NOT NULL, activated_at timestamptz,
 retired boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,subscription,version),
 FOREIGN KEY(tenant_id,subscription) REFERENCES mdm_webhook.subscriptions(tenant_id,id)
);
CREATE TABLE mdm_webhook.events (
 tenant_id uuid NOT NULL, id uuid NOT NULL, document jsonb NOT NULL, body bytea NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id)
);
CREATE TABLE mdm_webhook.compliance_sources (
 tenant_id uuid NOT NULL, id uuid NOT NULL, document jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(), cursor text, complete boolean NOT NULL DEFAULT false, PRIMARY KEY(tenant_id,id)
);
CREATE TABLE mdm_webhook.fanout (
 tenant_id uuid NOT NULL, id uuid NOT NULL, snapshot jsonb NOT NULL,
 cursor integer NOT NULL DEFAULT 0 CHECK(cursor>=0), complete boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,id)
);
CREATE TABLE mdm_webhook.deliveries (
 tenant_id uuid NOT NULL, id uuid NOT NULL, event_id uuid NOT NULL,
 subscription uuid NOT NULL, target_version bigint NOT NULL,
 fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),
 source_delivery uuid, operation_id uuid,
 attempts bigint NOT NULL DEFAULT 0, last_outcome text, last_stage text, last_reason text,
 PRIMARY KEY(tenant_id,id),
 FOREIGN KEY(tenant_id,event_id) REFERENCES mdm_webhook.events(tenant_id,id),
 FOREIGN KEY(tenant_id,subscription,target_version) REFERENCES mdm_webhook.versions(tenant_id,subscription,version),
 FOREIGN KEY(tenant_id,source_delivery) REFERENCES mdm_webhook.deliveries(tenant_id,id),
 UNIQUE(tenant_id,event_id,subscription,target_version,operation_id)
);
CREATE UNIQUE INDEX webhook_automatic_delivery ON mdm_webhook.deliveries(tenant_id,event_id,subscription,target_version) WHERE operation_id IS NULL;
CREATE TABLE mdm_webhook.operations (
 tenant_id uuid NOT NULL, id uuid NOT NULL, fingerprint bytea NOT NULL, response jsonb NOT NULL,
 PRIMARY KEY(tenant_id,id)
);
DO $$DECLARE n text; BEGIN
 FOREACH n IN ARRAY ARRAY['subscriptions','versions','events','compliance_sources','fanout','deliveries','operations'] LOOP
  EXECUTE format('ALTER TABLE mdm_webhook.%I ENABLE ROW LEVEL SECURITY',n);
  EXECUTE format('ALTER TABLE mdm_webhook.%I FORCE ROW LEVEL SECURITY',n);
  EXECUTE format('CREATE POLICY tenant ON mdm_webhook.%I USING (tenant_id=NULLIF(current_setting(''rss.tenant_id'',true),'''')::uuid) WITH CHECK (tenant_id=NULLIF(current_setting(''rss.tenant_id'',true),'''')::uuid)',n);
 END LOOP;
END$$;
GRANT USAGE ON SCHEMA mdm_webhook TO mdm_access,mdm_command_runtime,mdm_inventory_runtime,mdm_runtime;
GRANT SELECT,INSERT ON ALL TABLES IN SCHEMA mdm_webhook TO mdm_access,mdm_command_runtime,mdm_inventory_runtime,mdm_runtime;
GRANT UPDATE(revision,target_version,enabled,deleted,settings) ON mdm_webhook.subscriptions TO mdm_access,mdm_command_runtime,mdm_inventory_runtime,mdm_runtime;
GRANT UPDATE(retired) ON mdm_webhook.versions TO mdm_access,mdm_command_runtime,mdm_inventory_runtime,mdm_runtime;
GRANT UPDATE(cursor,complete) ON mdm_webhook.compliance_sources TO mdm_access,mdm_command_runtime,mdm_inventory_runtime,mdm_runtime;
GRANT UPDATE(cursor,complete) ON mdm_webhook.fanout TO mdm_access,mdm_command_runtime,mdm_inventory_runtime,mdm_runtime;
GRANT UPDATE(attempts,last_outcome,last_stage,last_reason) ON mdm_webhook.deliveries TO mdm_access,mdm_command_runtime,mdm_inventory_runtime,mdm_runtime;
GRANT SELECT ON rss_transactional_messaging.policy,rss_transactional_messaging.outbox TO mdm_access;
GRANT EXECUTE ON FUNCTION rss_transactional_messaging.check_execution(),rss_transactional_messaging.append_outbox(bytea,jsonb) TO mdm_access;
GRANT USAGE ON SCHEMA mdm_group TO mdm_command_runtime;
GRANT SELECT ON mdm_group.groups,mdm_group.member_runs,mdm_group.member_changes TO mdm_command_runtime;
GRANT USAGE ON SCHEMA mdm_compliance TO mdm_command_runtime;
GRANT SELECT ON mdm_compliance.results TO mdm_command_runtime;
GRANT USAGE ON SCHEMA rss_transactional_messaging TO mdm_webhook_operator;
GRANT SELECT ON rss_transactional_messaging.policy,rss_transactional_messaging.outbox,rss_transactional_messaging.recovery_operations TO mdm_webhook_operator;
GRANT SELECT,INSERT,UPDATE,DELETE ON rss_transactional_messaging.inbox TO mdm_webhook_operator;
GRANT SELECT,INSERT ON rss_transactional_messaging.consumer_dead_letter TO mdm_webhook_operator;
GRANT UPDATE(status,recovery_version,lease_token,lease_until,retry_after) ON rss_transactional_messaging.outbox TO mdm_webhook_operator;
GRANT UPDATE(recovery_version) ON rss_transactional_messaging.consumer_dead_letter TO mdm_webhook_operator;
GRANT INSERT ON rss_transactional_messaging.recovery_operations TO mdm_webhook_operator;
GRANT EXECUTE ON FUNCTION rss_transactional_messaging.check_execution(),rss_transactional_messaging.prepare_outbox_partitions(jsonb),rss_transactional_messaging.append_outbox(bytea,jsonb),rss_transactional_messaging.claim_outbox(uuid,text,integer,bigint),rss_transactional_messaging.next_outbox_wakeup(uuid,text),rss_transactional_messaging.outbox_lease(uuid,bigint,uuid,bigint,bigint,uuid),rss_transactional_messaging.settle_outbox(uuid,bigint,uuid,bigint,text,uuid) TO mdm_webhook_operator;
GRANT USAGE ON SCHEMA mdm_webhook TO mdm_identity_runtime;
GRANT SELECT,INSERT ON mdm_webhook.events TO mdm_identity_runtime;
COMMIT;
