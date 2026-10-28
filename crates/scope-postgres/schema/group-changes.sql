CREATE SCHEMA mdm_scope;
REVOKE ALL ON SCHEMA mdm_scope FROM PUBLIC;
CREATE TABLE mdm_scope.group_changes (
 tenant_id uuid NOT NULL,event_id text NOT NULL CHECK(octet_length(event_id) BETWEEN 1 AND 256),
 group_id uuid NOT NULL,cursor uuid,completed boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,event_id)
);
CREATE INDEX group_changes_pending ON mdm_scope.group_changes(tenant_id,event_id) WHERE NOT completed;
ALTER TABLE mdm_scope.group_changes ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_scope.group_changes FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_scope.group_changes USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON mdm_scope.group_changes FROM PUBLIC;
GRANT USAGE ON SCHEMA mdm_scope TO mdm_scope_group_consumer,mdm_flow_runtime;
GRANT SELECT,INSERT ON mdm_scope.group_changes TO mdm_scope_group_consumer;
GRANT SELECT ON mdm_scope.group_changes TO mdm_flow_runtime;
GRANT UPDATE(cursor,completed) ON mdm_scope.group_changes TO mdm_flow_runtime;
GRANT SELECT,INSERT ON rss_transactional_messaging.consumer_dead_letter TO mdm_scope_group_consumer;
