-- Frozen host selection metadata; the criteria remain solely in the Group core rule.
BEGIN;
CREATE TABLE mdm_assets.group_selections (
 tenant_id uuid NOT NULL, group_id uuid NOT NULL, rule_version text NOT NULL,
 selection jsonb NOT NULL CHECK(octet_length(selection::text)<=65536),
 PRIMARY KEY(tenant_id,group_id,rule_version)
);
ALTER TABLE mdm_assets.group_selections ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_assets.group_selections FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_assets.group_selections
 USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid)
 WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
ALTER TABLE mdm_assets.group_selections ADD FOREIGN KEY(tenant_id,group_id,rule_version) REFERENCES mdm_group.rules(tenant_id,group_id,version);
GRANT SELECT,INSERT ON mdm_assets.group_selections TO mdm_flow_runtime;
CREATE TABLE mdm_assets.group_tasks (
 tenant_id uuid NOT NULL,id uuid NOT NULL,target uuid NOT NULL,
 kind text NOT NULL CHECK(kind IN('group_definition','group','group_preview')),
 input jsonb NOT NULL CHECK(octet_length(input::text)<=1048576),
 completed boolean NOT NULL DEFAULT false,
 cursor text,replacement_task uuid,
 authority_revision bigint NOT NULL DEFAULT 0 CHECK(authority_revision>=0),
 failure text CHECK(failure IN('superseded','capacity_exceeded','source_unavailable','invalid_input','storage_invariant','automation_suspended','capability_unknown','owner_conflict','permission_denied')),
 PRIMARY KEY(tenant_id,id),
 CHECK(failure IS NULL OR completed),
 CHECK(replacement_task IS NULL OR replacement_task<>id),
 FOREIGN KEY(tenant_id,replacement_task) REFERENCES mdm_assets.group_tasks(tenant_id,id)
);
CREATE INDEX group_tasks_pending ON mdm_assets.group_tasks(tenant_id,target,id) WHERE NOT completed;
CREATE TABLE mdm_assets.group_evaluations (
 tenant_id uuid NOT NULL,task uuid NOT NULL,binding text NOT NULL CHECK(binding ~ '^[0-9a-f]{64}$'),
 PRIMARY KEY(tenant_id,task),FOREIGN KEY(tenant_id,task) REFERENCES mdm_assets.group_tasks(tenant_id,id)
);
CREATE TABLE mdm_assets.group_evaluation_arrays (
 tenant_id uuid NOT NULL,task uuid NOT NULL,version text NOT NULL CHECK(version ~ '^[0-9a-f]{64}$'),
 state jsonb NOT NULL CHECK(octet_length(state::text)<=1048576),
 PRIMARY KEY(tenant_id,task,version),
 FOREIGN KEY(tenant_id,task) REFERENCES mdm_assets.group_evaluations(tenant_id,task) ON DELETE CASCADE
);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['group_tasks','group_evaluations','group_evaluation_arrays'] LOOP
  EXECUTE format('ALTER TABLE mdm_assets.%I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE mdm_assets.%I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('CREATE POLICY tenant ON mdm_assets.%I USING(tenant_id=nullif(current_setting(''rss.tenant_id'',true),)::uuid) WITH CHECK(tenant_id=nullif(current_setting(rss.tenant_id,true),)::uuid)',t);
  EXECUTE format('REVOKE ALL ON mdm_assets.%I FROM PUBLIC',t);
  EXECUTE format('GRANT SELECT,INSERT ON mdm_assets.%I TO mdm_flow_runtime',t);
 END LOOP;
END $$;
GRANT UPDATE(completed,cursor,replacement_task,authority_revision,failure) ON mdm_assets.group_tasks TO mdm_flow_runtime;
GRANT UPDATE(binding) ON mdm_assets.group_evaluations TO mdm_flow_runtime;
GRANT UPDATE(state) ON mdm_assets.group_evaluation_arrays TO mdm_flow_runtime;
GRANT DELETE ON mdm_assets.group_evaluations,mdm_assets.group_evaluation_arrays TO mdm_flow_runtime;
CREATE TABLE mdm_assets.group_dispatch (
 tenant_id uuid PRIMARY KEY,consumed bigint NOT NULL DEFAULT 0 CHECK(consumed>=0),
 watermark bigint NOT NULL DEFAULT 0 CHECK(watermark>=consumed),cursor text COLLATE "C",
 relation_revision bigint NOT NULL DEFAULT 0 CHECK(relation_revision>=0),
 relation_cursor uuid,relation_pending_revision bigint
);
ALTER TABLE mdm_assets.group_dispatch ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_assets.group_dispatch FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_assets.group_dispatch USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON mdm_assets.group_dispatch FROM PUBLIC;
GRANT SELECT,INSERT ON mdm_assets.group_dispatch TO mdm_flow_runtime;
GRANT UPDATE(consumed,watermark,cursor,relation_revision,relation_cursor,relation_pending_revision) ON mdm_assets.group_dispatch TO mdm_flow_runtime;
COMMIT;
