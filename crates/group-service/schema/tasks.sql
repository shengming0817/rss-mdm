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
GRANT SELECT,INSERT ON mdm_assets.group_selections TO mdm_inventory_runtime;
CREATE TABLE mdm_assets.group_tasks (
 tenant_id uuid NOT NULL,id uuid NOT NULL,target uuid NOT NULL,
 expected_epoch bigint NOT NULL CHECK(expected_epoch>0),
 kind text NOT NULL CHECK(kind IN('group_definition','group')),
 input jsonb NOT NULL CHECK(octet_length(input::text)<=1048576),
 completed boolean NOT NULL DEFAULT false,
 cursor uuid,definition_progress jsonb,replacement_task uuid,
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
  EXECUTE format($policy$CREATE POLICY tenant ON mdm_assets.%I USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)$policy$,t);
  EXECUTE format('REVOKE ALL ON mdm_assets.%I FROM PUBLIC',t);
  EXECUTE format('GRANT SELECT,INSERT ON mdm_assets.%I TO mdm_inventory_runtime',t);
 END LOOP;
END $$;
GRANT UPDATE(completed,cursor,definition_progress,replacement_task,failure) ON mdm_assets.group_tasks TO mdm_inventory_runtime;
GRANT UPDATE(binding) ON mdm_assets.group_evaluations TO mdm_inventory_runtime;
GRANT UPDATE(state) ON mdm_assets.group_evaluation_arrays TO mdm_inventory_runtime;
GRANT DELETE ON mdm_assets.group_evaluations,mdm_assets.group_evaluation_arrays TO mdm_inventory_runtime;
CREATE TABLE mdm_assets.group_dispatch (
 tenant_id uuid PRIMARY KEY,expected_epoch bigint NOT NULL CHECK(expected_epoch>0),from_cut jsonb, to_cut jsonb,
 input_failed boolean NOT NULL DEFAULT false,
 event_after bigint NOT NULL DEFAULT 0 CHECK(event_after>=0),
 page_through bigint CHECK(page_through>event_after),cursor uuid,
 relation_revision bigint NOT NULL DEFAULT 0 CHECK(relation_revision>=0),
 relation_cursor uuid,relation_pending_revision bigint
);
ALTER TABLE mdm_assets.group_dispatch ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_assets.group_dispatch FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_assets.group_dispatch USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON mdm_assets.group_dispatch FROM PUBLIC;
GRANT SELECT,INSERT ON mdm_assets.group_dispatch TO mdm_inventory_runtime;
GRANT UPDATE(input_failed,from_cut,to_cut,event_after,page_through,cursor,relation_revision,relation_cursor,relation_pending_revision) ON mdm_assets.group_dispatch TO mdm_inventory_runtime;

CREATE POLICY delivery_discovery ON mdm_group.operations FOR SELECT TO mdm_owner USING(true);
CREATE POLICY delivery_discovery ON mdm_assets.group_tasks FOR SELECT TO mdm_owner USING(true);
CREATE FUNCTION mdm_group.delivery_scopes(after_tenant uuid,after_epoch bigint) RETURNS TABLE(tenant_id uuid,expected_epoch bigint) LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT tenant_id,expected_epoch FROM ((SELECT DISTINCT tenant_id,expected_epoch FROM mdm_group.operations WHERE after_tenant IS NULL OR (tenant_id,expected_epoch)>(after_tenant,after_epoch) ORDER BY tenant_id,expected_epoch LIMIT 32) UNION (SELECT DISTINCT tenant_id,expected_epoch FROM mdm_assets.group_tasks WHERE after_tenant IS NULL OR (tenant_id,expected_epoch)>(after_tenant,after_epoch) ORDER BY tenant_id,expected_epoch LIMIT 32)) work ORDER BY tenant_id,expected_epoch LIMIT 32
$$;
REVOKE ALL ON FUNCTION mdm_group.delivery_scopes(uuid,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mdm_group.delivery_scopes(uuid,bigint) TO mdm_access;
COMMIT;

-- Live reverse membership uses the already admitted product read pool.
GRANT USAGE ON SCHEMA mdm_group,mdm_assets TO mdm_access;
GRANT SELECT ON mdm_group.groups,mdm_group.member_runs,mdm_group.member_changes,mdm_assets.group_fields TO mdm_access;

-- Discovery exposes only original work coordinates; all execution remains tenant-fenced.
CREATE POLICY work_discovery ON mdm_assets.group_tasks FOR SELECT TO mdm_owner USING(true);
CREATE POLICY work_discovery ON mdm_assets.group_dispatch FOR SELECT TO mdm_owner USING(true);
CREATE FUNCTION mdm_assets.group_work_scopes(after_tenant uuid) RETURNS TABLE(tenant_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT tenant_id FROM (
  (SELECT DISTINCT tenant_id FROM mdm_assets.group_dispatch WHERE after_tenant IS NULL OR tenant_id>after_tenant ORDER BY tenant_id LIMIT 32)
  UNION (SELECT DISTINCT tenant_id FROM mdm_assets.group_tasks WHERE after_tenant IS NULL OR tenant_id>after_tenant ORDER BY tenant_id LIMIT 32)
 ) work ORDER BY tenant_id LIMIT 32
$$;
CREATE FUNCTION mdm_assets.group_work_epoch(t uuid, task uuid) RETURNS bigint
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT expected_epoch FROM mdm_assets.group_tasks WHERE task IS NOT NULL AND tenant_id=t AND id=task
 UNION ALL SELECT expected_epoch FROM mdm_assets.group_dispatch WHERE task IS NULL AND tenant_id=t
$$;
ALTER FUNCTION mdm_assets.group_work_scopes(uuid) OWNER TO mdm_owner;
ALTER FUNCTION mdm_assets.group_work_epoch(uuid,uuid) OWNER TO mdm_owner;
REVOKE ALL ON FUNCTION mdm_assets.group_work_scopes(uuid),mdm_assets.group_work_epoch(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mdm_assets.group_work_scopes(uuid),mdm_assets.group_work_epoch(uuid,uuid) TO mdm_access;
