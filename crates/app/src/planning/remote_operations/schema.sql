CREATE TABLE mdm_planning.remote_operations (
 tenant_id uuid NOT NULL,id uuid NOT NULL,resource text NOT NULL,resource_version text NOT NULL,
 frozen jsonb NOT NULL CHECK(octet_length(frozen::text)<=1048576),snapshot jsonb NOT NULL CHECK(octet_length(snapshot::text)<=4194304),
 created_at bigint NOT NULL,deadline bigint NOT NULL CHECK(deadline>created_at),author jsonb NOT NULL,
 cancelled boolean NOT NULL DEFAULT false,staged boolean NOT NULL DEFAULT false,cursor text,run_after uuid,
 PRIMARY KEY(tenant_id,id)
);
CREATE TABLE mdm_planning.remote_operation_targets (
 tenant_id uuid NOT NULL,operation uuid NOT NULL,device text NOT NULL,status text NOT NULL CHECK(status IN('accepted','blocked')),
 delivery_id uuid,diagnosis text,PRIMARY KEY(tenant_id,operation,device),
 FOREIGN KEY(tenant_id,operation) REFERENCES mdm_planning.remote_operations(tenant_id,id),
 CHECK((status='accepted')=(delivery_id IS NOT NULL))
);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['remote_operations','remote_operation_targets'] LOOP
 EXECUTE format('ALTER TABLE mdm_planning.%I ENABLE ROW LEVEL SECURITY',t);
 EXECUTE format('ALTER TABLE mdm_planning.%I FORCE ROW LEVEL SECURITY',t);
 EXECUTE format('CREATE POLICY tenant ON mdm_planning.%I USING(tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid) WITH CHECK(tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid)',t);
 END LOOP;
END $$;
GRANT SELECT,INSERT ON mdm_planning.remote_operations TO mdm_flow_runtime;
GRANT SELECT ON mdm_planning.remote_operations,mdm_planning.remote_operation_targets TO mdm_command_runtime,mdm_flow_runtime;
GRANT UPDATE(cancelled) ON mdm_planning.remote_operations TO mdm_flow_runtime;
GRANT UPDATE(staged,cursor,run_after) ON mdm_planning.remote_operations TO mdm_command_runtime;
GRANT INSERT ON mdm_planning.remote_operation_targets TO mdm_command_runtime;
CREATE FUNCTION mdm_planning.remote_target_page(p_operation uuid,p_after text,p_limit integer)
RETURNS TABLE(device text) LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $page$
 WITH operation AS (SELECT snapshot FROM mdm_planning.remote_operations WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND id=p_operation), targets AS (
 SELECT jsonb_array_elements_text(snapshot->'devices') AS device FROM operation WHERE snapshot->>'kind'='devices'
 UNION ALL SELECT r.device FROM operation o JOIN mdm_planning.scope_results r ON r.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND r.run=CASE WHEN o.snapshot->>'kind'='scope' THEN (o.snapshot->>'result')::uuid END WHERE r.matched
 ) SELECT device FROM targets WHERE device>coalesce(p_after,'') COLLATE "C" ORDER BY device COLLATE "C" LIMIT greatest(0,least(p_limit,65));
$page$;
REVOKE ALL ON FUNCTION mdm_planning.remote_target_page(uuid,text,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mdm_planning.remote_target_page(uuid,text,integer) TO mdm_command_runtime;
ALTER TABLE mdm_commands.operations ADD COLUMN source_kind text NOT NULL DEFAULT 'direct' CHECK(source_kind IN('direct','policy','remote_operation')),
 ADD COLUMN policy_version uuid,ADD COLUMN remote_operation uuid,
 ADD CONSTRAINT operation_source CHECK((source_kind='direct' AND policy_version IS NULL AND remote_operation IS NULL) OR(source_kind='policy' AND policy_version IS NOT NULL AND remote_operation IS NULL) OR(source_kind='remote_operation' AND policy_version IS NULL AND remote_operation IS NOT NULL)),
 ADD FOREIGN KEY(tenant_id,policy_version) REFERENCES mdm_policy.versions(tenant_id,id),
 ADD FOREIGN KEY(tenant_id,remote_operation,device) REFERENCES mdm_planning.remote_operation_targets(tenant_id,operation,device);
CREATE UNIQUE INDEX remote_native_once ON mdm_commands.operations(tenant_id,remote_operation,device) WHERE remote_operation IS NOT NULL;

ALTER TABLE mdm_commands.operations ADD CONSTRAINT operation_authority_source CHECK(coalesce(
 CASE source_kind
 WHEN 'direct' THEN approval->>'kind'='user'
 WHEN 'policy' THEN approval->>'kind'='policy' AND approval->>'tenant'=tenant_id::text AND approval->>'device'=device AND approval->>'version'=policy_version::text
 WHEN 'remote_operation' THEN approval->>'kind'='remote_operation' AND approval->>'tenant'=tenant_id::text AND approval->>'device'=device AND approval->>'operation'=remote_operation::text
 END,false));
