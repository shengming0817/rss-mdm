-- Fresh installation: inventory-service owns these objects.
BEGIN;
-- Inventory publishes collection changes through the SDK history contract.
ALTER TABLE mdm.asset_changes DROP CONSTRAINT asset_changes_kind_check;
ALTER TABLE mdm.asset_changes ADD CONSTRAINT asset_changes_kind_check
 CHECK(kind IN ('inventory','manual','device','registration','source','credential','collection'));
SET LOCAL check_function_bodies = false;

CREATE TRIGGER collection_history AFTER INSERT OR DELETE OR UPDATE ON mdm_access.collection_runs FOR EACH ROW EXECUTE FUNCTION mdm_access.capture_collection_history();

CREATE TRIGGER immutable_collection BEFORE UPDATE ON mdm_access.collection_runs FOR EACH ROW EXECUTE FUNCTION mdm_access.immutable_collection();

ALTER TABLE ONLY mdm_access.collection_history
    ADD CONSTRAINT collection_history_tenant_id_revision_fkey FOREIGN KEY (tenant_id, revision) REFERENCES mdm.asset_changes(tenant_id, revision);

ALTER TABLE ONLY mdm_access.collection_runs
    ADD CONSTRAINT collection_runs_tenant_id_registration_fkey FOREIGN KEY (tenant_id, registration) REFERENCES mdm_access.registrations(tenant_id, id);

ALTER TABLE ONLY mdm_assets.asset_query_facets
    ADD CONSTRAINT asset_query_facets_tenant_id_run_fkey FOREIGN KEY (tenant_id, run) REFERENCES mdm_assets.asset_query_runs(tenant_id, id);

ALTER TABLE ONLY mdm_assets.asset_query_results
    ADD CONSTRAINT asset_query_results_tenant_id_run_fkey FOREIGN KEY (tenant_id, run) REFERENCES mdm_assets.asset_query_runs(tenant_id, id);

ALTER TABLE ONLY mdm_assets.asset_query_runs
    ADD CONSTRAINT asset_query_runs_tenant_id_id_fkey FOREIGN KEY (tenant_id, id) REFERENCES mdm_automation.automation_jobs(tenant_id, id);

ALTER TABLE ONLY mdm_assets.group_fields
    ADD CONSTRAINT group_fields_tenant_id_group_id_fkey FOREIGN KEY (tenant_id, group_id) REFERENCES mdm_group.groups(tenant_id, id);

GRANT USAGE ON SCHEMA mdm TO mdm_runtime;
GRANT USAGE ON SCHEMA mdm TO mdm_api;
GRANT USAGE ON SCHEMA mdm TO mdm_flow_runtime;
GRANT USAGE ON SCHEMA mdm TO mdm_command_runtime;

GRANT USAGE ON SCHEMA mdm_assets TO mdm_flow_runtime;

GRANT USAGE ON SCHEMA mdm_compliance TO mdm_flow_runtime;

GRANT USAGE ON SCHEMA mdm_group TO mdm_group_runtime;

GRANT USAGE ON SCHEMA mdm_inventory TO mdm_access;

GRANT USAGE ON SCHEMA rss_observation TO mdm_runtime;

GRANT USAGE ON SCHEMA rss_projection TO mdm_runtime;

REVOKE ALL ON FUNCTION mdm.capture_inventory_history() FROM PUBLIC;

REVOKE ALL ON FUNCTION mdm.capture_manual_history() FROM PUBLIC;

REVOKE ALL ON FUNCTION mdm.lock_asset_watermark(t uuid) FROM PUBLIC;
GRANT ALL ON FUNCTION mdm.lock_asset_watermark(t uuid) TO mdm_flow_runtime;

REVOKE ALL ON FUNCTION mdm.record_asset_change(t uuid, k text, i jsonb, f text[]) FROM PUBLIC;
GRANT ALL ON FUNCTION mdm.record_asset_change(t uuid, k text, i jsonb, f text[]) TO mdm_runtime;

REVOKE ALL ON FUNCTION mdm_access.capture_collection_history() FROM PUBLIC;

REVOKE ALL ON FUNCTION mdm_access.immutable_collection() FROM PUBLIC;

REVOKE ALL ON FUNCTION mdm_access.prune_agent_collections(p_registration uuid, p_epoch uuid) FROM PUBLIC;
GRANT ALL ON FUNCTION mdm_access.prune_agent_collections(p_registration uuid, p_epoch uuid) TO mdm_access;

REVOKE ALL ON FUNCTION rss_observation.activate(p_scope text, p_expected numeric, p_policy text, p_initial text) FROM PUBLIC;
GRANT ALL ON FUNCTION rss_observation.activate(p_scope text, p_expected numeric, p_policy text, p_initial text) TO mdm_runtime;

REVOKE ALL ON FUNCTION rss_observation.commit_batch(p_scope text, p_id text, p_sequence numeric, p_raw bytea, p_fingerprint bytea, p_received bigint, p_policy text, p_decision text, p_expected numeric, p_applicable boolean) FROM PUBLIC;
GRANT ALL ON FUNCTION rss_observation.commit_batch(p_scope text, p_id text, p_sequence numeric, p_raw bytea, p_fingerprint bytea, p_received bigint, p_policy text, p_decision text, p_expected numeric, p_applicable boolean) TO mdm_runtime;

GRANT SELECT ON TABLE rss_observation.streams TO mdm_runtime;

REVOKE ALL ON FUNCTION rss_observation.lock_stream(p_scope text) FROM PUBLIC;
GRANT ALL ON FUNCTION rss_observation.lock_stream(p_scope text) TO mdm_runtime;

REVOKE ALL ON FUNCTION rss_projection.append_event(t uuid, s text, e text, bytes bytea) FROM PUBLIC;

REVOKE ALL ON FUNCTION rss_projection.assert_tenant(t uuid) FROM PUBLIC;
GRANT ALL ON FUNCTION rss_projection.assert_tenant(t uuid) TO mdm_runtime;

REVOKE ALL ON FUNCTION rss_projection.finish_event(t uuid, s text, p text, g text, worker_epoch bigint, token uuid, expected bigint, at_position bigint, e text, digest bytea, definition bytea) FROM PUBLIC;
GRANT ALL ON FUNCTION rss_projection.finish_event(t uuid, s text, p text, g text, worker_epoch bigint, token uuid, expected bigint, at_position bigint, e text, digest bytea, definition bytea) TO mdm_runtime;

REVOKE ALL ON FUNCTION rss_projection.initialize(t uuid, s text, p text, g text, start_at bigint, is_replay boolean, end_at bigint, ids text[], digests bytea[], definition bytea) FROM PUBLIC;
GRANT ALL ON FUNCTION rss_projection.initialize(t uuid, s text, p text, g text, start_at bigint, is_replay boolean, end_at bigint, ids text[], digests bytea[], definition bytea) TO mdm_runtime;

REVOKE ALL ON FUNCTION rss_projection.lock_event(t uuid, s text, p text, g text, worker_epoch bigint, token uuid, expected bigint, at_position bigint, e text, digest bytea, definition bytea) FROM PUBLIC;
GRANT ALL ON FUNCTION rss_projection.lock_event(t uuid, s text, p text, g text, worker_epoch bigint, token uuid, expected bigint, at_position bigint, e text, digest bytea, definition bytea) TO mdm_runtime;

REVOKE ALL ON FUNCTION rss_projection.takeover(t uuid, s text, p text, g text, token uuid, definition bytea) FROM PUBLIC;
GRANT ALL ON FUNCTION rss_projection.takeover(t uuid, s text, p text, g text, token uuid, definition bytea) TO mdm_runtime;

GRANT SELECT ON TABLE mdm.asset_changes TO mdm_flow_runtime;

GRANT UPDATE(forwarded) ON TABLE mdm.asset_changes TO mdm_flow_runtime;

GRANT SELECT ON TABLE mdm.asset_clock TO mdm_flow_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE mdm.inventory TO mdm_runtime;
GRANT SELECT ON TABLE mdm.inventory TO mdm_api;
GRANT SELECT ON TABLE mdm.inventory TO mdm_flow_runtime;
GRANT SELECT ON TABLE mdm.inventory TO mdm_command_runtime;

GRANT SELECT ON TABLE mdm.inventory_history TO mdm_flow_runtime;

GRANT SELECT,INSERT ON TABLE mdm.manual_assignments TO mdm_flow_runtime;

GRANT UPDATE(revision) ON TABLE mdm.manual_assignments TO mdm_flow_runtime;

GRANT UPDATE(fact) ON TABLE mdm.manual_assignments TO mdm_flow_runtime;

GRANT SELECT ON TABLE mdm.manual_history TO mdm_flow_runtime;

GRANT SELECT ON TABLE mdm_access.collection_history TO mdm_flow_runtime;

GRANT SELECT,INSERT ON TABLE mdm_access.collection_runs TO mdm_access;
GRANT SELECT ON TABLE mdm_access.collection_runs TO mdm_flow_runtime;
GRANT SELECT,INSERT ON TABLE mdm_access.collection_runs TO mdm_command_runtime;

GRANT UPDATE(attempts) ON TABLE mdm_access.collection_runs TO mdm_access;
GRANT UPDATE(attempts) ON TABLE mdm_access.collection_runs TO mdm_command_runtime;

GRANT UPDATE(result) ON TABLE mdm_access.collection_runs TO mdm_access;
GRANT UPDATE(result) ON TABLE mdm_access.collection_runs TO mdm_command_runtime;

GRANT UPDATE(reason) ON TABLE mdm_access.collection_runs TO mdm_access;
GRANT UPDATE(reason) ON TABLE mdm_access.collection_runs TO mdm_command_runtime;

GRANT UPDATE(batch) ON TABLE mdm_access.collection_runs TO mdm_access;
GRANT UPDATE(batch) ON TABLE mdm_access.collection_runs TO mdm_command_runtime;

GRANT UPDATE(digest) ON TABLE mdm_access.collection_runs TO mdm_access;
GRANT UPDATE(digest) ON TABLE mdm_access.collection_runs TO mdm_command_runtime;

GRANT UPDATE(sealed_at) ON TABLE mdm_access.collection_runs TO mdm_access;
GRANT UPDATE(sealed_at) ON TABLE mdm_access.collection_runs TO mdm_command_runtime;

GRANT UPDATE(delivery_pending) ON TABLE mdm_access.collection_runs TO mdm_access;
GRANT UPDATE(delivery_pending) ON TABLE mdm_access.collection_runs TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_assets.asset_query_facets TO mdm_flow_runtime;

GRANT UPDATE(total) ON TABLE mdm_assets.asset_query_facets TO mdm_flow_runtime;

GRANT SELECT,INSERT ON TABLE mdm_assets.asset_query_results TO mdm_flow_runtime;

GRANT SELECT,INSERT ON TABLE mdm_assets.asset_query_runs TO mdm_flow_runtime;

GRANT UPDATE(total) ON TABLE mdm_assets.asset_query_runs TO mdm_flow_runtime;

GRANT UPDATE(matched) ON TABLE mdm_assets.asset_query_runs TO mdm_flow_runtime;

GRANT UPDATE(unknown) ON TABLE mdm_assets.asset_query_runs TO mdm_flow_runtime;

GRANT SELECT,INSERT,DELETE ON TABLE mdm_assets.group_fields TO mdm_flow_runtime;

GRANT SELECT,INSERT ON TABLE mdm_assets.group_operations TO mdm_flow_runtime;

GRANT SELECT,INSERT ON TABLE mdm_assets.operations TO mdm_flow_runtime;

GRANT SELECT,INSERT ON TABLE mdm_assets.saved_queries TO mdm_flow_runtime;

GRANT UPDATE(revision) ON TABLE mdm_assets.saved_queries TO mdm_flow_runtime;

GRANT UPDATE(document) ON TABLE mdm_assets.saved_queries TO mdm_flow_runtime;

GRANT SELECT,INSERT,DELETE ON TABLE mdm_compliance.fields TO mdm_flow_runtime;

GRANT SELECT,INSERT,DELETE ON TABLE mdm_compliance.groups TO mdm_flow_runtime;

GRANT SELECT,INSERT ON TABLE mdm_compliance.operations TO mdm_flow_runtime;

GRANT SELECT,INSERT ON TABLE mdm_compliance.results TO mdm_flow_runtime;

GRANT SELECT,INSERT ON TABLE mdm_compliance.rules TO mdm_flow_runtime;

GRANT UPDATE(revision) ON TABLE mdm_compliance.rules TO mdm_flow_runtime;

GRANT UPDATE(enabled) ON TABLE mdm_compliance.rules TO mdm_flow_runtime;

GRANT UPDATE(desired) ON TABLE mdm_compliance.rules TO mdm_flow_runtime;

GRANT UPDATE(current_run) ON TABLE mdm_compliance.rules TO mdm_flow_runtime;

GRANT SELECT,INSERT ON TABLE mdm_compliance.versions TO mdm_flow_runtime;

GRANT SELECT,INSERT ON TABLE mdm_group.groups TO mdm_group_runtime;

GRANT UPDATE(name) ON TABLE mdm_group.groups TO mdm_group_runtime;

GRANT UPDATE(description) ON TABLE mdm_group.groups TO mdm_group_runtime;

GRANT UPDATE(revision) ON TABLE mdm_group.groups TO mdm_group_runtime;

GRANT UPDATE(calculation_revision) ON TABLE mdm_group.groups TO mdm_group_runtime;

GRANT UPDATE(member_version) ON TABLE mdm_group.groups TO mdm_group_runtime;

GRANT UPDATE(member_count) ON TABLE mdm_group.groups TO mdm_group_runtime;

GRANT UPDATE(rule_version) ON TABLE mdm_group.groups TO mdm_group_runtime;

GRANT UPDATE(deleted) ON TABLE mdm_group.groups TO mdm_group_runtime;

GRANT UPDATE(member_set) ON TABLE mdm_group.groups TO mdm_group_runtime;

GRANT SELECT,INSERT ON TABLE mdm_group.member_changes TO mdm_group_runtime;

GRANT SELECT,INSERT ON TABLE mdm_group.member_pages TO mdm_group_runtime;

GRANT SELECT,INSERT ON TABLE mdm_group.member_rows TO mdm_group_runtime;

GRANT SELECT,INSERT ON TABLE mdm_group.member_runs TO mdm_group_runtime;

GRANT UPDATE(phase) ON TABLE mdm_group.member_runs TO mdm_group_runtime;

GRANT UPDATE(cursor) ON TABLE mdm_group.member_runs TO mdm_group_runtime;

GRANT UPDATE(diff_cursor) ON TABLE mdm_group.member_runs TO mdm_group_runtime;

GRANT UPDATE(processed_count) ON TABLE mdm_group.member_runs TO mdm_group_runtime;

GRANT UPDATE(object_count) ON TABLE mdm_group.member_runs TO mdm_group_runtime;

GRANT UPDATE(member_count) ON TABLE mdm_group.member_runs TO mdm_group_runtime;

GRANT UPDATE(added) ON TABLE mdm_group.member_runs TO mdm_group_runtime;

GRANT UPDATE(removed) ON TABLE mdm_group.member_runs TO mdm_group_runtime;

GRANT UPDATE(receipt) ON TABLE mdm_group.member_runs TO mdm_group_runtime;

GRANT SELECT,INSERT ON TABLE mdm_group.operations TO mdm_group_runtime;

GRANT SELECT,INSERT ON TABLE mdm_group.rules TO mdm_group_runtime;

GRANT SELECT,INSERT ON TABLE mdm_inventory.collection_operations TO mdm_access;

GRANT SELECT ON TABLE rss_observation.batches TO mdm_runtime;

GRANT SELECT ON TABLE rss_observation.journals TO mdm_runtime;

GRANT SELECT ON TABLE rss_observation.objects TO mdm_runtime;

GRANT SELECT ON TABLE rss_projection.checkpoints TO mdm_runtime;

GRANT SELECT ON TABLE rss_projection.events TO mdm_runtime;

GRANT SELECT ON TABLE rss_projection.receipts TO mdm_runtime;

GRANT SELECT ON TABLE rss_projection.sources TO mdm_runtime;

CREATE OR REPLACE FUNCTION mdm.record_asset_change(t uuid,k text,i jsonb,f text[]) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,mdm AS $$
DECLARE v bigint;
BEGIN
 IF t IS DISTINCT FROM nullif(current_setting('rss.tenant_id',true),'')::uuid THEN
  RAISE EXCEPTION 'asset tenant mismatch' USING ERRCODE='42501';
 END IF;
 INSERT INTO mdm.asset_clock(tenant_id,revision) VALUES(t,1)
 ON CONFLICT(tenant_id) DO UPDATE SET revision=mdm.asset_clock.revision+1
 RETURNING revision INTO v;
 INSERT INTO mdm.asset_changes(tenant_id,revision,kind,identity,fields) VALUES(t,v,k,i,f);
 PERFORM pg_catalog.pg_notify('mdm_work_' || replace(t::text,'-',''),'automation_input');
 RETURN v;
END $$;

COMMIT;
