BEGIN;
GRANT USAGE ON SCHEMA rss_da TO da_access,da_command_runtime,da_policy_runtime,da_inventory_runtime,da_scope_runtime,da_identity_runtime;
GRANT SELECT(instance_id,target,lineage) ON rss_da.installation_binding TO da_access,da_command_runtime,da_policy_runtime;
GRANT SELECT ON rss_da.installation_units TO da_access;
GRANT SELECT(instance_id,management_tenant_id) ON rss_da.authorization_installation TO da_command_runtime,da_policy_runtime,da_scope_runtime,da_inventory_runtime;
GRANT USAGE ON SCHEMA mdm,mdm_group TO da_access,da_command_runtime,da_scope_runtime,da_policy_runtime,da_inventory_runtime;
GRANT SELECT ON mdm.asset_epochs,mdm.asset_changes,mdm.inventory_history,mdm.inventory,mdm.field_versions,mdm.array_versions,mdm.array_items,mdm.collection_definitions,mdm.collection_results,mdm.manual_assignments TO da_access,da_command_runtime,da_scope_runtime,da_policy_runtime,da_inventory_runtime;
GRANT EXECUTE ON FUNCTION mdm.record_asset_change(uuid,text,jsonb,text[]) TO da_access,da_command_runtime,da_inventory_runtime;
GRANT EXECUTE ON FUNCTION mdm_group.scope_dependencies(uuid),mdm_group.lock_scope_dependencies(uuid[]),mdm_group.scope_source(uuid) TO da_owner;
GRANT USAGE ON SCHEMA rss_audit TO da_access,da_command_runtime,da_policy_runtime,da_scope_runtime,da_identity_runtime,da_identity_maintenance,da_identity_provisioning;
GRANT SELECT ON rss_audit.records TO da_access,da_command_runtime,da_policy_runtime,da_scope_runtime,da_identity_runtime,da_identity_maintenance,da_identity_provisioning;
GRANT EXECUTE ON FUNCTION rss_audit.append_batch(uuid,text[],text[],bigint[],bytea[],bigint[]) TO da_access,da_command_runtime,da_policy_runtime,da_scope_runtime,da_identity_runtime,da_identity_maintenance,da_identity_provisioning;
GRANT USAGE ON SCHEMA rss_transactional_messaging TO da_access,da_command_runtime,da_policy_runtime;
GRANT SELECT ON rss_transactional_messaging.policy,rss_transactional_messaging.outbox TO da_access,da_command_runtime,da_policy_runtime;
GRANT EXECUTE ON FUNCTION rss_transactional_messaging.check_execution(),rss_transactional_messaging.prepare_outbox_partitions(jsonb),rss_transactional_messaging.append_outbox(bytea,jsonb) TO da_access,da_command_runtime,da_policy_runtime;
GRANT EXECUTE ON FUNCTION mdm.capture_asset_cut(uuid),mdm.asset_cut_contains(jsonb,uuid,xid8),mdm.asset_visible(jsonb,bigint) TO da_access,da_command_runtime,da_scope_runtime,da_policy_runtime,da_inventory_runtime;
GRANT USAGE ON SCHEMA mdm_group TO da_owner;


GRANT USAGE ON SCHEMA rss_transactional_messaging TO da_policy_runtime;
GRANT USAGE ON SCHEMA rss_transactional_messaging TO da_command_runtime;
REVOKE ALL ON FUNCTION rss_transactional_messaging.append_outbox(p_message bytea, p_transport jsonb) FROM PUBLIC;
GRANT ALL ON FUNCTION rss_transactional_messaging.append_outbox(p_message bytea, p_transport jsonb) TO da_policy_runtime;
GRANT ALL ON FUNCTION rss_transactional_messaging.append_outbox(p_message bytea, p_transport jsonb) TO da_command_runtime;
REVOKE ALL ON FUNCTION rss_transactional_messaging.apply_dr(p_operation uuid, p_digest bytea, p_kind text, p_evidence jsonb, p_members jsonb, p_expected bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION rss_transactional_messaging.archive_claim(p_op uuid, p_id uuid, p_version bigint, p_digest bytea, p_hot bigint, p_cold bigint, p_hold boolean, p_ttl bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION rss_transactional_messaging.archive_fault(p_op uuid, p_token uuid, p_digest bytea, p_fault text) FROM PUBLIC;
REVOKE ALL ON FUNCTION rss_transactional_messaging.archive_fence(p_op uuid, p_token uuid, p_digest bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION rss_transactional_messaging.archive_missing(p_op uuid, p_token uuid, p_digest bytea, p_generation uuid, p_object jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION rss_transactional_messaging.archive_prepare(p_op uuid, p_token uuid, p_digest bytea, p_object jsonb, p_bytes bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION rss_transactional_messaging.archive_purge(p_op uuid, p_token uuid, p_digest bytea, p_object jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION rss_transactional_messaging.archive_record(p_op uuid, p_token uuid, p_digest bytea, p_generation uuid, p_object jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION rss_transactional_messaging.check_execution() FROM PUBLIC;
GRANT ALL ON FUNCTION rss_transactional_messaging.check_execution() TO da_policy_runtime;
GRANT ALL ON FUNCTION rss_transactional_messaging.check_execution() TO da_command_runtime;
REVOKE ALL ON FUNCTION rss_transactional_messaging.claim_outbox(p_tenant uuid, p_domain text, p_limit integer, p_ttl_ms bigint) FROM PUBLIC;
GRANT ALL ON FUNCTION rss_transactional_messaging.claim_outbox(p_tenant uuid, p_domain text, p_limit integer, p_ttl_ms bigint) TO da_command_runtime;
GRANT EXECUTE ON FUNCTION rss_transactional_messaging.next_outbox_wakeup(uuid,text) TO da_command_runtime;
REVOKE ALL ON FUNCTION rss_transactional_messaging.decode_outbox_message(data bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION rss_transactional_messaging.guard_archive_generation() FROM PUBLIC;
REVOKE ALL ON FUNCTION rss_transactional_messaging.guard_dr_consumer() FROM PUBLIC;
REVOKE ALL ON FUNCTION rss_transactional_messaging.guard_execution() FROM PUBLIC;
REVOKE ALL ON FUNCTION rss_transactional_messaging.outbox_lease(p_tenant uuid, p_seq bigint, p_token uuid, p_lease_us bigint, p_extend_ms bigint, p_dr uuid) FROM PUBLIC;
GRANT ALL ON FUNCTION rss_transactional_messaging.outbox_lease(p_tenant uuid, p_seq bigint, p_token uuid, p_lease_us bigint, p_extend_ms bigint, p_dr uuid) TO da_command_runtime;
REVOKE ALL ON FUNCTION rss_transactional_messaging.prepare_outbox_partitions(p_partitions jsonb) FROM PUBLIC;
GRANT ALL ON FUNCTION rss_transactional_messaging.prepare_outbox_partitions(p_partitions jsonb) TO da_policy_runtime;
GRANT ALL ON FUNCTION rss_transactional_messaging.prepare_outbox_partitions(p_partitions jsonb) TO da_command_runtime;
REVOKE ALL ON FUNCTION rss_transactional_messaging.read_dr(p_operation uuid, p_digest bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION rss_transactional_messaging.read_outbox_frame(data bytea, pos integer, tag integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION rss_transactional_messaging.settle_outbox(p_tenant uuid, p_seq bigint, p_token uuid, p_lease_us bigint, p_disposition text, p_dr uuid) FROM PUBLIC;
GRANT ALL ON FUNCTION rss_transactional_messaging.settle_outbox(p_tenant uuid, p_seq bigint, p_token uuid, p_lease_us bigint, p_disposition text, p_dr uuid) TO da_command_runtime;
GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE rss_transactional_messaging.inbox TO da_command_runtime;
GRANT SELECT ON TABLE rss_transactional_messaging.outbox TO da_policy_runtime;
GRANT SELECT ON TABLE rss_transactional_messaging.outbox TO da_command_runtime;
GRANT SELECT ON TABLE rss_transactional_messaging.policy TO da_policy_runtime;
GRANT SELECT ON TABLE rss_transactional_messaging.policy TO da_command_runtime;
GRANT USAGE ON SCHEMA rss_transactional_messaging TO da_scope_runtime;
GRANT SELECT ON rss_transactional_messaging.policy,rss_transactional_messaging.outbox TO da_scope_runtime;
REVOKE INSERT ON rss_transactional_messaging.outbox FROM mdm_scope_runtime,mdm_content_runtime,mdm_telemetry_runtime;
REVOKE ALL ON SEQUENCE rss_transactional_messaging.outbox_seq_seq FROM mdm_scope_runtime,mdm_content_runtime,mdm_telemetry_runtime;
GRANT EXECUTE ON FUNCTION rss_transactional_messaging.check_execution(),
 rss_transactional_messaging.prepare_outbox_partitions(jsonb),
 rss_transactional_messaging.append_outbox(bytea,jsonb) TO da_scope_runtime;
GRANT USAGE ON SCHEMA rss_reconcile TO da_command_runtime,da_inventory_runtime,da_scope_runtime,da_policy_runtime;
GRANT SELECT ON TABLE rss_reconcile.targets,rss_reconcile.resources,rss_reconcile.target_resources,rss_reconcile.scans TO da_command_runtime,da_inventory_runtime,da_scope_runtime,da_policy_runtime;
GRANT EXECUTE ON FUNCTION
 rss_reconcile.assert_tenant(uuid),
 rss_reconcile.lock_resources(uuid,text,text,text[],boolean),
 rss_reconcile.bind_resources(uuid,text,text,text[]),
 rss_reconcile.wake(uuid,text,text,text[]),
 rss_reconcile.lock_authority(uuid,text,text,uuid,bigint),
 rss_reconcile.lock_execution(uuid,text,text,uuid,bigint,bigint),
 rss_reconcile.claim_due(uuid,text,integer,bigint),
 rss_reconcile.renew(uuid,text,text,uuid,bigint,bigint,bigint),
 rss_reconcile.finish(uuid,text,text,uuid,bigint,bigint,bigint,text,bigint,bigint),
 rss_reconcile.release(uuid,text,text,uuid,bigint),
 rss_reconcile.mark_applied(uuid,text,text,uuid,bigint,bigint)
 TO da_command_runtime,da_inventory_runtime,da_scope_runtime,da_policy_runtime;
GRANT SELECT,INSERT ON mdm.collection_definitions,mdm.collection_results TO da_access,da_command_runtime;
GRANT EXECUTE ON FUNCTION rss_transactional_messaging.consumer_scope_domain(),rss_transactional_messaging.consumer_inbox_allowed(uuid,text,text),rss_transactional_messaging.projection_scope_matches(text,text) TO da_access;
COMMIT;
