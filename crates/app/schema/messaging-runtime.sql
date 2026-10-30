
-- Explicit integration privileges owned by this capability.
GRANT USAGE ON SCHEMA rss_transactional_messaging TO rss_tmsg_relay;

GRANT USAGE ON SCHEMA rss_transactional_messaging TO mdm_resource_runtime;

GRANT USAGE ON SCHEMA rss_transactional_messaging TO mdm_software_release_runtime;

GRANT USAGE ON SCHEMA rss_transactional_messaging TO mdm_group_runtime;

GRANT USAGE ON SCHEMA rss_transactional_messaging TO mdm_policy_runtime;

GRANT USAGE ON SCHEMA rss_transactional_messaging TO mdm_identity_runtime;

GRANT USAGE ON SCHEMA rss_transactional_messaging TO mdm_identity_maintenance;

GRANT USAGE ON SCHEMA rss_transactional_messaging TO mdm_command_runtime;

REVOKE ALL ON FUNCTION rss_transactional_messaging.append_outbox(p_message bytea, p_transport jsonb) FROM PUBLIC;

GRANT ALL ON FUNCTION rss_transactional_messaging.append_outbox(p_message bytea, p_transport jsonb) TO mdm_group_runtime;

GRANT ALL ON FUNCTION rss_transactional_messaging.append_outbox(p_message bytea, p_transport jsonb) TO mdm_policy_runtime;

GRANT ALL ON FUNCTION rss_transactional_messaging.append_outbox(p_message bytea, p_transport jsonb) TO mdm_resource_runtime;

GRANT ALL ON FUNCTION rss_transactional_messaging.append_outbox(p_message bytea, p_transport jsonb) TO mdm_software_release_runtime;

GRANT ALL ON FUNCTION rss_transactional_messaging.append_outbox(p_message bytea, p_transport jsonb) TO mdm_identity_runtime;

GRANT ALL ON FUNCTION rss_transactional_messaging.append_outbox(p_message bytea, p_transport jsonb) TO mdm_identity_maintenance;

GRANT ALL ON FUNCTION rss_transactional_messaging.append_outbox(p_message bytea, p_transport jsonb) TO mdm_command_runtime;

REVOKE ALL ON FUNCTION rss_transactional_messaging.apply_dr(p_operation uuid, p_digest bytea, p_kind text, p_evidence jsonb, p_members jsonb, p_expected bigint) FROM PUBLIC;

REVOKE ALL ON FUNCTION rss_transactional_messaging.archive_claim(p_op uuid, p_id uuid, p_version bigint, p_digest bytea, p_hot bigint, p_cold bigint, p_hold boolean, p_ttl bigint) FROM PUBLIC;

REVOKE ALL ON FUNCTION rss_transactional_messaging.archive_fault(p_op uuid, p_token uuid, p_digest bytea, p_fault text) FROM PUBLIC;

REVOKE ALL ON FUNCTION rss_transactional_messaging.archive_fence(p_op uuid, p_token uuid, p_digest bytea) FROM PUBLIC;

REVOKE ALL ON FUNCTION rss_transactional_messaging.archive_missing(p_op uuid, p_token uuid, p_digest bytea, p_generation uuid, p_object jsonb) FROM PUBLIC;

REVOKE ALL ON FUNCTION rss_transactional_messaging.archive_prepare(p_op uuid, p_token uuid, p_digest bytea, p_object jsonb, p_bytes bytea) FROM PUBLIC;

REVOKE ALL ON FUNCTION rss_transactional_messaging.archive_purge(p_op uuid, p_token uuid, p_digest bytea, p_object jsonb) FROM PUBLIC;

REVOKE ALL ON FUNCTION rss_transactional_messaging.archive_record(p_op uuid, p_token uuid, p_digest bytea, p_generation uuid, p_object jsonb) FROM PUBLIC;

REVOKE ALL ON FUNCTION rss_transactional_messaging.check_execution() FROM PUBLIC;

GRANT ALL ON FUNCTION rss_transactional_messaging.check_execution() TO mdm_resource_runtime;

GRANT ALL ON FUNCTION rss_transactional_messaging.check_execution() TO mdm_software_release_runtime;

GRANT ALL ON FUNCTION rss_transactional_messaging.check_execution() TO mdm_group_runtime;

GRANT ALL ON FUNCTION rss_transactional_messaging.check_execution() TO mdm_policy_runtime;

GRANT ALL ON FUNCTION rss_transactional_messaging.check_execution() TO mdm_identity_runtime;

GRANT ALL ON FUNCTION rss_transactional_messaging.check_execution() TO mdm_identity_maintenance;

GRANT ALL ON FUNCTION rss_transactional_messaging.check_execution() TO mdm_command_runtime;

REVOKE ALL ON FUNCTION rss_transactional_messaging.claim_outbox(p_tenant uuid, p_domain text, p_limit integer, p_ttl_ms bigint) FROM PUBLIC;

GRANT ALL ON FUNCTION rss_transactional_messaging.claim_outbox(p_tenant uuid, p_domain text, p_limit integer, p_ttl_ms bigint) TO mdm_command_runtime;

GRANT EXECUTE ON FUNCTION rss_transactional_messaging.next_outbox_wakeup(uuid,text) TO mdm_command_runtime;

REVOKE ALL ON FUNCTION rss_transactional_messaging.decode_outbox_message(data bytea) FROM PUBLIC;

REVOKE ALL ON FUNCTION rss_transactional_messaging.guard_archive_generation() FROM PUBLIC;

REVOKE ALL ON FUNCTION rss_transactional_messaging.guard_dr_consumer() FROM PUBLIC;

REVOKE ALL ON FUNCTION rss_transactional_messaging.guard_execution() FROM PUBLIC;

REVOKE ALL ON FUNCTION rss_transactional_messaging.outbox_lease(p_tenant uuid, p_seq bigint, p_token uuid, p_lease_us bigint, p_extend_ms bigint, p_dr uuid) FROM PUBLIC;

GRANT ALL ON FUNCTION rss_transactional_messaging.outbox_lease(p_tenant uuid, p_seq bigint, p_token uuid, p_lease_us bigint, p_extend_ms bigint, p_dr uuid) TO mdm_command_runtime;

REVOKE ALL ON FUNCTION rss_transactional_messaging.prepare_outbox_partitions(p_partitions jsonb) FROM PUBLIC;

GRANT ALL ON FUNCTION rss_transactional_messaging.prepare_outbox_partitions(p_partitions jsonb) TO mdm_group_runtime;

GRANT ALL ON FUNCTION rss_transactional_messaging.prepare_outbox_partitions(p_partitions jsonb) TO mdm_policy_runtime;

GRANT ALL ON FUNCTION rss_transactional_messaging.prepare_outbox_partitions(p_partitions jsonb) TO mdm_resource_runtime;

GRANT ALL ON FUNCTION rss_transactional_messaging.prepare_outbox_partitions(p_partitions jsonb) TO mdm_software_release_runtime;

GRANT ALL ON FUNCTION rss_transactional_messaging.prepare_outbox_partitions(p_partitions jsonb) TO mdm_identity_runtime;

GRANT ALL ON FUNCTION rss_transactional_messaging.prepare_outbox_partitions(p_partitions jsonb) TO mdm_identity_maintenance;

GRANT ALL ON FUNCTION rss_transactional_messaging.prepare_outbox_partitions(p_partitions jsonb) TO mdm_command_runtime;

REVOKE ALL ON FUNCTION rss_transactional_messaging.read_dr(p_operation uuid, p_digest bytea) FROM PUBLIC;

REVOKE ALL ON FUNCTION rss_transactional_messaging.read_outbox_frame(data bytea, pos integer, tag integer) FROM PUBLIC;

REVOKE ALL ON FUNCTION rss_transactional_messaging.settle_outbox(p_tenant uuid, p_seq bigint, p_token uuid, p_lease_us bigint, p_disposition text, p_dr uuid) FROM PUBLIC;

GRANT ALL ON FUNCTION rss_transactional_messaging.settle_outbox(p_tenant uuid, p_seq bigint, p_token uuid, p_lease_us bigint, p_disposition text, p_dr uuid) TO mdm_command_runtime;

GRANT SELECT,INSERT,UPDATE ON TABLE rss_transactional_messaging.dr_members TO rss_tmsg_relay;

GRANT SELECT,INSERT,UPDATE ON TABLE rss_transactional_messaging.dr_plans TO rss_tmsg_relay;

GRANT SELECT ON TABLE rss_transactional_messaging.inbox TO rss_tmsg_relay;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE rss_transactional_messaging.inbox TO mdm_command_runtime;

GRANT SELECT,INSERT,UPDATE ON TABLE rss_transactional_messaging.outbox TO rss_tmsg_relay;

GRANT SELECT ON TABLE rss_transactional_messaging.outbox TO mdm_resource_runtime;

GRANT SELECT ON TABLE rss_transactional_messaging.outbox TO mdm_software_release_runtime;

GRANT SELECT ON TABLE rss_transactional_messaging.outbox TO mdm_group_runtime;

GRANT SELECT ON TABLE rss_transactional_messaging.outbox TO mdm_policy_runtime;

GRANT SELECT ON TABLE rss_transactional_messaging.outbox TO mdm_identity_runtime;

GRANT SELECT ON TABLE rss_transactional_messaging.outbox TO mdm_identity_maintenance;

GRANT SELECT ON TABLE rss_transactional_messaging.outbox TO mdm_command_runtime;

GRANT SELECT,INSERT,UPDATE ON TABLE rss_transactional_messaging.outbox_partitions TO rss_tmsg_relay;

GRANT USAGE ON SEQUENCE rss_transactional_messaging.outbox_seq_seq TO rss_tmsg_relay;

GRANT SELECT ON TABLE rss_transactional_messaging.policy TO mdm_resource_runtime;

GRANT SELECT ON TABLE rss_transactional_messaging.policy TO mdm_software_release_runtime;

GRANT SELECT ON TABLE rss_transactional_messaging.policy TO mdm_group_runtime;

GRANT SELECT ON TABLE rss_transactional_messaging.policy TO mdm_policy_runtime;

GRANT SELECT ON TABLE rss_transactional_messaging.policy TO mdm_identity_runtime;

GRANT SELECT ON TABLE rss_transactional_messaging.policy TO mdm_identity_maintenance;

GRANT SELECT ON TABLE rss_transactional_messaging.policy TO mdm_command_runtime;

GRANT SELECT ON TABLE rss_transactional_messaging.storage_lineage TO rss_tmsg_relay;

GRANT UPDATE(singleton) ON TABLE rss_transactional_messaging.storage_lineage TO rss_tmsg_relay;

GRANT SELECT,UPDATE ON TABLE rss_transactional_messaging.tenant_epoch TO rss_tmsg_relay;

-- Additional independent transaction initiators use the same public RSS producer contract.
-- Public Outbox writer admission; existing product schema units stay immutable.
BEGIN;
GRANT USAGE ON SCHEMA rss_transactional_messaging TO mdm_scope_runtime,mdm_content_runtime,mdm_telemetry_runtime;
GRANT SELECT ON rss_transactional_messaging.policy,rss_transactional_messaging.outbox TO mdm_scope_runtime,mdm_content_runtime,mdm_telemetry_runtime;
REVOKE INSERT ON rss_transactional_messaging.outbox FROM mdm_scope_runtime,mdm_content_runtime,mdm_telemetry_runtime;
REVOKE ALL ON SEQUENCE rss_transactional_messaging.outbox_seq_seq FROM mdm_scope_runtime,mdm_content_runtime,mdm_telemetry_runtime;
GRANT EXECUTE ON FUNCTION rss_transactional_messaging.check_execution(),
 rss_transactional_messaging.prepare_outbox_partitions(jsonb),
 rss_transactional_messaging.append_outbox(bytea,jsonb) TO mdm_scope_runtime,mdm_content_runtime,mdm_telemetry_runtime;
COMMIT;
