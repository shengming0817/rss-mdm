-- Fresh installation: flow owns these objects.
BEGIN;

SET LOCAL check_function_bodies = false;

GRANT USAGE ON SCHEMA mdm_flow TO mdm_flow_runtime;

GRANT USAGE ON SCHEMA mdm_planning TO mdm_flow_runtime;

GRANT USAGE ON SCHEMA mdm_planning TO mdm_command_runtime;

GRANT USAGE ON SCHEMA mdm_policy TO mdm_policy_runtime;

GRANT USAGE ON SCHEMA mdm_policy TO mdm_command_runtime;

GRANT USAGE ON SCHEMA mdm_publication TO mdm_flow_runtime;

GRANT USAGE ON SCHEMA mdm_resource TO mdm_resource_runtime;

GRANT USAGE ON SCHEMA mdm_resource TO mdm_command_runtime;


GRANT USAGE ON SCHEMA mdm_software TO mdm_flow_runtime;

GRANT USAGE ON SCHEMA mdm_software TO mdm_command_runtime;

GRANT USAGE ON SCHEMA mdm_software_composition TO mdm_software_driver;

GRANT USAGE ON SCHEMA mdm_software_composition TO mdm_flow_runtime;

GRANT USAGE ON SCHEMA mdm_software_release TO mdm_software_release_runtime;

GRANT USAGE ON SCHEMA rss_device_command TO mdm_command_runtime;

GRANT USAGE ON SCHEMA rss_reconcile TO mdm_command_runtime;

GRANT USAGE ON SCHEMA rss_reconcile TO mdm_flow_runtime;

GRANT USAGE ON SCHEMA rss_transactional_messaging TO rss_tmsg_relay;

GRANT USAGE ON SCHEMA rss_transactional_messaging TO mdm_resource_runtime;

GRANT USAGE ON SCHEMA rss_transactional_messaging TO mdm_software_release_runtime;

GRANT USAGE ON SCHEMA rss_transactional_messaging TO mdm_group_runtime;

GRANT USAGE ON SCHEMA rss_transactional_messaging TO mdm_policy_runtime;

GRANT USAGE ON SCHEMA rss_transactional_messaging TO mdm_identity_runtime;

GRANT USAGE ON SCHEMA rss_transactional_messaging TO mdm_identity_maintenance;

GRANT USAGE ON SCHEMA rss_transactional_messaging TO mdm_command_runtime;

REVOKE ALL ON FUNCTION rss_device_command.advance(t uuid, d uuid, g bigint, e bigint, ng bigint, ne bigint) FROM PUBLIC;

GRANT ALL ON FUNCTION rss_device_command.advance(t uuid, d uuid, g bigint, e bigint, ng bigint, ne bigint) TO mdm_command_runtime;

REVOKE ALL ON FUNCTION rss_device_command.enqueue(t uuid, d uuid, c text, g bigint, e bigint, digest bytea, expires bigint, at_time bigint, m text, f bytea, domain_name text) FROM PUBLIC;

GRANT ALL ON FUNCTION rss_device_command.enqueue(t uuid, d uuid, c text, g bigint, e bigint, digest bytea, expires bigint, at_time bigint, m text, f bytea, domain_name text) TO mdm_command_runtime;

REVOKE ALL ON FUNCTION rss_device_command.initialize(t uuid, d uuid, g bigint, e bigint) FROM PUBLIC;

GRANT ALL ON FUNCTION rss_device_command.initialize(t uuid, d uuid, g bigint, e bigint) TO mdm_command_runtime;

GRANT SELECT ON TABLE rss_device_command.authorities TO mdm_command_runtime;

REVOKE ALL ON FUNCTION rss_device_command.lock_authority(t uuid, d uuid) FROM PUBLIC;

GRANT ALL ON FUNCTION rss_device_command.lock_authority(t uuid, d uuid) TO mdm_command_runtime;

REVOKE ALL ON FUNCTION rss_device_command.save(t uuid, d uuid, c text, v bigint, s text, p bigint, r bigint, done bigint) FROM PUBLIC;

GRANT ALL ON FUNCTION rss_device_command.save(t uuid, d uuid, c text, v bigint, s text, p bigint, r bigint, done bigint) TO mdm_command_runtime;

REVOKE ALL ON FUNCTION rss_reconcile.assert_tenant(t uuid) FROM PUBLIC;

GRANT ALL ON FUNCTION rss_reconcile.assert_tenant(t uuid) TO mdm_command_runtime;

GRANT ALL ON FUNCTION rss_reconcile.assert_tenant(t uuid) TO mdm_flow_runtime;

GRANT SELECT ON TABLE rss_reconcile.targets TO mdm_command_runtime;

GRANT SELECT ON TABLE rss_reconcile.targets TO mdm_flow_runtime;

REVOKE ALL ON FUNCTION rss_reconcile.claim_due(t uuid, r text, n integer, ttl bigint) FROM PUBLIC;

GRANT ALL ON FUNCTION rss_reconcile.claim_due(t uuid, r text, n integer, ttl bigint) TO mdm_command_runtime;

GRANT ALL ON FUNCTION rss_reconcile.claim_due(t uuid, r text, n integer, ttl bigint) TO mdm_flow_runtime;

REVOKE ALL ON FUNCTION rss_reconcile.finish(t uuid, r text, e text, k uuid, g bigint, w bigint, outcome text, delay bigint, f bigint) FROM PUBLIC;

GRANT ALL ON FUNCTION rss_reconcile.finish(t uuid, r text, e text, k uuid, g bigint, w bigint, outcome text, delay bigint, f bigint) TO mdm_command_runtime;

GRANT ALL ON FUNCTION rss_reconcile.finish(t uuid, r text, e text, k uuid, g bigint, w bigint, outcome text, delay bigint, f bigint) TO mdm_flow_runtime;

REVOKE ALL ON FUNCTION rss_reconcile.lock_claim(t uuid, r text, e text, k uuid, g bigint) FROM PUBLIC;

GRANT ALL ON FUNCTION rss_reconcile.lock_claim(t uuid, r text, e text, k uuid, g bigint) TO mdm_command_runtime;

GRANT ALL ON FUNCTION rss_reconcile.lock_claim(t uuid, r text, e text, k uuid, g bigint) TO mdm_flow_runtime;

REVOKE ALL ON FUNCTION rss_reconcile.mark_applied(t uuid, r text, e text, k uuid, g bigint) FROM PUBLIC;

GRANT ALL ON FUNCTION rss_reconcile.mark_applied(t uuid, r text, e text, k uuid, g bigint) TO mdm_command_runtime;

GRANT ALL ON FUNCTION rss_reconcile.mark_applied(t uuid, r text, e text, k uuid, g bigint) TO mdm_flow_runtime;

REVOKE ALL ON FUNCTION rss_reconcile.release(t uuid, r text, e text, k uuid, g bigint) FROM PUBLIC;

GRANT ALL ON FUNCTION rss_reconcile.release(t uuid, r text, e text, k uuid, g bigint) TO mdm_command_runtime;

GRANT ALL ON FUNCTION rss_reconcile.release(t uuid, r text, e text, k uuid, g bigint) TO mdm_flow_runtime;

REVOKE ALL ON FUNCTION rss_reconcile.renew(t uuid, r text, e text, k uuid, g bigint, ttl bigint) FROM PUBLIC;

GRANT ALL ON FUNCTION rss_reconcile.renew(t uuid, r text, e text, k uuid, g bigint, ttl bigint) TO mdm_command_runtime;

GRANT ALL ON FUNCTION rss_reconcile.renew(t uuid, r text, e text, k uuid, g bigint, ttl bigint) TO mdm_flow_runtime;

REVOKE ALL ON FUNCTION rss_reconcile.wake(t uuid, r text, e text) FROM PUBLIC;

GRANT ALL ON FUNCTION rss_reconcile.wake(t uuid, r text, e text) TO mdm_command_runtime;

GRANT ALL ON FUNCTION rss_reconcile.wake(t uuid, r text, e text) TO mdm_flow_runtime;

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

GRANT SELECT,INSERT ON TABLE mdm_publication.operations TO mdm_flow_runtime;

GRANT SELECT,INSERT ON TABLE mdm_resource.aggregates TO mdm_resource_runtime;

GRANT SELECT ON TABLE mdm_resource.aggregates TO mdm_command_runtime;

GRANT UPDATE(revision) ON TABLE mdm_resource.aggregates TO mdm_resource_runtime;

GRANT UPDATE(document) ON TABLE mdm_resource.aggregates TO mdm_resource_runtime;

GRANT UPDATE(digest) ON TABLE mdm_resource.aggregates TO mdm_resource_runtime;

GRANT SELECT,INSERT ON TABLE mdm_resource.artifact_refs TO mdm_resource_runtime;

GRANT UPDATE(archived) ON TABLE mdm_resource.artifact_refs TO mdm_resource_runtime;

GRANT SELECT,INSERT ON TABLE mdm_resource.immutable TO mdm_resource_runtime;

GRANT SELECT ON TABLE mdm_resource.immutable TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_resource.requests TO mdm_resource_runtime;


GRANT SELECT,INSERT ON TABLE mdm_software.versions TO mdm_flow_runtime;

GRANT SELECT ON TABLE mdm_software.versions TO mdm_command_runtime;

GRANT UPDATE(lifecycle) ON TABLE mdm_software.versions TO mdm_flow_runtime;

GRANT SELECT,INSERT ON TABLE mdm_software.materials TO mdm_flow_runtime;

GRANT SELECT ON TABLE mdm_software.materials TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_software.operations TO mdm_flow_runtime;

GRANT SELECT,INSERT ON TABLE mdm_software.sources TO mdm_flow_runtime;

GRANT SELECT ON TABLE mdm_software.sources TO mdm_command_runtime;

GRANT UPDATE(lifecycle) ON TABLE mdm_software.sources TO mdm_flow_runtime;

GRANT SELECT,INSERT ON TABLE mdm_software_composition.authorities TO mdm_software_driver;

GRANT UPDATE(record) ON TABLE mdm_software_composition.authorities TO mdm_software_driver;

GRANT SELECT,INSERT ON TABLE mdm_software_composition.bindings TO mdm_software_driver;

GRANT SELECT,INSERT,DELETE ON TABLE mdm_software_composition.projections TO mdm_software_driver;

GRANT UPDATE(publication) ON TABLE mdm_software_composition.projections TO mdm_software_driver;

GRANT SELECT,INSERT ON TABLE mdm_software_composition.slots TO mdm_software_driver;

GRANT UPDATE(operation) ON TABLE mdm_software_composition.slots TO mdm_software_driver;

GRANT UPDATE(cursor) ON TABLE mdm_software_composition.slots TO mdm_software_driver;

GRANT SELECT,INSERT ON TABLE mdm_software_composition.subjects TO mdm_software_driver;

GRANT SELECT ON TABLE mdm_software_composition.subjects TO mdm_flow_runtime;

GRANT SELECT,INSERT ON TABLE mdm_software_composition.targets TO mdm_software_driver;

GRANT UPDATE(call_generation) ON TABLE mdm_software_composition.targets TO mdm_software_driver;

GRANT UPDATE(attempted) ON TABLE mdm_software_composition.targets TO mdm_software_driver;

GRANT UPDATE(acknowledged) ON TABLE mdm_software_composition.targets TO mdm_software_driver;

GRANT SELECT,INSERT ON TABLE mdm_software_composition.withdrawals TO mdm_software_driver;

GRANT UPDATE(complete) ON TABLE mdm_software_composition.withdrawals TO mdm_software_driver;

GRANT SELECT,INSERT ON TABLE mdm_software_release.aggregates TO mdm_software_release_runtime;

GRANT UPDATE(revision) ON TABLE mdm_software_release.aggregates TO mdm_software_release_runtime;

GRANT UPDATE(document) ON TABLE mdm_software_release.aggregates TO mdm_software_release_runtime;

GRANT UPDATE(digest) ON TABLE mdm_software_release.aggregates TO mdm_software_release_runtime;

GRANT SELECT,INSERT ON TABLE mdm_software_release.immutable TO mdm_software_release_runtime;

GRANT SELECT,INSERT ON TABLE mdm_software_release.requests TO mdm_software_release_runtime;

GRANT SELECT ON TABLE rss_device_command.commands TO mdm_command_runtime;

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

GRANT USAGE ON SCHEMA mdm_policy, mdm_resource, mdm_software, mdm_planning TO mdm_access;

GRANT SELECT ON TABLE mdm_resource.aggregates, mdm_resource.immutable, mdm_software.sources, mdm_software.versions TO mdm_access;



COMMIT;

-- Existing owner roots cover Policy/Scope/Group publication. Only target facts are visited;
-- immutable historical resolution rows never participate in a command read.
CREATE FUNCTION mdm_planning.execution_source_versions(command_id uuid, allowed_devices text[]) RETURNS TABLE(owner text,version text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
WITH commands AS MATERIALIZED (
 SELECT o.id,o.device,o.authority->>'kind' AS kind
 FROM mdm_commands.operations o
 WHERE o.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
 AND (command_id IS NULL OR o.id=command_id)
 AND (allowed_devices IS NULL OR o.device=ANY(allowed_devices))
), targets AS MATERIALIZED (SELECT DISTINCT device FROM commands),
registrations AS MATERIALIZED (
 SELECT r.id FROM mdm_access.registrations r JOIN targets t ON t.device=r.device
 WHERE r.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND r.state='active' AND r.purpose='primary'
)
SELECT 'device-root'::text,query_revision::text||'/'||relation_revision::text||'/'||identity_watermark::text FROM mdm_devices.checkpoints WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
UNION ALL
SELECT 'registration-root',revision::text FROM mdm_access.directory_revisions WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
UNION ALL
SELECT 'software-root',revision::text FROM mdm_software.authority_revision WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND EXISTS(SELECT 1 FROM commands WHERE kind IN('software','agent_install'))
UNION ALL
SELECT 'identity-input',id::text FROM (SELECT s.id FROM mdm_devices.input_snapshots s JOIN mdm_devices.checkpoints k USING(tenant_id) WHERE s.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND s.phase='sealed' AND s.relation_revision=k.relation_revision AND s.watermark>=k.identity_watermark ORDER BY s.watermark DESC LIMIT 1) current_input
UNION ALL
SELECT 'capability',v.ctid::text||'/'||v.xmin::text FROM mdm_commands.capabilities v JOIN registrations r ON r.id=v.registration WHERE v.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
UNION ALL
SELECT 'report-source',v.ctid::text||'/'||v.xmin::text FROM mdm_access.report_sources v JOIN registrations r ON r.id=v.registration WHERE v.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
UNION ALL
SELECT 'retirement-work',v.ctid::text||'/'||v.xmin::text FROM mdm_devices.retirement_work v JOIN commands o ON o.id=v.execution WHERE v.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
UNION ALL
SELECT 'retirement-channel',v.ctid::text||'/'||v.xmin::text FROM mdm_devices.retirement_channels v JOIN targets t ON t.device=v.device JOIN mdm_access.devices d ON(d.tenant_id,d.id,d.retirement)=(v.tenant_id,v.device,v.operation) WHERE v.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
UNION ALL
SELECT 'configuration-claim',v.ctid::text||'/'||v.xmin::text FROM mdm_planning.configuration_claims v JOIN targets t ON t.device=v.device WHERE v.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
$$;

REVOKE ALL ON FUNCTION mdm_planning.execution_source_versions(uuid,text[]) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION mdm_planning.execution_source_versions(uuid,text[]) TO mdm_command_runtime;
