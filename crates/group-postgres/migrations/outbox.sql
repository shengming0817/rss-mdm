-- Public Outbox writer admission; existing product schema units stay immutable.
BEGIN;
GRANT USAGE ON SCHEMA rss_transactional_messaging TO mdm_group_runtime;
GRANT SELECT ON rss_transactional_messaging.policy,rss_transactional_messaging.outbox TO mdm_group_runtime;
REVOKE INSERT ON rss_transactional_messaging.outbox FROM mdm_group_runtime;
REVOKE ALL ON SEQUENCE rss_transactional_messaging.outbox_seq_seq FROM mdm_group_runtime;
GRANT EXECUTE ON FUNCTION rss_transactional_messaging.check_execution(),
 rss_transactional_messaging.prepare_outbox_partitions(jsonb),
 rss_transactional_messaging.append_outbox(bytea,jsonb) TO mdm_group_runtime;
COMMIT;
