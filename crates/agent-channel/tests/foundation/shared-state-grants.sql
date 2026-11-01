-- Same public components, separately admitted producer roles. No private cross-profile grant.
GRANT USAGE ON SCHEMA rss_transactional_messaging TO mdm_access,mdm_scope_runtime;
GRANT SELECT ON rss_transactional_messaging.policy,rss_transactional_messaging.outbox TO mdm_access,mdm_scope_runtime;
GRANT EXECUTE ON FUNCTION rss_transactional_messaging.check_execution(),rss_transactional_messaging.prepare_outbox_partitions(jsonb),rss_transactional_messaging.append_outbox(bytea,jsonb) TO mdm_access,mdm_scope_runtime;
GRANT USAGE ON SCHEMA rss_audit TO mdm_access,mdm_scope_runtime;
GRANT SELECT ON rss_audit.records TO mdm_access,mdm_scope_runtime;
GRANT EXECUTE ON FUNCTION rss_audit.append_batch(uuid,text[],text[],bigint[],bytea[],bigint[]) TO mdm_access,mdm_scope_runtime;
