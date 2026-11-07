BEGIN;
GRANT SELECT(instance_id,management_tenant_id) ON public.mdm_installation TO da_owner,da_access;
GRANT USAGE ON SCHEMA mdm_access,mdm_agent TO da_access;
GRANT SELECT ON mdm_access.devices,mdm_access.registrations,mdm_access.credentials,mdm_access.certificate_issuances,mdm_access.report_sources,mdm_agent.bindings TO da_access;
GRANT USAGE ON SCHEMA mdm TO da_access;
GRANT EXECUTE ON FUNCTION mdm.record_asset_change(uuid,text,jsonb,text[]) TO da_access;
GRANT USAGE ON SCHEMA rss_audit TO da_access;
GRANT SELECT ON rss_audit.records TO da_access;
GRANT EXECUTE ON FUNCTION rss_audit.append_batch(uuid,text[],text[],bigint[],bytea[],bigint[]) TO da_access;
GRANT USAGE ON SCHEMA rss_transactional_messaging TO da_access;
GRANT SELECT ON rss_transactional_messaging.policy,rss_transactional_messaging.outbox TO da_access;
GRANT EXECUTE ON FUNCTION rss_transactional_messaging.check_execution(),rss_transactional_messaging.prepare_outbox_partitions(jsonb),rss_transactional_messaging.append_outbox(bytea,jsonb),rss_transactional_messaging.consumer_scope_domain(),rss_transactional_messaging.consumer_inbox_allowed(uuid,text,text),rss_transactional_messaging.projection_scope_matches(text,text) TO da_access;
-- Agent fact verification on the shared Identity transaction never authenticates a DA registration as Agent.
GRANT USAGE ON SCHEMA mdm_access,mdm_agent TO mdm_identity_runtime;
GRANT SELECT ON mdm_access.devices,mdm_access.registrations,mdm_access.credentials,mdm_access.certificate_issuances,mdm_access.report_sources,mdm_agent.bindings TO mdm_identity_runtime;
GRANT USAGE ON SCHEMA mdm TO da_owner;
GRANT REFERENCES(tenant_id,revision) ON mdm.asset_changes TO da_owner;
GRANT EXECUTE ON FUNCTION mdm.record_asset_change(uuid,text,jsonb,text[]) TO da_owner;
-- Hosted DA authorization borrows the existing host authority, with no mirrored grants.
GRANT SELECT ON mdm_access.authorization_rules,mdm_access.user_groups,mdm_access.api_keys,mdm_access.api_network_policy TO da_access;
GRANT EXECUTE ON FUNCTION mdm_access.operation_authority_valid(jsonb,text,text,bigint),mdm_access.operation_authority_valid_until(jsonb,text,text,bigint) TO da_access;

-- Hosted diagnostics read the shared rebuildable index through the DA authority transaction.
GRANT USAGE ON SCHEMA mdm_timeline TO da_access;
GRANT SELECT ON mdm_timeline.facts TO da_access;
-- Hosted credential tasks retain a policy-version coordinate, not policy contents.
GRANT USAGE ON SCHEMA mdm_policy TO da_access;
GRANT SELECT(tenant_id,id,policy) ON mdm_policy.versions TO da_access;
COMMIT;
