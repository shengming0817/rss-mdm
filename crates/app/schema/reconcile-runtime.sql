
-- Explicit integration privileges owned by this capability.
GRANT USAGE ON SCHEMA rss_reconcile TO mdm_command_runtime;

GRANT USAGE ON SCHEMA rss_reconcile TO mdm_inventory_runtime,mdm_scope_runtime,mdm_policy_runtime,mdm_scheduler_runtime;

REVOKE ALL ON FUNCTION rss_reconcile.assert_tenant(t uuid) FROM PUBLIC;

GRANT ALL ON FUNCTION rss_reconcile.assert_tenant(t uuid) TO mdm_command_runtime;

GRANT ALL ON FUNCTION rss_reconcile.assert_tenant(t uuid) TO mdm_inventory_runtime,mdm_scope_runtime,mdm_policy_runtime,mdm_scheduler_runtime;

GRANT SELECT ON TABLE rss_reconcile.targets TO mdm_command_runtime;

GRANT SELECT ON TABLE rss_reconcile.targets TO mdm_inventory_runtime,mdm_scope_runtime,mdm_policy_runtime,mdm_scheduler_runtime;

REVOKE ALL ON FUNCTION rss_reconcile.claim_due(t uuid, r text, n integer, ttl bigint) FROM PUBLIC;

GRANT ALL ON FUNCTION rss_reconcile.claim_due(t uuid, r text, n integer, ttl bigint) TO mdm_command_runtime;

GRANT ALL ON FUNCTION rss_reconcile.claim_due(t uuid, r text, n integer, ttl bigint) TO mdm_inventory_runtime,mdm_scope_runtime,mdm_policy_runtime,mdm_scheduler_runtime;

REVOKE ALL ON FUNCTION rss_reconcile.finish(t uuid, r text, e text, k uuid, g bigint, w bigint, outcome text, delay bigint, f bigint) FROM PUBLIC;

GRANT ALL ON FUNCTION rss_reconcile.finish(t uuid, r text, e text, k uuid, g bigint, w bigint, outcome text, delay bigint, f bigint) TO mdm_command_runtime;

GRANT ALL ON FUNCTION rss_reconcile.finish(t uuid, r text, e text, k uuid, g bigint, w bigint, outcome text, delay bigint, f bigint) TO mdm_inventory_runtime,mdm_scope_runtime,mdm_policy_runtime,mdm_scheduler_runtime;

REVOKE ALL ON FUNCTION rss_reconcile.lock_claim(t uuid, r text, e text, k uuid, g bigint) FROM PUBLIC;

GRANT ALL ON FUNCTION rss_reconcile.lock_claim(t uuid, r text, e text, k uuid, g bigint) TO mdm_command_runtime;

GRANT ALL ON FUNCTION rss_reconcile.lock_claim(t uuid, r text, e text, k uuid, g bigint) TO mdm_inventory_runtime,mdm_scope_runtime,mdm_policy_runtime,mdm_scheduler_runtime;

REVOKE ALL ON FUNCTION rss_reconcile.mark_applied(t uuid, r text, e text, k uuid, g bigint) FROM PUBLIC;

GRANT ALL ON FUNCTION rss_reconcile.mark_applied(t uuid, r text, e text, k uuid, g bigint) TO mdm_command_runtime;

GRANT ALL ON FUNCTION rss_reconcile.mark_applied(t uuid, r text, e text, k uuid, g bigint) TO mdm_inventory_runtime,mdm_scope_runtime,mdm_policy_runtime,mdm_scheduler_runtime;

REVOKE ALL ON FUNCTION rss_reconcile.release(t uuid, r text, e text, k uuid, g bigint) FROM PUBLIC;

GRANT ALL ON FUNCTION rss_reconcile.release(t uuid, r text, e text, k uuid, g bigint) TO mdm_command_runtime;

GRANT ALL ON FUNCTION rss_reconcile.release(t uuid, r text, e text, k uuid, g bigint) TO mdm_inventory_runtime,mdm_scope_runtime,mdm_policy_runtime,mdm_scheduler_runtime;

REVOKE ALL ON FUNCTION rss_reconcile.renew(t uuid, r text, e text, k uuid, g bigint, ttl bigint) FROM PUBLIC;

GRANT ALL ON FUNCTION rss_reconcile.renew(t uuid, r text, e text, k uuid, g bigint, ttl bigint) TO mdm_command_runtime;

GRANT ALL ON FUNCTION rss_reconcile.renew(t uuid, r text, e text, k uuid, g bigint, ttl bigint) TO mdm_inventory_runtime,mdm_scope_runtime,mdm_policy_runtime,mdm_scheduler_runtime;

REVOKE ALL ON FUNCTION rss_reconcile.wake(t uuid, r text, e text) FROM PUBLIC;

GRANT ALL ON FUNCTION rss_reconcile.wake(t uuid, r text, e text) TO mdm_command_runtime;

GRANT ALL ON FUNCTION rss_reconcile.wake(t uuid, r text, e text) TO mdm_inventory_runtime,mdm_scope_runtime,mdm_policy_runtime,mdm_scheduler_runtime;
