-- Explicit current Reconcile privileges; component DML and sequence access stay denied.
GRANT USAGE ON SCHEMA rss_reconcile TO mdm_command_runtime,mdm_inventory_runtime,mdm_scope_runtime,mdm_policy_runtime,mdm_scheduler_runtime;
GRANT SELECT ON TABLE rss_reconcile.targets,rss_reconcile.resources,rss_reconcile.target_resources,rss_reconcile.scans TO mdm_command_runtime,mdm_inventory_runtime,mdm_scope_runtime,mdm_policy_runtime,mdm_scheduler_runtime;
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
 TO mdm_command_runtime,mdm_inventory_runtime,mdm_scope_runtime,mdm_policy_runtime,mdm_scheduler_runtime;
