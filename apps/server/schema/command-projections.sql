-- Fixed RSS consumer bindings: {command_bindings}
CREATE FUNCTION public.mdm_dispatch_native_status(p_device uuid, p_id text, p_message text, p_fingerprint bytea)
RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT c.status FROM rss_device_command.commands c
 WHERE c.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
   AND c.device_id=p_device AND c.command_id=p_id AND c.outbox_message_id=p_message AND c.outbox_fingerprint=p_fingerprint
   AND c.outbox_domain=rss_transactional_messaging.consumer_scope_domain()
$$;
REVOKE ALL ON FUNCTION public.mdm_dispatch_native_status(uuid,text,text,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.mdm_dispatch_native_status(uuid,text,text,bytea) TO mdm_dispatch_device,mdm_dispatch_policy,mdm_dispatch_software,mdm_dispatch_installation,mdm_dispatch_native_credentials;
GRANT USAGE ON SCHEMA mdm_devices TO mdm_dispatch_device;
GRANT SELECT,UPDATE(gateway_accepted) ON mdm_devices.control_operations TO mdm_dispatch_device;
GRANT SELECT,UPDATE(gateway_accepted) ON mdm_devices.unmanage_runs TO mdm_dispatch_device;
GRANT SELECT(tenant_id,execution,operation) ON mdm_devices.retirement_work TO mdm_dispatch_device;
GRANT USAGE ON SCHEMA mdm_access TO mdm_dispatch_device;
GRANT SELECT(tenant_id,device,command_device) ON mdm_access.command_authorities TO mdm_dispatch_device;
GRANT USAGE ON SCHEMA mdm_planning TO mdm_dispatch_policy;
GRANT SELECT,UPDATE(gateway_accepted) ON mdm_planning.configuration_operations TO mdm_dispatch_policy;
GRANT USAGE ON SCHEMA mdm_access TO mdm_dispatch_policy;
GRANT SELECT(tenant_id,device,command_device) ON mdm_access.command_authorities TO mdm_dispatch_policy;
GRANT USAGE ON SCHEMA mdm_script TO mdm_dispatch_script;
GRANT SELECT,UPDATE(gateway_accepted) ON mdm_script.runs TO mdm_dispatch_script;
GRANT USAGE ON SCHEMA mdm_inventory TO mdm_dispatch_inventory;
GRANT SELECT,UPDATE(gateway_accepted) ON mdm_inventory.collection_tasks TO mdm_dispatch_inventory;
GRANT USAGE ON SCHEMA mdm_software_deployment TO mdm_dispatch_software;
GRANT SELECT,UPDATE(gateway_accepted) ON mdm_software_deployment.operations TO mdm_dispatch_software;
GRANT SELECT,UPDATE(gateway_accepted) ON mdm_software_deployment.action_runs TO mdm_dispatch_software;
GRANT USAGE ON SCHEMA mdm_access TO mdm_dispatch_software;
GRANT SELECT(tenant_id,device,command_device) ON mdm_access.command_authorities TO mdm_dispatch_software;
GRANT USAGE ON SCHEMA mdm_registration_tasks TO mdm_dispatch_installation;
GRANT SELECT,UPDATE(gateway_accepted) ON mdm_registration_tasks.operations TO mdm_dispatch_installation;
GRANT USAGE ON SCHEMA mdm_access TO mdm_dispatch_installation;
GRANT SELECT(tenant_id,device,command_device) ON mdm_access.command_authorities TO mdm_dispatch_installation;
GRANT USAGE ON SCHEMA mdm_registration_tasks TO mdm_dispatch_enrollment;
GRANT SELECT,UPDATE(gateway_accepted) ON mdm_registration_tasks.runs TO mdm_dispatch_enrollment;
GRANT USAGE ON SCHEMA mdm_recovery_tasks TO mdm_dispatch_mdm_credentials;
GRANT SELECT,UPDATE(gateway_accepted) ON mdm_recovery_tasks.runs TO mdm_dispatch_mdm_credentials;
GRANT USAGE ON SCHEMA mdm_recovery_tasks TO mdm_dispatch_native_credentials;
GRANT SELECT,UPDATE(gateway_accepted) ON mdm_recovery_tasks.operations TO mdm_dispatch_native_credentials;
GRANT USAGE ON SCHEMA mdm_access TO mdm_dispatch_native_credentials;
GRANT SELECT(tenant_id,device,command_device) ON mdm_access.command_authorities TO mdm_dispatch_native_credentials;

GRANT SELECT,INSERT ON rss_transactional_messaging.consumer_dead_letter TO {command_roles};

CREATE POLICY command_initial_state ON mdm_devices.control_operations AS RESTRICTIVE FOR INSERT TO mdm_command_runtime,mdm_policy_runtime WITH CHECK (NOT gateway_accepted);
CREATE POLICY command_initial_state ON mdm_devices.unmanage_runs AS RESTRICTIVE FOR INSERT TO mdm_command_runtime,mdm_policy_runtime WITH CHECK (NOT gateway_accepted);
CREATE POLICY command_initial_state ON mdm_planning.configuration_operations AS RESTRICTIVE FOR INSERT TO mdm_command_runtime,mdm_policy_runtime WITH CHECK (NOT gateway_accepted);
CREATE POLICY command_initial_state ON mdm_script.runs AS RESTRICTIVE FOR INSERT TO mdm_command_runtime,mdm_policy_runtime WITH CHECK (NOT gateway_accepted);
CREATE POLICY command_initial_state ON mdm_inventory.collection_tasks AS RESTRICTIVE FOR INSERT TO mdm_command_runtime,mdm_policy_runtime WITH CHECK (NOT gateway_accepted);
CREATE POLICY command_initial_state ON mdm_software_deployment.operations AS RESTRICTIVE FOR INSERT TO mdm_command_runtime,mdm_policy_runtime WITH CHECK (NOT gateway_accepted);
CREATE POLICY command_initial_state ON mdm_software_deployment.action_runs AS RESTRICTIVE FOR INSERT TO mdm_command_runtime,mdm_policy_runtime WITH CHECK (NOT gateway_accepted);
CREATE POLICY command_initial_state ON mdm_registration_tasks.operations AS RESTRICTIVE FOR INSERT TO mdm_command_runtime,mdm_policy_runtime WITH CHECK (NOT gateway_accepted);
CREATE POLICY command_initial_state ON mdm_registration_tasks.runs AS RESTRICTIVE FOR INSERT TO mdm_command_runtime,mdm_policy_runtime WITH CHECK (NOT gateway_accepted);
CREATE POLICY command_initial_state ON mdm_recovery_tasks.runs AS RESTRICTIVE FOR INSERT TO mdm_command_runtime,mdm_policy_runtime WITH CHECK (NOT gateway_accepted);
CREATE POLICY command_initial_state ON mdm_recovery_tasks.operations AS RESTRICTIVE FOR INSERT TO mdm_command_runtime,mdm_policy_runtime WITH CHECK (NOT gateway_accepted);


-- A Collection projection can wake only the already-admitted run in its current binding.
CREATE FUNCTION public.mdm_dispatch_collection_wake(p_run uuid,p_fingerprint bytea) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE tenant uuid := current_setting('rss.tenant_id')::uuid; target text := 'run:'||p_run::text;
        lane text := rss_transactional_messaging.consumer_scope_domain(); resources text[];
BEGIN
 SELECT array_agg(d.resource ORDER BY d.resource) INTO resources
 FROM mdm_inventory.collection_tasks r
 JOIN rss_reconcile.targets t ON t.tenant_id=r.tenant_id AND t.reconciler=lane AND t.entity=target
 JOIN rss_reconcile.target_resources d ON (d.tenant_id,d.reconciler,d.entity)=(t.tenant_id,t.reconciler,t.entity)
 WHERE r.tenant_id=tenant AND r.id=p_run AND r.gateway_accepted AND r.dispatch_fingerprint=p_fingerprint
   AND r.expected_epoch=current_setting('rss.execution_epoch')::bigint;
 IF resources IS NULL THEN RAISE EXCEPTION 'collection dispatch binding unavailable'; END IF;
 PERFORM rss_reconcile.wake(tenant,lane,target,resources);
 PERFORM pg_notify('mdm_work','collection_recovery');
END $$;
REVOKE ALL ON FUNCTION public.mdm_dispatch_collection_wake(uuid,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.mdm_dispatch_collection_wake(uuid,bytea) TO mdm_dispatch_inventory;
