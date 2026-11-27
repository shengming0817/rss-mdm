CREATE FUNCTION public.mdm_dispatch_native_status(p_id text, p_fingerprint bytea)
RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT c.status FROM rss_device_command.commands c
 WHERE c.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
   AND c.command_id=p_id AND c.outbox_fingerprint=p_fingerprint
   AND c.outbox_domain=rss_transactional_messaging.consumer_scope_domain()
$$;
REVOKE ALL ON FUNCTION public.mdm_dispatch_native_status(text,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.mdm_dispatch_native_status(text,bytea) TO mdm_dispatch_device,mdm_dispatch_policy,mdm_dispatch_software,mdm_dispatch_installation,mdm_dispatch_native_credentials;
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

GRANT SELECT,INSERT ON rss_transactional_messaging.consumer_dead_letter TO mdm_dispatch_device,mdm_dispatch_policy,mdm_dispatch_script,mdm_dispatch_inventory,mdm_dispatch_software,mdm_dispatch_installation,mdm_dispatch_enrollment,mdm_dispatch_device_access,mdm_dispatch_mdm_credentials,mdm_dispatch_da_credentials,mdm_dispatch_native_credentials;
