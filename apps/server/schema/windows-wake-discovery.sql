-- Check command and device state under the candidate's tenant policy and restore the caller's scope.
CREATE FUNCTION mdm_windows.wake_target_credential(t uuid, device_id uuid, command text, channel_configuration bytea, rejected_revision bigint) RETURNS bytea
LANGUAGE plpgsql STABLE SET search_path=pg_catalog AS $$
DECLARE prior text := current_setting('rss.tenant_id',true); identity bytea;
BEGIN
 PERFORM set_config('rss.tenant_id',t::text,true);
 SELECT v.sid_digest INTO identity FROM mdm_wns.versions v JOIN mdm_wns.heads h
 ON (h.tenant_id,h.desired_revision)=(v.tenant_id,v.revision)
 WHERE v.tenant_id=t AND v.selected AND NOT v.revoked AND v.qualified_at IS NOT NULL AND v.configuration=channel_configuration
 AND v.revision IS DISTINCT FROM rejected_revision AND mdm_wns.provider_available(v.sid_digest)
 AND EXISTS(SELECT FROM mdm_access.devices d WHERE (d.tenant_id,d.id)=(t,device_id) AND d.state='active')
 AND (command IS NULL OR EXISTS(SELECT FROM rss_device_command.commands c
        WHERE c.tenant_id=t AND c.command_id=command AND c.status IN ('published','received')));
 PERFORM set_config('rss.tenant_id',coalesce(prior,''),true);
 RETURN identity;
END $$;
REVOKE ALL ON FUNCTION mdm_windows.wake_target_credential(uuid,uuid,text,bytea,bigint) FROM PUBLIC;

CREATE FUNCTION mdm_windows.push_work_page(after_tenant uuid,after_device uuid) RETURNS TABLE(tenant_id uuid,device uuid,credential bytea)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT DISTINCT w.tenant_id,w.device,provider.credential FROM (
    SELECT * FROM mdm_devices.windows_wake_inputs() UNION ALL
    SELECT * FROM mdm_planning.configuration_windows_wake_inputs() UNION ALL
    SELECT * FROM mdm_software_deployment.windows_wake_inputs() UNION ALL
    SELECT * FROM mdm_registration_tasks.windows_wake_inputs() UNION ALL
    SELECT t.tenant_id,t.device,NULL::text FROM mdm_inventory.windows_wake_inputs() t
 ) w JOIN mdm_windows.push_channels p USING(tenant_id,device)
 CROSS JOIN LATERAL (SELECT mdm_windows.wake_target_credential(w.tenant_id,w.device,w.command_id,p.configuration,CASE WHEN p.outcome='rejected' THEN p.material_revision END) AS credential OFFSET 0) provider
 WHERE (after_tenant IS NULL OR (w.tenant_id,w.device)>(after_tenant,after_device))
   AND p.attempt_until>statement_timestamp()
   AND p.outcome IS DISTINCT FROM 'unregistered' AND provider.credential IS NOT NULL
 ORDER BY w.tenant_id,w.device LIMIT 32
$$;
REVOKE ALL ON FUNCTION mdm_windows.push_work_page(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mdm_windows.push_work_page(uuid,uuid) TO mdm_access;
