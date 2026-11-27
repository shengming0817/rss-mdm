-- Only the product's reference to original Outbox headers is indexed here.
CREATE INDEX mdm_command_relay_catalog ON rss_transactional_messaging.outbox(domain,tenant_id,status);
CREATE FUNCTION public.mdm_command_relay_tenants(lane text, after_tenant uuid)
RETURNS TABLE(tenant_id uuid,epoch bigint,claimable boolean,quarantined boolean)
LANGUAGE plpgsql STABLE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp
AS $function$
DECLARE candidate uuid; previous_tenant text:=current_setting('rss.tenant_id',true);
BEGIN
 candidate := after_tenant;
 FOR position IN 1..32 LOOP
   -- One seek per tenant. Published history does not increase the page size or
   -- hide the last binding from another host's outstanding publication check.
   IF candidate IS NULL THEN
     SELECT o.tenant_id INTO candidate FROM rss_transactional_messaging.outbox o
       WHERE o.domain=lane ORDER BY o.tenant_id LIMIT 1;
   ELSE
     SELECT o.tenant_id INTO candidate FROM rss_transactional_messaging.outbox o
       WHERE o.domain=lane AND o.tenant_id>candidate ORDER BY o.tenant_id LIMIT 1;
   END IF;
   EXIT WHEN candidate IS NULL;
   -- Even the installation owner is subject to FORCE RLS on tenant_epoch.
   -- Restore the caller's binding at normal exit. A failed statement rolls back its local settings.
   PERFORM set_config('rss.tenant_id',candidate::text,true);
   RETURN QUERY SELECT e.tenant_id,e.epoch,
      EXISTS (SELECT FROM rss_transactional_messaging.outbox o
              WHERE o.tenant_id=candidate AND o.domain=lane
                AND (o.partition_head OR o.partition_key IS NULL) AND o.status IN ('pending','publishing')),
      EXISTS (SELECT FROM rss_transactional_messaging.outbox o
              WHERE o.tenant_id=candidate AND o.domain=lane AND o.status='dead_letter')
      FROM rss_transactional_messaging.tenant_epoch e
      WHERE e.tenant_id=candidate;
 END LOOP;
 PERFORM set_config('rss.tenant_id',coalesce(previous_tenant,''),true);
END
$function$;
REVOKE ALL ON FUNCTION public.mdm_command_relay_tenants(text,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.mdm_command_relay_tenants(text,uuid) TO rss_tmsg_relay;
