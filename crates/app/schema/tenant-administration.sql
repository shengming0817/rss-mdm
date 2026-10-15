-- Product registry permissions do not confer business table writes or reusable seeding.
BEGIN;
GRANT SELECT ON public.mdm_installation,public.mdm_tenants,public.mdm_tenant_operations,public.mdm_migrations TO mdm_tenant_registry,mdm_identity_provisioning;
GRANT UPDATE(name,notes,revision,deleted) ON public.mdm_tenants TO mdm_tenant_registry;
GRANT INSERT ON public.mdm_tenant_operations TO mdm_tenant_registry,mdm_identity_provisioning;
CREATE POLICY registry ON public.mdm_tenants TO mdm_tenant_registry,mdm_identity_provisioning USING(true);
GRANT USAGE ON SCHEMA rss_transactional_messaging,mdm_access TO mdm_tenant_registry,mdm_identity_provisioning;
GRANT SELECT ON rss_transactional_messaging.tenant_epoch TO mdm_tenant_registry,mdm_identity_provisioning;
GRANT SELECT ON mdm_access.authorization_rules,mdm_access.user_groups,mdm_access.authorization_initializations TO mdm_tenant_registry,mdm_identity_provisioning;
GRANT INSERT ON mdm_access.authorization_rules TO mdm_identity_provisioning;
GRANT EXECUTE ON FUNCTION public.claim_tenant_use(uuid,bigint,uuid,bytea,bytea,text) TO mdm_identity_provisioning;
CREATE FUNCTION public.create_new_tenant(t uuid,e bigint,n text,d text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $create$
BEGIN
 PERFORM pg_advisory_xact_lock(2346);
 IF (SELECT count(*) FROM public.mdm_tenants WHERE NOT deleted AND tenant_id<>(SELECT management_tenant_id FROM public.mdm_installation))>=1024 THEN RAISE EXCEPTION 'tenant capacity'; END IF;
 PERFORM set_config('rss.tenant_id',t::text,true);
 INSERT INTO public.mdm_tenants(tenant_id,initial_epoch,name,notes) VALUES(t,e,n,d);
 INSERT INTO rss_transactional_messaging.tenant_epoch(tenant_id,epoch) VALUES(t,e);
 PERFORM mdm.seed_tenant_catalog(t);
 PERFORM mdm_access.seed_tenant_settings(t);
END;
$create$;
ALTER FUNCTION public.create_new_tenant(uuid,bigint,text,text) OWNER TO mdm_owner;
REVOKE ALL ON FUNCTION public.create_new_tenant(uuid,bigint,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.create_new_tenant(uuid,bigint,text,text) TO mdm_tenant_registry;
COMMIT;
