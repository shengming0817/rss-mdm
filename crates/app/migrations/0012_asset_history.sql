BEGIN;
CREATE TABLE mdm_access.asset_authority_history (
 tenant_id uuid NOT NULL, kind text NOT NULL CHECK(kind IN ('device','registration','source','credential')),
 identity text NOT NULL CHECK(octet_length(identity) BETWEEN 1 AND 1024),
 device text, registration uuid, revision bigint NOT NULL,
 document jsonb CHECK(document IS NULL OR octet_length(document::text)<=16384),
 PRIMARY KEY(tenant_id,kind,identity,revision),
 FOREIGN KEY(tenant_id,revision) REFERENCES mdm.asset_changes(tenant_id,revision)
);
CREATE INDEX asset_authority_by_device ON mdm_access.asset_authority_history(tenant_id,device,kind,identity,revision);
CREATE INDEX asset_authority_by_registration ON mdm_access.asset_authority_history(tenant_id,registration,kind,identity,revision);
CREATE INDEX asset_authority_device_watermark ON mdm_access.asset_authority_history(tenant_id,device,revision DESC);
ALTER TABLE mdm_access.asset_authority_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_access.asset_authority_history FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_access.asset_authority_history
 USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)
 WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON mdm_access.asset_authority_history FROM PUBLIC;

CREATE FUNCTION mdm_access.capture_asset_authority() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,mdm_access AS $$
DECLARE r jsonb; d jsonb; previous jsonb; k text; i text; dev text; reg uuid; v bigint; t uuid;
BEGIN
 IF TG_OP='DELETE' THEN r=to_jsonb(OLD); ELSE r=to_jsonb(NEW); END IF;
 IF TG_OP='UPDATE' THEN previous=to_jsonb(OLD); END IF;
 t=(r->>'tenant_id')::uuid;
 CASE TG_TABLE_NAME
 WHEN 'devices' THEN
  k='device'; i=r->>'id'; dev=i; d=jsonb_build_object('id',i);
 WHEN 'registrations' THEN
  k='registration'; i=r->>'id'; reg=i::uuid; dev=r->>'device';
  d=jsonb_build_object('id',i,'device',dev,'channel',r->>'channel','generation',r->'generation','state',r->>'state');
 WHEN 'report_sources' THEN
  k='source'; reg=(r->>'registration')::uuid;
  i=jsonb_build_array(r->>'registration',r->>'source')::text;
  d=jsonb_build_object('registration',reg,'source',r->>'source','epoch',r->>'epoch','coverage',r->>'coverage','enabled',r->'enabled');
  -- Collection sequence/command allocation is not an asset change.
  IF previous IS NOT NULL AND d=jsonb_build_object('registration',(previous->>'registration')::uuid,'source',previous->>'source','epoch',previous->>'epoch','coverage',previous->>'coverage','enabled',previous->'enabled') THEN RETURN NULL; END IF;
 WHEN 'credentials' THEN
  k='credential'; i=r->>'id'; reg=(r->>'registration')::uuid;
  -- Credential locators and secrets never enter asset history.
  d=jsonb_build_object('id',i,'registration',reg,'channel',r->>'channel','state',r->>'state');
 ELSE RAISE EXCEPTION 'unexpected asset authority';
 END CASE;
 IF TG_OP='UPDATE' AND NEW IS NOT DISTINCT FROM OLD THEN RETURN NULL; END IF;
 IF dev IS NULL THEN SELECT device INTO dev FROM mdm_access.registrations WHERE tenant_id=t AND id=reg; END IF;
 v=mdm.record_asset_change(t,k,jsonb_build_object('device',dev,'registration',reg,'identity',i),ARRAY[]::text[]);
 IF TG_OP='DELETE' THEN d=NULL; END IF;
 INSERT INTO mdm_access.asset_authority_history VALUES(t,k,i,dev,reg,v,d);
 RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION mdm_access.capture_asset_authority() FROM PUBLIC;
CREATE TRIGGER asset_authority AFTER INSERT OR UPDATE OR DELETE ON mdm_access.devices
 FOR EACH ROW EXECUTE FUNCTION mdm_access.capture_asset_authority();
CREATE TRIGGER asset_authority AFTER INSERT OR UPDATE OR DELETE ON mdm_access.registrations
 FOR EACH ROW EXECUTE FUNCTION mdm_access.capture_asset_authority();
CREATE TRIGGER asset_authority AFTER INSERT OR UPDATE OR DELETE ON mdm_access.report_sources
 FOR EACH ROW EXECUTE FUNCTION mdm_access.capture_asset_authority();
CREATE TRIGGER asset_authority AFTER INSERT OR UPDATE OR DELETE ON mdm_access.credentials
 FOR EACH ROW EXECUTE FUNCTION mdm_access.capture_asset_authority();
GRANT SELECT ON mdm.asset_clock,mdm.asset_changes,mdm.inventory_history,mdm.manual_history,
 mdm_access.asset_authority_history TO mdm_management_runtime;
GRANT UPDATE(forwarded) ON mdm.asset_changes TO mdm_management_runtime;
GRANT USAGE ON SCHEMA rss_reconcile TO mdm_management_runtime;
GRANT SELECT ON ALL TABLES IN SCHEMA rss_reconcile TO mdm_management_runtime;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA rss_reconcile TO mdm_management_runtime;
COMMIT;
