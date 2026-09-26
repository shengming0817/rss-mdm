-- A consumer can serialize publication with asset ingress without update authority.
CREATE FUNCTION mdm.lock_asset_watermark(t uuid) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,mdm AS $$
DECLARE v bigint;
BEGIN
 IF t IS DISTINCT FROM nullif(current_setting('rss.tenant_id',true),'')::uuid THEN
  RAISE EXCEPTION 'asset tenant mismatch' USING ERRCODE='42501';
 END IF;
 INSERT INTO mdm.asset_clock(tenant_id,revision) VALUES(t,0) ON CONFLICT DO NOTHING;
 SELECT revision INTO STRICT v FROM mdm.asset_clock WHERE tenant_id=t FOR UPDATE;
 RETURN v;
END $$;
REVOKE ALL ON FUNCTION mdm.lock_asset_watermark(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mdm.lock_asset_watermark(uuid) TO mdm_flow_runtime;
