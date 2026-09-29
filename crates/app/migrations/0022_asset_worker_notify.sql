-- Add a commit-time scheduling hint at the existing asset history boundary.
-- CREATE OR REPLACE preserves the function owner and explicit EXECUTE grants.
BEGIN;
CREATE OR REPLACE FUNCTION mdm.record_asset_change(t uuid,k text,i jsonb,f text[]) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,mdm AS $$
DECLARE v bigint;
BEGIN
 IF t IS DISTINCT FROM nullif(current_setting('rss.tenant_id',true),'')::uuid THEN
  RAISE EXCEPTION 'asset tenant mismatch' USING ERRCODE='42501';
 END IF;
 INSERT INTO mdm.asset_clock(tenant_id,revision) VALUES(t,1)
 ON CONFLICT(tenant_id) DO UPDATE SET revision=mdm.asset_clock.revision+1
 RETURNING revision INTO v;
 INSERT INTO mdm.asset_changes(tenant_id,revision,kind,identity,fields) VALUES(t,v,k,i,f);
 PERFORM pg_catalog.pg_notify('mdm_work_' || replace(t::text,'-',''),'automation_input');
 RETURN v;
END $$;
COMMIT;
