-- Product-owned asset history. No timer, lease, or execution authority lives here.
BEGIN;
CREATE TABLE mdm.asset_clock (
 tenant_id uuid PRIMARY KEY, revision bigint NOT NULL CHECK(revision>=0)
);
CREATE TABLE mdm.asset_changes (
 tenant_id uuid NOT NULL, revision bigint NOT NULL CHECK(revision>0),
 kind text NOT NULL CHECK(kind IN ('inventory','manual','device','registration','source','credential')),
 identity jsonb NOT NULL CHECK(octet_length(identity::text)<=16384),
 fields text[] NOT NULL, forwarded boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,revision)
);
CREATE INDEX asset_changes_pending ON mdm.asset_changes(tenant_id,revision) WHERE NOT forwarded;
CREATE TABLE mdm.inventory_history (
 tenant_id uuid NOT NULL, scope_digest bytea NOT NULL CHECK(octet_length(scope_digest)=32),
 field text NOT NULL, revision bigint NOT NULL,
 document jsonb, PRIMARY KEY(tenant_id,scope_digest,field,revision),
 FOREIGN KEY(tenant_id,revision) REFERENCES mdm.asset_changes(tenant_id,revision),
 CHECK(document IS NULL OR octet_length(document::text)<=65536)
);
CREATE TABLE mdm.manual_history (
 tenant_id uuid NOT NULL, device text NOT NULL, field text NOT NULL, revision bigint NOT NULL,
 document jsonb, PRIMARY KEY(tenant_id,device,field,revision),
 FOREIGN KEY(tenant_id,revision) REFERENCES mdm.asset_changes(tenant_id,revision),
 CHECK(document IS NULL OR octet_length(document::text)<=8192)
);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['asset_clock','asset_changes','inventory_history','manual_history'] LOOP
  EXECUTE format('ALTER TABLE mdm.%I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE mdm.%I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('CREATE POLICY tenant ON mdm.%I USING(tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid) WITH CHECK(tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid)',t);
  EXECUTE format('REVOKE ALL ON mdm.%I FROM PUBLIC',t);
 END LOOP;
END $$;

-- The row lock is held until the fact transaction settles. Reading the committed
-- clock therefore cannot skip an earlier uncommitted revision, unlike a sequence.
CREATE FUNCTION mdm.record_asset_change(t uuid,k text,i jsonb,f text[]) RETURNS bigint
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
 RETURN v;
END $$;
REVOKE ALL ON FUNCTION mdm.record_asset_change(uuid,text,jsonb,text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mdm.record_asset_change(uuid,text,jsonb,text[]) TO mdm_runtime;

CREATE FUNCTION mdm.capture_inventory_history() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,mdm AS $$
DECLARE r jsonb; d jsonb; v bigint; t uuid; s bytea;
BEGIN
 IF TG_OP='UPDATE' AND NEW IS NOT DISTINCT FROM OLD THEN RETURN NEW; END IF;
 IF TG_OP='DELETE' THEN r=to_jsonb(OLD); d=NULL; ELSE r=to_jsonb(NEW); d=r; END IF;
 t=(r->>'tenant_id')::uuid;
 s=sha256(convert_to(jsonb_build_array(r->>'journal',r->>'generation',r->>'scope',r->>'coverage')::text,'UTF8'));
 v=mdm.record_asset_change(t,'inventory',jsonb_build_object('registration',r->>'registration','scope',r->>'scope'),ARRAY[r->>'field']);
 INSERT INTO mdm.inventory_history VALUES(t,s,r->>'field',v,d);
 RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION mdm.capture_inventory_history() FROM PUBLIC;
CREATE TRIGGER inventory_history AFTER INSERT OR UPDATE OR DELETE ON mdm.inventory
 FOR EACH ROW EXECUTE FUNCTION mdm.capture_inventory_history();

CREATE FUNCTION mdm.capture_manual_history() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,mdm AS $$
DECLARE r jsonb; d jsonb; v bigint; t uuid;
BEGIN
 IF TG_OP='UPDATE' AND NEW IS NOT DISTINCT FROM OLD THEN RETURN NEW; END IF;
 IF TG_OP='DELETE' THEN r=to_jsonb(OLD); d=NULL; ELSE r=to_jsonb(NEW); d=r; END IF;
 t=(r->>'tenant_id')::uuid;
 v=mdm.record_asset_change(t,'manual',jsonb_build_object('device',r->>'device'),ARRAY[r->>'field']);
 INSERT INTO mdm.manual_history VALUES(t,r->>'device',r->>'field',v,d);
 RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION mdm.capture_manual_history() FROM PUBLIC;
CREATE TRIGGER manual_history AFTER INSERT OR UPDATE OR DELETE ON mdm.manual_assignments
 FOR EACH ROW EXECUTE FUNCTION mdm.capture_manual_history();
COMMIT;
