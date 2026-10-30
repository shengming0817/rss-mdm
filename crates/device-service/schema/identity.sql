-- Device owns current identity and immutable object evidence. No lease/retry state lives here.
BEGIN;
CREATE TABLE mdm_devices.endpoint_identities (
 tenant_id uuid NOT NULL,device text NOT NULL COLLATE "C",channel text NOT NULL CHECK(channel IN('mdm','agent')),
 input jsonb NOT NULL,hardware jsonb NOT NULL,
 PRIMARY KEY(tenant_id,device,channel)
);
CREATE TABLE mdm_devices.identity_keys (
 tenant_id uuid NOT NULL,kind text NOT NULL CHECK(kind IN('serial','uuid')),value text NOT NULL,
 device text NOT NULL COLLATE "C",channel text NOT NULL CHECK(channel IN('mdm','agent')),
 PRIMARY KEY(tenant_id,kind,value,device,channel),
 FOREIGN KEY(tenant_id,device,channel) REFERENCES mdm_devices.endpoint_identities(tenant_id,device,channel) ON DELETE CASCADE
);
CREATE INDEX identity_keys_device ON mdm_devices.identity_keys(tenant_id,device);
CREATE TABLE mdm_devices.object_cuts (
 tenant_id uuid NOT NULL,id uuid NOT NULL,watermark bigint NOT NULL,through bigint NOT NULL CHECK(through>=0),
 PRIMARY KEY(tenant_id,id)
);
CREATE INDEX object_cuts_order ON mdm_devices.object_cuts(tenant_id,watermark,through);
CREATE TABLE mdm_devices.object_versions (
 tenant_id uuid NOT NULL,object text COLLATE "C" NOT NULL,revision bigint NOT NULL CHECK(revision>0),
 input jsonb,devices text[] NOT NULL,
 PRIMARY KEY(tenant_id,object,revision)
);
CREATE INDEX object_versions_devices ON mdm_devices.object_versions USING gin(devices);
CREATE TABLE mdm_devices.object_heads (
 tenant_id uuid NOT NULL,object text COLLATE "C" NOT NULL,revision bigint NOT NULL,
 PRIMARY KEY(tenant_id,object),
 FOREIGN KEY(tenant_id,object,revision) REFERENCES mdm_devices.object_versions(tenant_id,object,revision)
);
CREATE TABLE mdm_devices.object_changes (
 tenant_id uuid NOT NULL,revision bigint NOT NULL,object text COLLATE "C" NOT NULL,
 old_devices text[] NOT NULL,new_devices text[] NOT NULL,
 PRIMARY KEY(tenant_id,revision),
 FOREIGN KEY(tenant_id,object,revision) REFERENCES mdm_devices.object_versions(tenant_id,object,revision)
);
-- Desired/completed input versions and fan-out cursor are business progress only.
-- RSS owns the task target, claims, attempts and retry schedule.
CREATE TABLE mdm_devices.association_work (
 tenant_id uuid NOT NULL,id uuid NOT NULL,kind text NOT NULL CHECK(kind IN('device','serial','uuid')),
 value text NOT NULL CHECK(octet_length(value) BETWEEN 1 AND 4096),
 requested bigint NOT NULL DEFAULT 1 CHECK(requested>0),completed bigint NOT NULL DEFAULT 0 CHECK(completed>=0),
 watermark bigint NOT NULL DEFAULT 0 CHECK(watermark>=completed),cursor text COLLATE "C",
 PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,kind,value)
);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['endpoint_identities','identity_keys','object_cuts','object_versions','object_heads','object_changes','association_work'] LOOP
  EXECUTE format('ALTER TABLE mdm_devices.%I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE mdm_devices.%I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('CREATE POLICY tenant ON mdm_devices.%I USING(tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid) WITH CHECK(tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid)',t);
  EXECUTE format('REVOKE ALL ON mdm_devices.%I FROM PUBLIC',t);
  EXECUTE format('GRANT SELECT,INSERT ON mdm_devices.%I TO mdm_access',t);
  IF t IN('object_cuts','object_versions','object_heads','object_changes') THEN
   EXECUTE format('GRANT SELECT ON mdm_devices.%I TO mdm_inventory_runtime,mdm_scope_runtime,mdm_policy_runtime,mdm_telemetry_runtime,mdm_command_runtime',t);
  END IF;
 END LOOP;
END $$;
GRANT SELECT ON mdm_devices.checkpoints TO mdm_inventory_runtime,mdm_scope_runtime,mdm_policy_runtime,mdm_telemetry_runtime,mdm_command_runtime;
GRANT UPDATE(consumed,watermark,cursor,rebuild_after,rebuilding,object_revision,current_cut) ON mdm_devices.checkpoints TO mdm_access;
GRANT UPDATE(input,hardware) ON mdm_devices.endpoint_identities TO mdm_access;
GRANT DELETE ON mdm_devices.endpoint_identities,mdm_devices.identity_keys TO mdm_access;
GRANT UPDATE(revision) ON mdm_devices.object_heads TO mdm_access;
GRANT UPDATE(requested,completed,watermark,cursor) ON mdm_devices.association_work TO mdm_access;

CREATE FUNCTION mdm_devices.guard_object_evidence() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN RAISE EXCEPTION 'object evidence is immutable'; END $$;
REVOKE ALL ON FUNCTION mdm_devices.guard_object_evidence() FROM PUBLIC;
CREATE TRIGGER immutable_object_evidence BEFORE UPDATE OR DELETE ON mdm_devices.object_versions FOR EACH ROW EXECUTE FUNCTION mdm_devices.guard_object_evidence();
CREATE TRIGGER immutable_object_cut BEFORE UPDATE OR DELETE ON mdm_devices.object_cuts FOR EACH ROW EXECUTE FUNCTION mdm_devices.guard_object_evidence();
GRANT USAGE ON SCHEMA rss_reconcile TO mdm_access;
GRANT SELECT ON rss_reconcile.targets,rss_reconcile.resources,rss_reconcile.target_resources,rss_reconcile.scans TO mdm_access;
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
 TO mdm_access;
GRANT SELECT ON mdm.asset_changes,mdm_access.asset_authority_history TO mdm_access;
COMMIT;
