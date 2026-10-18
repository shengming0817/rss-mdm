-- Fresh-install product associations. Registration remains an independent owner.
BEGIN;
CREATE SCHEMA mdm_devices;
REVOKE ALL ON SCHEMA mdm_devices FROM PUBLIC;
CREATE TABLE mdm_devices.associations (
 tenant_id uuid NOT NULL REFERENCES public.mdm_tenants(tenant_id),
 id uuid NOT NULL, version bigint NOT NULL CHECK(version>0),
 state text NOT NULL CHECK(state IN ('confirmed','needs_verification','revoked')),
 evidence text NOT NULL CHECK(length(evidence) BETWEEN 1 AND 2048),
 hardware jsonb NOT NULL,
 confirmed_by text NOT NULL, confirmed_at bigint NOT NULL,
 revoked_by text, revoked_at bigint, reason text,
 PRIMARY KEY(tenant_id,id),
 CHECK((state='revoked')=(revoked_at IS NOT NULL)),
 CHECK((state='revoked')=(revoked_by IS NOT NULL)),
 CHECK((state='revoked')=(reason IS NOT NULL))
);
CREATE TABLE mdm_devices.members (
 tenant_id uuid NOT NULL, association_id uuid NOT NULL,
 device text NOT NULL, channel text NOT NULL CHECK(channel IN ('mdm','agent')),
 registration_id uuid NOT NULL, generation bigint NOT NULL CHECK(generation>0),
 released boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,association_id,channel),
 UNIQUE(tenant_id,association_id,device),
 FOREIGN KEY(tenant_id,association_id) REFERENCES mdm_devices.associations(tenant_id,id),
 FOREIGN KEY(tenant_id,device) REFERENCES mdm_access.devices(tenant_id,id),
 FOREIGN KEY(tenant_id,registration_id,generation) REFERENCES mdm_access.registrations(tenant_id,id,generation),
 FOREIGN KEY(tenant_id,registration_id,channel) REFERENCES mdm_access.registrations(tenant_id,id,channel)
);
CREATE UNIQUE INDEX one_unreleased_association ON mdm_devices.members(tenant_id,device) WHERE NOT released;
CREATE TABLE mdm_devices.operations (
 tenant_id uuid NOT NULL, operation_id uuid NOT NULL, actor text NOT NULL, instance text NOT NULL,
 digest bytea NOT NULL CHECK(octet_length(digest)=32), result jsonb NOT NULL,
 PRIMARY KEY(tenant_id,operation_id),
 FOREIGN KEY(tenant_id) REFERENCES public.mdm_tenants(tenant_id)
);
ALTER TABLE mdm_devices.associations ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_devices.associations FORCE ROW LEVEL SECURITY;
ALTER TABLE mdm_devices.members ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_devices.members FORCE ROW LEVEL SECURITY;
ALTER TABLE mdm_devices.operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_devices.operations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_devices.associations USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY tenant ON mdm_devices.members USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY tenant ON mdm_devices.operations USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON mdm_devices.associations,mdm_devices.members,mdm_devices.operations FROM PUBLIC;
GRANT USAGE ON SCHEMA mdm_devices TO mdm_access;
GRANT SELECT,INSERT ON mdm_devices.associations,mdm_devices.members,mdm_devices.operations TO mdm_access;
GRANT UPDATE(version,state,evidence,hardware,confirmed_by,confirmed_at,revoked_by,revoked_at,reason) ON mdm_devices.associations TO mdm_access;
GRANT UPDATE(registration_id,generation,released) ON mdm_devices.members TO mdm_access;
CREATE TABLE mdm_devices.checkpoints (
 tenant_id uuid PRIMARY KEY REFERENCES public.mdm_tenants(tenant_id), watermark bigint NOT NULL CHECK(watermark>=0), relation_revision bigint NOT NULL DEFAULT 0 CHECK(relation_revision>=0), identity_watermark bigint NOT NULL DEFAULT 0 CHECK(identity_watermark>=0)
);
ALTER TABLE mdm_devices.checkpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_devices.checkpoints FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_devices.checkpoints USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON mdm_devices.checkpoints FROM PUBLIC;
GRANT SELECT,INSERT ON mdm_devices.checkpoints TO mdm_access;
GRANT UPDATE(watermark) ON mdm_devices.checkpoints TO mdm_access;
GRANT USAGE ON SCHEMA mdm TO mdm_access;
GRANT SELECT ON mdm.asset_clock,mdm.inventory_history,mdm.manual_history,mdm.field_versions,mdm.collection_definitions TO mdm_access;
CREATE FUNCTION mdm_devices.advance_relation_revision() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 INSERT INTO mdm_devices.checkpoints(tenant_id,watermark,relation_revision) VALUES(NEW.tenant_id,0,1)
 ON CONFLICT(tenant_id) DO UPDATE SET relation_revision=mdm_devices.checkpoints.relation_revision+1;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION mdm_devices.advance_relation_revision() FROM PUBLIC;
CREATE TRIGGER association_revision AFTER INSERT OR UPDATE ON mdm_devices.associations FOR EACH ROW EXECUTE FUNCTION mdm_devices.advance_relation_revision();
CREATE TRIGGER association_member_revision AFTER INSERT OR UPDATE ON mdm_devices.members FOR EACH ROW EXECUTE FUNCTION mdm_devices.advance_relation_revision();
-- Identity proof changes only for owner inputs; unrelated inventory must not block delivery.
CREATE FUNCTION mdm_devices.capture_identity_watermark() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF NEW.kind IN('device','registration','source','credential') OR NEW.fields && ARRAY['device.serial_number','device.hardware_uuid','device.manufacturer']::text[] THEN
  INSERT INTO mdm_devices.checkpoints(tenant_id,watermark,identity_watermark) VALUES(NEW.tenant_id,0,NEW.revision)
  ON CONFLICT(tenant_id) DO UPDATE SET identity_watermark=NEW.revision;
 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION mdm_devices.capture_identity_watermark() FROM PUBLIC;
CREATE TRIGGER device_identity_watermark AFTER INSERT ON mdm.asset_changes FOR EACH ROW EXECUTE FUNCTION mdm_devices.capture_identity_watermark();
CREATE TABLE mdm_devices.input_snapshots (
 tenant_id uuid NOT NULL REFERENCES public.mdm_tenants(tenant_id), id uuid NOT NULL,
 watermark bigint NOT NULL CHECK(watermark>=0), version text NOT NULL CHECK(length(version)=64),
 relation_revision bigint NOT NULL CHECK(relation_revision>=0), phase text NOT NULL CHECK(phase IN('endpoints','associations','standalone','sealed')), cursor text COLLATE "C" NOT NULL DEFAULT '',
 object_count bigint NOT NULL DEFAULT 0 CHECK(object_count BETWEEN 0 AND 1000000), byte_count bigint NOT NULL DEFAULT 0 CHECK(byte_count BETWEEN 0 AND 1073741824),
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,watermark,version)
);
CREATE INDEX current_identity_snapshot ON mdm_devices.input_snapshots(tenant_id,relation_revision,watermark DESC) WHERE phase='sealed';
CREATE TABLE mdm_devices.input_objects (
 tenant_id uuid NOT NULL, snapshot uuid NOT NULL, object text COLLATE "C" NOT NULL, input jsonb NOT NULL CHECK(octet_length(input::text)<=1048576), hardware jsonb NOT NULL DEFAULT '[]'::jsonb, devices text[] NOT NULL,
 PRIMARY KEY(tenant_id,snapshot,object), FOREIGN KEY(tenant_id,snapshot) REFERENCES mdm_devices.input_snapshots(tenant_id,id)
);
CREATE INDEX input_hardware_serial ON mdm_devices.input_objects USING gin((hardware->'serial'));
CREATE INDEX input_hardware_uuid ON mdm_devices.input_objects USING gin((hardware->'uuid'));
CREATE INDEX input_devices ON mdm_devices.input_objects USING gin(devices);
ALTER TABLE mdm_devices.input_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_devices.input_snapshots FORCE ROW LEVEL SECURITY;
ALTER TABLE mdm_devices.input_objects ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_devices.input_objects FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_devices.input_snapshots USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY tenant ON mdm_devices.input_objects USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON mdm_devices.input_snapshots,mdm_devices.input_objects FROM PUBLIC;
GRANT USAGE ON SCHEMA mdm_devices TO mdm_flow_runtime,mdm_command_runtime;
GRANT SELECT ON mdm_devices.associations,mdm_devices.members,mdm_devices.checkpoints,mdm_devices.input_snapshots,mdm_devices.input_objects TO mdm_flow_runtime;
GRANT SELECT ON mdm_devices.checkpoints,mdm_devices.input_snapshots,mdm_devices.input_objects TO mdm_command_runtime;
GRANT INSERT ON mdm_devices.input_snapshots,mdm_devices.input_objects TO mdm_flow_runtime;
GRANT UPDATE(phase,cursor,object_count,byte_count) ON mdm_devices.input_snapshots TO mdm_flow_runtime;

-- Sealed publication is append-closed even for the bounded builder role.
CREATE FUNCTION mdm_devices.guard_input_publication() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE publication_phase text;
BEGIN
 IF TG_TABLE_NAME='input_snapshots' THEN
  IF OLD.phase='sealed' THEN RAISE EXCEPTION 'object snapshot is sealed'; END IF;
 ELSE
  SELECT phase INTO publication_phase FROM mdm_devices.input_snapshots WHERE tenant_id=NEW.tenant_id AND id=NEW.snapshot FOR SHARE;
  IF publication_phase='sealed' THEN RAISE EXCEPTION 'object snapshot is sealed'; END IF;
 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION mdm_devices.guard_input_publication() FROM PUBLIC;
CREATE TRIGGER immutable_publication BEFORE UPDATE ON mdm_devices.input_snapshots FOR EACH ROW EXECUTE FUNCTION mdm_devices.guard_input_publication();
CREATE TRIGGER immutable_input BEFORE INSERT ON mdm_devices.input_objects FOR EACH ROW EXECUTE FUNCTION mdm_devices.guard_input_publication();

-- Execution revalidates owner evidence under the same narrow tenant watermark fence.
GRANT EXECUTE ON FUNCTION mdm.lock_asset_watermark(uuid) TO mdm_command_runtime;

-- One product-owned retirement intent. Execution attempts remain in their owners.
CREATE TABLE mdm_devices.retirements (
 tenant_id uuid NOT NULL REFERENCES public.mdm_tenants(tenant_id),
 id uuid NOT NULL, policy uuid NOT NULL, version uuid NOT NULL,
 object text NOT NULL, occurrence text NOT NULL,
 target jsonb NOT NULL, authority jsonb NOT NULL,
 delivery_seconds integer NOT NULL CHECK(delivery_seconds BETWEEN 60 AND 604800),
 created_at bigint NOT NULL, forced_at bigint, forced_by jsonb,
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,version,object,occurrence),
 CHECK(length(object) BETWEEN 1 AND 1024), CHECK(length(occurrence) BETWEEN 1 AND 256),
 CHECK(octet_length(target::text)<=1048576), CHECK(octet_length(authority::text)<=65536),
 CHECK((forced_at IS NULL)=(forced_by IS NULL))
);
CREATE TABLE mdm_devices.retirement_channels (
 tenant_id uuid NOT NULL, operation uuid NOT NULL,
 device text NOT NULL, channel text NOT NULL CHECK(channel IN('mdm','agent')),
 registration uuid NOT NULL, generation bigint NOT NULL CHECK(generation>0),
 parent_registration uuid,
 stage text NOT NULL CHECK(stage IN('cleanup','unenroll','revoke','complete')),
 effect text NOT NULL CHECK(effect IN('pending','confirmed','unknown','blocked')),
 execution uuid, blocking_execution uuid, reason text,
 PRIMARY KEY(tenant_id,operation,registration),
 FOREIGN KEY(tenant_id,operation) REFERENCES mdm_devices.retirements(tenant_id,id),
 FOREIGN KEY(tenant_id,registration,generation) REFERENCES mdm_access.registrations(tenant_id,id,generation)
);
ALTER TABLE mdm_devices.retirements ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_devices.retirements FORCE ROW LEVEL SECURITY;
ALTER TABLE mdm_devices.retirement_channels ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_devices.retirement_channels FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_devices.retirements USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY tenant ON mdm_devices.retirement_channels USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON mdm_devices.retirements,mdm_devices.retirement_channels FROM PUBLIC;
GRANT SELECT,INSERT ON mdm_devices.retirements,mdm_devices.retirement_channels TO mdm_access,mdm_flow_runtime;
GRANT SELECT ON mdm_devices.retirements,mdm_devices.retirement_channels,mdm_devices.associations,mdm_devices.members TO mdm_command_runtime;
GRANT UPDATE(forced_at,forced_by) ON mdm_devices.retirements TO mdm_access;
GRANT UPDATE(stage,effect,execution,blocking_execution,reason) ON mdm_devices.retirement_channels TO mdm_access,mdm_flow_runtime,mdm_command_runtime;
CREATE INDEX pending_retirement_channels ON mdm_devices.retirement_channels(tenant_id,operation) WHERE stage<>'complete';

CREATE TABLE mdm_devices.retirement_work (
 tenant_id uuid NOT NULL, operation uuid NOT NULL, registration uuid NOT NULL, execution uuid NOT NULL,
 PRIMARY KEY(tenant_id,execution),
 FOREIGN KEY(tenant_id,operation,registration) REFERENCES mdm_devices.retirement_channels(tenant_id,operation,registration)
);
ALTER TABLE mdm_devices.retirement_work ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_devices.retirement_work FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_devices.retirement_work USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON mdm_devices.retirement_work FROM PUBLIC;
GRANT SELECT ON mdm_devices.retirement_work TO mdm_access,mdm_flow_runtime,mdm_command_runtime;
GRANT INSERT ON mdm_devices.retirement_work TO mdm_command_runtime;
CREATE TABLE mdm_devices.asset_states (
 tenant_id uuid NOT NULL,device text NOT NULL,state text NOT NULL CHECK(state IN('active','archived','deleted')),
 PRIMARY KEY(tenant_id,device),FOREIGN KEY(tenant_id,device) REFERENCES mdm_access.devices(tenant_id,id)
);
ALTER TABLE mdm_devices.asset_states ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_devices.asset_states FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_devices.asset_states USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON mdm_devices.asset_states FROM PUBLIC;
GRANT SELECT,INSERT ON mdm_devices.asset_states TO mdm_access;
GRANT UPDATE(state) ON mdm_devices.asset_states TO mdm_access;
CREATE TABLE mdm_devices.retirement_policies (
 tenant_id uuid NOT NULL,policy uuid NOT NULL,version uuid NOT NULL,operation uuid NOT NULL,
 PRIMARY KEY(tenant_id,policy,version,operation),
 FOREIGN KEY(tenant_id,operation) REFERENCES mdm_devices.retirements(tenant_id,id)
);
ALTER TABLE mdm_devices.retirement_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_devices.retirement_policies FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_devices.retirement_policies USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON mdm_devices.retirement_policies FROM PUBLIC;
GRANT SELECT,INSERT ON mdm_devices.retirement_policies TO mdm_access,mdm_flow_runtime;
GRANT SELECT ON mdm_devices.retirement_policies TO mdm_command_runtime;
COMMIT;
