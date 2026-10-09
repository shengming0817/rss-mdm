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
 tenant_id uuid PRIMARY KEY REFERENCES public.mdm_tenants(tenant_id), watermark bigint NOT NULL CHECK(watermark>=0)
);
ALTER TABLE mdm_devices.checkpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_devices.checkpoints FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_devices.checkpoints USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON mdm_devices.checkpoints FROM PUBLIC;
GRANT SELECT,INSERT ON mdm_devices.checkpoints TO mdm_access;
GRANT UPDATE(watermark) ON mdm_devices.checkpoints TO mdm_access;
GRANT USAGE ON SCHEMA mdm TO mdm_access;
GRANT SELECT ON mdm.asset_clock,mdm.inventory_history,mdm.manual_history,mdm.field_versions,mdm.collection_definitions TO mdm_access;
CREATE TABLE mdm_devices.input_snapshots (
 tenant_id uuid NOT NULL REFERENCES public.mdm_tenants(tenant_id), id uuid NOT NULL,
 watermark bigint NOT NULL CHECK(watermark>=0), version text NOT NULL CHECK(length(version)=64),
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,watermark,version)
);
CREATE TABLE mdm_devices.input_objects (
 tenant_id uuid NOT NULL, snapshot uuid NOT NULL, object text COLLATE "C" NOT NULL, input jsonb NOT NULL,
 PRIMARY KEY(tenant_id,snapshot,object), FOREIGN KEY(tenant_id,snapshot) REFERENCES mdm_devices.input_snapshots(tenant_id,id)
);
ALTER TABLE mdm_devices.input_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_devices.input_snapshots FORCE ROW LEVEL SECURITY;
ALTER TABLE mdm_devices.input_objects ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_devices.input_objects FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_devices.input_snapshots USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY tenant ON mdm_devices.input_objects USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON mdm_devices.input_snapshots,mdm_devices.input_objects FROM PUBLIC;
GRANT USAGE ON SCHEMA mdm_devices TO mdm_flow_runtime,mdm_command_runtime;
GRANT SELECT ON mdm_devices.associations,mdm_devices.members,mdm_devices.input_snapshots,mdm_devices.input_objects TO mdm_flow_runtime,mdm_command_runtime;
GRANT INSERT ON mdm_devices.input_snapshots,mdm_devices.input_objects TO mdm_flow_runtime;
COMMIT;
