BEGIN;
CREATE SCHEMA mdm_recovery;
REVOKE ALL ON SCHEMA mdm_recovery FROM PUBLIC;
CREATE TABLE mdm_recovery.entries (
 tenant_id uuid NOT NULL REFERENCES public.mdm_tenants(tenant_id), id uuid NOT NULL,
 device text NOT NULL, registration uuid NOT NULL, generation bigint NOT NULL CHECK(generation>0),
 subject jsonb NOT NULL CHECK(octet_length(subject::text)<=2048),
 revision bigint NOT NULL DEFAULT 0 CHECK(revision>=0), current_version bigint,
 retired boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,device,registration,generation,subject),
 FOREIGN KEY(tenant_id,registration,generation) REFERENCES mdm_access.registrations(tenant_id,id,generation),
 FOREIGN KEY(tenant_id,device) REFERENCES mdm_access.devices(tenant_id,id)
);
CREATE TABLE mdm_recovery.versions (
 tenant_id uuid NOT NULL, entry uuid NOT NULL, version bigint NOT NULL CHECK(version>0),
 operation uuid NOT NULL, validity text NOT NULL CHECK(validity IN('unverified','verified','unknown','superseded','revoked')),
 key_id text, sealed bytea CHECK(octet_length(sealed)<=8192),
 created_at bigint NOT NULL, invalidated_at bigint,
 pending boolean NOT NULL DEFAULT true,
 cleanup_checked_at bigint NOT NULL DEFAULT 0,
 PRIMARY KEY(tenant_id,entry,version), UNIQUE(tenant_id,entry,operation),
 FOREIGN KEY(tenant_id,entry) REFERENCES mdm_recovery.entries(tenant_id,id),
 CHECK((key_id IS NULL)=(sealed IS NULL)),
 CHECK((validity IN('revoked','superseded'))=(invalidated_at IS NOT NULL))
);
ALTER TABLE mdm_recovery.entries ADD FOREIGN KEY(tenant_id,id,current_version) REFERENCES mdm_recovery.versions(tenant_id,entry,version);
CREATE INDEX recovery_operation ON mdm_recovery.versions(tenant_id,operation);
CREATE TABLE mdm_recovery.agent_guards (
 tenant_id uuid NOT NULL, registration uuid NOT NULL, generation bigint NOT NULL CHECK(generation>0), task uuid NOT NULL, attempt uuid NOT NULL,
 PRIMARY KEY(tenant_id,registration,generation), UNIQUE(tenant_id,task),
 FOREIGN KEY(tenant_id,registration,generation) REFERENCES mdm_access.registrations(tenant_id,id,generation)
);
ALTER TABLE mdm_recovery.agent_guards ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_recovery.agent_guards FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_recovery.agent_guards USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE TABLE mdm_recovery.agent_materials (
 tenant_id uuid NOT NULL, task uuid NOT NULL, attempt uuid NOT NULL, entry uuid NOT NULL, version bigint NOT NULL,
 PRIMARY KEY(tenant_id,task,attempt,entry),
 FOREIGN KEY(tenant_id,entry,version) REFERENCES mdm_recovery.versions(tenant_id,entry,version)
);
ALTER TABLE mdm_recovery.agent_materials ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_recovery.agent_materials FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_recovery.agent_materials USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE INDEX recovery_cleanup ON mdm_recovery.versions(tenant_id,invalidated_at) WHERE sealed IS NOT NULL AND NOT pending;
CREATE TABLE mdm_recovery.native_actions (
 tenant_id uuid NOT NULL, operation uuid NOT NULL, device text NOT NULL,
 registration uuid NOT NULL, generation bigint NOT NULL CHECK(generation>0),
 action text NOT NULL CHECK(action IN('configure_filevault','collect_filevault','rotate_filevault','set_recovery_lock','clear_recovery_lock','verify_recovery_lock','lock_pin')),
 inputs_purged boolean NOT NULL DEFAULT false,
 reconciles uuid,
 coordinates jsonb CHECK(octet_length(coordinates::text)<=4096), recipient text NOT NULL,
 PRIMARY KEY(tenant_id,operation),
 FOREIGN KEY(tenant_id,registration,generation) REFERENCES mdm_access.registrations(tenant_id,id,generation)
);
ALTER TABLE mdm_recovery.native_actions ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_recovery.native_actions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_recovery.native_actions USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
ALTER TABLE mdm_recovery.entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_recovery.entries FORCE ROW LEVEL SECURITY;
ALTER TABLE mdm_recovery.versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_recovery.versions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_recovery.entries USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY tenant ON mdm_recovery.versions USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON ALL TABLES IN SCHEMA mdm_recovery FROM PUBLIC;
GRANT USAGE ON SCHEMA mdm_recovery TO mdm_access,mdm_command_runtime;
GRANT SELECT,INSERT ON ALL TABLES IN SCHEMA mdm_recovery TO mdm_access,mdm_command_runtime;
GRANT UPDATE(revision,current_version,retired) ON mdm_recovery.entries TO mdm_access,mdm_command_runtime;
GRANT UPDATE(validity,key_id,sealed,invalidated_at,pending,cleanup_checked_at) ON mdm_recovery.versions TO mdm_access,mdm_command_runtime;
GRANT UPDATE(inputs_purged) ON mdm_recovery.native_actions TO mdm_command_runtime;
GRANT DELETE ON mdm_recovery.agent_guards TO mdm_command_runtime;
COMMIT;
