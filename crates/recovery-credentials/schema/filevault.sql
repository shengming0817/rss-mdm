BEGIN;
-- FileVault custody outlives a particular MDM/Agent ingress. Other material owners are unchanged.
CREATE TABLE mdm_recovery.filevault_custodies (
    tenant_id uuid NOT NULL REFERENCES public.mdm_tenants (tenant_id)
  , id uuid NOT NULL
  , epoch bigint NOT NULL DEFAULT 1 CHECK (epoch > 0)
  , active boolean NOT NULL DEFAULT TRUE
  , revision bigint NOT NULL DEFAULT 0 CHECK (revision >= 0)
  , enabled boolean NOT NULL DEFAULT FALSE
  , recipient text
  , origin_device uuid NOT NULL
  , PRIMARY KEY (tenant_id, id)
  , UNIQUE (tenant_id, id, epoch)
  , FOREIGN KEY (tenant_id, origin_device) REFERENCES mdm_access.devices (tenant_id, id)
);
CREATE TABLE mdm_recovery.filevault_sources (
    tenant_id uuid NOT NULL
  , device uuid NOT NULL
  , custody uuid NOT NULL
  , epoch bigint NOT NULL
  , active boolean NOT NULL DEFAULT TRUE
  , association uuid
  , association_version bigint
  , CHECK ((association IS NULL) = (association_version IS NULL))
  , CHECK (association_version IS NULL
        OR association_version > 0)
  , FOREIGN KEY (tenant_id, association) REFERENCES mdm_devices.associations (tenant_id, id)
  , PRIMARY KEY (tenant_id, device)
  , FOREIGN KEY (tenant_id, device) REFERENCES mdm_access.devices (tenant_id, id)
  , FOREIGN KEY (tenant_id, custody, epoch) REFERENCES mdm_recovery.filevault_custodies (tenant_id, id, epoch)
);
CREATE TABLE mdm_recovery.filevault_receipts (
    tenant_id uuid NOT NULL
  , device uuid NOT NULL
  , operation uuid NOT NULL
  , purpose text NOT NULL CHECK (purpose IN ('configure', 'upload', 'link'))
  , digest bytea NOT NULL CHECK (octet_length(digest) = 32)
  , receipt jsonb NOT NULL CHECK (octet_length(CAST(receipt AS text)) <= 8192)
  , devices uuid[] NOT NULL CHECK (cardinality(devices) BETWEEN 1 AND 2)
  , PRIMARY KEY (tenant_id, device, operation)
  , FOREIGN KEY (tenant_id, device) REFERENCES mdm_access.devices (tenant_id, id)
);
ALTER TABLE mdm_recovery.filevault_custodies ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_recovery.filevault_custodies FORCE ROW LEVEL SECURITY;
ALTER TABLE mdm_recovery.filevault_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_recovery.filevault_sources FORCE ROW LEVEL SECURITY;
ALTER TABLE mdm_recovery.filevault_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_recovery.filevault_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_recovery.filevault_custodies USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY tenant ON mdm_recovery.filevault_sources USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY tenant ON mdm_recovery.filevault_receipts USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON mdm_recovery.filevault_custodies,mdm_recovery.filevault_sources,mdm_recovery.filevault_receipts TO mdm_access,mdm_command_runtime;
GRANT UPDATE(active,revision,enabled,recipient) ON mdm_recovery.filevault_custodies TO mdm_access,mdm_command_runtime;
GRANT UPDATE(custody,epoch,active,association,association_version) ON mdm_recovery.filevault_sources TO mdm_access,mdm_command_runtime;
COMMIT;
-- Resolve an authorized display/disclosure device through live ingress membership, not origin metadata.
CREATE FUNCTION mdm_recovery.filevault_accessible(subject jsonb,device uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT subject->>'kind'='filevault' AND EXISTS(
  SELECT FROM mdm_recovery.filevault_custodies f
  JOIN mdm_recovery.filevault_sources s ON(s.tenant_id,s.custody,s.epoch)=(f.tenant_id,f.id,f.epoch)
  JOIN mdm_access.devices r ON(r.tenant_id,r.id)=(s.tenant_id,s.device)
  WHERE f.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
   AND f.id::text=subject->>'custody' AND f.epoch::text=subject->>'epoch'
   AND f.active AND s.active AND r.state='active' AND r.id=$2
   AND (s.association IS NULL OR mdm_devices.association_grant_current(s.association,s.association_version,s.device)))
$$;
REVOKE ALL ON FUNCTION mdm_recovery.filevault_accessible(jsonb,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mdm_recovery.filevault_accessible(jsonb,uuid) TO mdm_access,mdm_command_runtime,mdm_identity_runtime;

GRANT UPDATE(coordinates) ON mdm_recovery.native_actions TO mdm_command_runtime;
