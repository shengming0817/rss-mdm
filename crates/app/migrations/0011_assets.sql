BEGIN;
GRANT SELECT(tenant_id,registration,state) ON mdm_access.credentials TO mdm_management_runtime;
GRANT SELECT,INSERT ON mdm.manual_assignments TO mdm_management_runtime;
GRANT UPDATE(revision,fact) ON mdm.manual_assignments TO mdm_management_runtime;
CREATE TABLE mdm_management.saved_queries (
 tenant_id uuid NOT NULL, instance uuid NOT NULL, owner uuid NOT NULL, id uuid NOT NULL,
 revision bigint NOT NULL CHECK(revision>0), document jsonb CHECK(octet_length(document::text)<=16384),
 PRIMARY KEY(tenant_id,instance,owner,id)
);
ALTER TABLE mdm_management.saved_queries ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_management.saved_queries FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_management.saved_queries
 USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)
 WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON mdm_management.saved_queries FROM PUBLIC;
GRANT SELECT,INSERT ON mdm_management.saved_queries TO mdm_management_runtime;
GRANT UPDATE(revision,document) ON mdm_management.saved_queries TO mdm_management_runtime;
COMMIT;
