-- Frozen host selection metadata; the criteria remain solely in the Group core rule.
BEGIN;
CREATE TABLE mdm_assets.group_selections (
 tenant_id uuid NOT NULL, group_id uuid NOT NULL, rule_version text NOT NULL,
 selection jsonb NOT NULL CHECK(octet_length(selection::text)<=65536),
 PRIMARY KEY(tenant_id,group_id,rule_version)
);
ALTER TABLE mdm_assets.group_selections ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_assets.group_selections FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_assets.group_selections
 USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid)
 WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
ALTER TABLE mdm_assets.group_selections ADD FOREIGN KEY(tenant_id,group_id,rule_version) REFERENCES mdm_group.rules(tenant_id,group_id,version);
GRANT SELECT,INSERT ON mdm_assets.group_selections TO mdm_flow_runtime;
COMMIT;
