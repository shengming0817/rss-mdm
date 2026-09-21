-- Ordered fresh-install unit. It is not an upgrade of a populated legacy deployment.
BEGIN;
DO $$ BEGIN IF EXISTS(SELECT 1 FROM mdm.inventory) THEN
 RAISE EXCEPTION 'fresh inventory installation required'; END IF; END $$;
ALTER TABLE mdm.inventory ALTER COLUMN value DROP NOT NULL;
ALTER TABLE mdm.inventory ADD COLUMN state text NOT NULL CHECK(state IN ('known','deleted'));
ALTER TABLE mdm.inventory ADD COLUMN last_known text;
ALTER TABLE mdm.inventory ADD COLUMN last_known_batch text;
ALTER TABLE mdm.inventory ADD COLUMN last_known_observed bigint;
ALTER TABLE mdm.inventory ADD COLUMN last_known_received bigint;
ALTER TABLE mdm.inventory ADD COLUMN registration text NOT NULL;
ALTER TABLE mdm.inventory ADD COLUMN source text NOT NULL;
ALTER TABLE mdm.inventory ADD COLUMN epoch text NOT NULL;
ALTER TABLE mdm.inventory ADD CONSTRAINT inventory_value_state CHECK((state='known')=(value IS NOT NULL));
CREATE INDEX inventory_source ON mdm.inventory(tenant_id,registration,source,epoch);
CREATE TABLE mdm.manual_assignments (
 tenant_id uuid NOT NULL, device text NOT NULL, field text NOT NULL CHECK(field IN ('custom.asset_tag','custom.office_floor','custom.is_loaner','custom.purchase_date')),
 revision bigint NOT NULL CHECK(revision>0), fact jsonb NOT NULL CHECK(octet_length(fact::text)<=4096),
 PRIMARY KEY(tenant_id,device,field)
);
ALTER TABLE mdm.manual_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm.manual_assignments FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm.manual_assignments
 USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)
 WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON mdm.manual_assignments FROM PUBLIC;
COMMIT;
