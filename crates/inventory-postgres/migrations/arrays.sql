-- Immutable version values; current and history records carry only version references.
BEGIN;
CREATE TABLE mdm.array_versions (
 tenant_id uuid NOT NULL,version text COLLATE "C" NOT NULL CHECK(version ~ '^[0-9a-f]{64}$'),
 format integer NOT NULL CHECK(format=1),field text NOT NULL,
 definition_digest text NOT NULL CHECK(definition_digest ~ '^[0-9a-f]{64}$'),
 item_count bigint NOT NULL CHECK(item_count BETWEEN 0 AND 200000),
 canonical_bytes bigint NOT NULL CHECK(canonical_bytes >= 27),
 digest text NOT NULL CHECK(digest ~ '^[0-9a-f]{64}$'),
 definition bytea NOT NULL CHECK(octet_length(definition) BETWEEN 1 AND 65536 AND definition_digest=encode(sha256(definition),'hex')),
 PRIMARY KEY(tenant_id,version)
);
CREATE TABLE mdm.array_items (
 tenant_id uuid NOT NULL,version text COLLATE "C" NOT NULL,ordinal bigint NOT NULL CHECK(ordinal>=0),
 payload bytea NOT NULL CHECK(octet_length(payload) > 0),
 digest bytea NOT NULL CHECK(octet_length(digest)=32 AND digest=sha256(payload)),
 item_bytes integer GENERATED ALWAYS AS (octet_length(payload)) STORED,
 prefix_bytes bigint NOT NULL CHECK(prefix_bytes>=octet_length(payload)),
 PRIMARY KEY(tenant_id,version,ordinal),
 FOREIGN KEY(tenant_id,version) REFERENCES mdm.array_versions(tenant_id,version)
);
ALTER TABLE mdm.array_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm.array_versions FORCE ROW LEVEL SECURITY;
ALTER TABLE mdm.array_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm.array_items FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm.array_versions USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY tenant ON mdm.array_items USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON mdm.array_versions,mdm.array_items FROM PUBLIC;
GRANT SELECT,INSERT ON mdm.array_versions,mdm.array_items TO mdm_runtime;
ALTER TABLE mdm.inventory ADD COLUMN value_version text COLLATE "C", ADD COLUMN last_known_version text COLLATE "C";
ALTER TABLE mdm.inventory DROP CONSTRAINT inventory_value_state;
ALTER TABLE mdm.inventory ADD CONSTRAINT inventory_value_state CHECK((state='known')=(value IS NOT NULL OR value_version IS NOT NULL));
ALTER TABLE mdm.inventory ADD CONSTRAINT inventory_inline_scalar CHECK((value IS NULL OR value::jsonb->>'kind'<>'array') AND (last_known IS NULL OR last_known::jsonb->>'kind'<>'array'));
ALTER TABLE mdm.inventory ADD CONSTRAINT inventory_value_representation CHECK(NOT(value IS NOT NULL AND value_version IS NOT NULL) AND NOT(last_known IS NOT NULL AND last_known_version IS NOT NULL));
ALTER TABLE mdm.inventory ADD FOREIGN KEY(tenant_id,value_version) REFERENCES mdm.array_versions(tenant_id,version) DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE mdm.inventory ADD FOREIGN KEY(tenant_id,last_known_version) REFERENCES mdm.array_versions(tenant_id,version) DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE mdm.manual_assignments ADD COLUMN value_version text COLLATE "C", ADD COLUMN last_known_version text COLLATE "C";
ALTER TABLE mdm.manual_assignments ADD FOREIGN KEY(tenant_id,value_version) REFERENCES mdm.array_versions(tenant_id,version) DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE mdm.manual_assignments ADD FOREIGN KEY(tenant_id,last_known_version) REFERENCES mdm.array_versions(tenant_id,version) DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE mdm.manual_assignments ADD CONSTRAINT manual_value_representation CHECK(
 (fact#>>'{state,kind}'='known')=(fact#>'{state,value}' IS NOT NULL OR value_version IS NOT NULL)
 AND NOT(fact#>'{state,value}' IS NOT NULL AND value_version IS NOT NULL)
 AND (value_version IS NULL OR fact#>>'{state,kind}'='known')
 AND (last_known_version IS NULL OR (fact#>'{lastKnown,evidence}' IS NOT NULL AND fact#>'{lastKnown,value}' IS NULL))
 AND fact#>>'{state,value,kind}' IS DISTINCT FROM 'array'
 AND fact#>>'{lastKnown,value,kind}' IS DISTINCT FROM 'array');
COMMIT;
