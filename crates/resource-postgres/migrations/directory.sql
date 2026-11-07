BEGIN;
-- The original Resource owner writes this projection in the same aggregate CAS.
-- Installation backfills with the canonical checked header decoder, then makes it NOT NULL.
ALTER TABLE mdm_resource.aggregates ADD COLUMN directory jsonb;
ALTER TABLE mdm_resource.aggregates ADD CONSTRAINT resource_directory_object CHECK(jsonb_typeof(directory)='object');
GRANT UPDATE(directory) ON mdm_resource.aggregates TO mdm_resource_runtime,mdm_software_runtime,mdm_software_driver;
CREATE INDEX resource_directory_kind ON mdm_resource.aggregates(tenant_id,((directory#>>'{kind}') COLLATE "C"),id COLLATE "C");
CREATE INDEX resource_directory_active ON mdm_resource.aggregates(tenant_id,((directory#>>'{active}')::boolean),id COLLATE "C");
CREATE INDEX resource_directory_name ON mdm_resource.aggregates(tenant_id,((directory#>>'{presentation,name}') COLLATE "C"),id COLLATE "C");
CREATE INDEX resource_directory_category ON mdm_resource.aggregates(tenant_id,((directory#>>'{presentation,category}') COLLATE "C"),id COLLATE "C");
COMMIT;
