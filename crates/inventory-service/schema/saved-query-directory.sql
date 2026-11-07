-- A rebuildable query projection; the compiled AST remains the field-reference authority.
BEGIN;
ALTER TABLE mdm_assets.saved_queries ADD COLUMN filter_text text;
ALTER TABLE mdm_assets.saved_queries ADD CONSTRAINT saved_queries_filter_text_bound
 CHECK (filter_text IS NULL OR octet_length(filter_text)<=8192);
ALTER TABLE mdm_assets.saved_queries ADD CONSTRAINT saved_queries_filter_text_deleted
 CHECK (document IS NOT NULL OR filter_text IS NULL);
GRANT UPDATE(filter_text) ON mdm_assets.saved_queries TO mdm_inventory_runtime;
CREATE INDEX saved_queries_name_directory ON mdm_assets.saved_queries
 (tenant_id,instance,owner,((document->>'name') COLLATE "C"),id);
COMMIT;
