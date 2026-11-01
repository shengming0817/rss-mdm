-- Group service relations and exact capabilities.



ALTER TABLE ONLY mdm_assets.group_fields
    ADD CONSTRAINT group_fields_tenant_id_group_id_fkey FOREIGN KEY (tenant_id, group_id) REFERENCES mdm_group.groups(tenant_id, id);

GRANT USAGE ON SCHEMA mdm_group TO mdm_group_runtime;

GRANT SELECT,INSERT,DELETE ON TABLE mdm_assets.group_fields TO mdm_inventory_runtime;

GRANT SELECT,INSERT ON TABLE mdm_assets.group_operations TO mdm_inventory_runtime;

GRANT SELECT,INSERT ON TABLE mdm_group.groups TO mdm_group_runtime;

GRANT UPDATE(presentation) ON TABLE mdm_group.groups TO mdm_group_runtime;

GRANT UPDATE(revision) ON TABLE mdm_group.groups TO mdm_group_runtime;

GRANT UPDATE(calculation_revision) ON TABLE mdm_group.groups TO mdm_group_runtime;

GRANT UPDATE(member_version) ON TABLE mdm_group.groups TO mdm_group_runtime;

GRANT UPDATE(member_count) ON TABLE mdm_group.groups TO mdm_group_runtime;

GRANT UPDATE(rule_version) ON TABLE mdm_group.groups TO mdm_group_runtime;

GRANT UPDATE(deleted) ON TABLE mdm_group.groups TO mdm_group_runtime;

GRANT UPDATE(member_set) ON TABLE mdm_group.groups TO mdm_group_runtime;

GRANT SELECT,INSERT ON TABLE mdm_group.member_changes TO mdm_group_runtime;

GRANT SELECT,INSERT ON TABLE mdm_group.member_pages TO mdm_group_runtime;

GRANT SELECT,INSERT ON TABLE mdm_group.member_rows TO mdm_group_runtime;

GRANT SELECT,INSERT ON TABLE mdm_group.member_runs TO mdm_group_runtime;

GRANT UPDATE(phase) ON TABLE mdm_group.member_runs TO mdm_group_runtime;

GRANT UPDATE(cursor) ON TABLE mdm_group.member_runs TO mdm_group_runtime;

GRANT UPDATE(diff_cursor) ON TABLE mdm_group.member_runs TO mdm_group_runtime;

GRANT UPDATE(processed_count) ON TABLE mdm_group.member_runs TO mdm_group_runtime;

GRANT UPDATE(object_count) ON TABLE mdm_group.member_runs TO mdm_group_runtime;

GRANT UPDATE(member_count) ON TABLE mdm_group.member_runs TO mdm_group_runtime;

GRANT UPDATE(added) ON TABLE mdm_group.member_runs TO mdm_group_runtime;

GRANT UPDATE(removed) ON TABLE mdm_group.member_runs TO mdm_group_runtime;

GRANT UPDATE(receipt) ON TABLE mdm_group.member_runs TO mdm_group_runtime;

GRANT SELECT,INSERT ON TABLE mdm_group.operations TO mdm_group_runtime;

GRANT SELECT,INSERT ON TABLE mdm_group.rules TO mdm_group_runtime;