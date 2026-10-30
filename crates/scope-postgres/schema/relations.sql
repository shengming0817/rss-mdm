BEGIN;
ALTER TABLE ONLY mdm_scope.scope_results
    ADD CONSTRAINT scope_results_tenant_id_run_fkey FOREIGN KEY (tenant_id, run) REFERENCES mdm_scope.scope_runs(tenant_id, id);

ALTER TABLE ONLY mdm_scope.scope_runs
    ADD CONSTRAINT scope_runs_tenant_id_scope_fkey FOREIGN KEY (tenant_id, scope) REFERENCES mdm_scope.scopes(tenant_id, id);

ALTER TABLE ONLY mdm_scope.scope_source_members
    ADD CONSTRAINT scope_source_members_tenant_id_run_fkey FOREIGN KEY (tenant_id, run) REFERENCES mdm_scope.scope_runs(tenant_id, id);

ALTER TABLE ONLY mdm_scope.scope_sources
    ADD CONSTRAINT scope_sources_tenant_id_scope_fkey FOREIGN KEY (tenant_id, scope) REFERENCES mdm_scope.scopes(tenant_id, id);

ALTER TABLE ONLY mdm_scope.scope_versions
    ADD CONSTRAINT scope_versions_tenant_id_id_fkey FOREIGN KEY (tenant_id, id) REFERENCES mdm_scope.scopes(tenant_id, id);

ALTER TABLE ONLY mdm_scope.scopes
    ADD CONSTRAINT scopes_tenant_id_resolution_fkey FOREIGN KEY (tenant_id, resolution) REFERENCES mdm_scope.scope_runs(tenant_id, id);

REVOKE ALL ON FUNCTION mdm_scope.scope_admission(p_scope uuid, p_device text) FROM PUBLIC;

GRANT ALL ON FUNCTION mdm_scope.scope_admission(p_scope uuid, p_device text) TO mdm_command_runtime;

GRANT ALL ON FUNCTION mdm_scope.scope_admission(p_scope uuid, p_device text) TO mdm_scope_runtime,mdm_policy_runtime,mdm_inventory_runtime,mdm_telemetry_runtime;

GRANT SELECT,INSERT ON TABLE mdm_scope.scope_results TO mdm_scope_runtime;

GRANT SELECT ON TABLE mdm_scope.scope_results TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_scope.scope_runs TO mdm_scope_runtime;





GRANT UPDATE(phase) ON TABLE mdm_scope.scope_runs TO mdm_scope_runtime;

GRANT UPDATE(source_index) ON TABLE mdm_scope.scope_runs TO mdm_scope_runtime;

GRANT UPDATE(source_cursor) ON TABLE mdm_scope.scope_runs TO mdm_scope_runtime;

GRANT UPDATE(evaluation_cursor) ON TABLE mdm_scope.scope_runs TO mdm_scope_runtime;

GRANT UPDATE(object_count) ON TABLE mdm_scope.scope_runs TO mdm_scope_runtime;

GRANT UPDATE(member_count) ON TABLE mdm_scope.scope_runs TO mdm_scope_runtime;

GRANT SELECT,INSERT ON TABLE mdm_scope.scope_source_members TO mdm_scope_runtime;

GRANT SELECT ON TABLE mdm_scope.scope_source_members TO mdm_command_runtime;

GRANT SELECT ON TABLE mdm_scope.scope_runs TO mdm_command_runtime;

GRANT SELECT,INSERT,DELETE ON TABLE mdm_scope.scope_sources TO mdm_scope_runtime;

GRANT SELECT,INSERT ON TABLE mdm_scope.scope_versions TO mdm_scope_runtime;

GRANT SELECT,INSERT ON TABLE mdm_scope.scopes TO mdm_scope_runtime;

GRANT SELECT ON TABLE mdm_scope.scopes TO mdm_command_runtime;

GRANT UPDATE(revision) ON TABLE mdm_scope.scopes TO mdm_scope_runtime;

GRANT UPDATE(deleted) ON TABLE mdm_scope.scopes TO mdm_scope_runtime;

GRANT UPDATE(calculation_revision) ON TABLE mdm_scope.scopes TO mdm_scope_runtime;

GRANT UPDATE(resolution) ON TABLE mdm_scope.scopes TO mdm_scope_runtime;

GRANT UPDATE(resolution_revision) ON TABLE mdm_scope.scopes TO mdm_scope_runtime;

GRANT EXECUTE ON FUNCTION mdm_scope.scope_admission(uuid,text) TO mdm_access;




GRANT SELECT ON mdm_scope.scopes,mdm_scope.scope_runs,mdm_scope.scope_source_members TO mdm_access;
COMMIT;

GRANT USAGE ON SCHEMA mdm_scope TO mdm_inventory_runtime,mdm_policy_runtime,mdm_telemetry_runtime;
GRANT SELECT ON mdm_scope.scopes,mdm_scope.scope_versions,mdm_scope.scope_runs,mdm_scope.scope_sources,mdm_scope.scope_source_members,mdm_scope.scope_results TO mdm_inventory_runtime,mdm_policy_runtime,mdm_telemetry_runtime;
