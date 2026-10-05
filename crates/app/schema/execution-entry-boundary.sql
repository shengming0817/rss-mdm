-- Append-only retirement: preserve historical owners and sealed inputs.
ALTER TABLE mdm_commands.operations DROP CONSTRAINT operation_authority_source;
ALTER TABLE mdm_commands.operations ADD CONSTRAINT operation_authority_source CHECK (COALESCE(
CASE source_kind
    WHEN 'direct'::text THEN ((approval ->> 'kind'::text) IN ('user'::text,'device_control'::text))
    WHEN 'policy'::text THEN (((approval ->> 'kind'::text) IN ('policy'::text,'agent_install'::text)) AND ((approval ->> 'tenant'::text) = (tenant_id)::text) AND ((approval ->> 'device'::text) = device) AND ((approval ->> 'version'::text) = (policy_version)::text))
    WHEN 'remote_operation'::text THEN (((approval ->> 'kind'::text) = 'remote_operation'::text) AND ((approval ->> 'tenant'::text) = (tenant_id)::text) AND ((approval ->> 'device'::text) = device) AND ((approval ->> 'operation'::text) = (remote_operation)::text))
    ELSE NULL::boolean
END, false));
REVOKE INSERT ON mdm_planning.remote_operations, mdm_planning.remote_operation_targets FROM mdm_command_runtime;
REVOKE UPDATE(staged,cursor) ON mdm_planning.remote_operations FROM mdm_command_runtime;
