GRANT SELECT ON rss_da.installation_units TO da_access;
GRANT SELECT(instance_id,target,lineage) ON rss_da.installation_binding TO da_access,da_identity_runtime,da_command_runtime;
