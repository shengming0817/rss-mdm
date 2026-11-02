GRANT USAGE ON SCHEMA rss_ledger TO da_access,da_identity_runtime,da_identity_maintenance,da_identity_provisioning;
GRANT SELECT ON rss_ledger.heads,rss_ledger.entries TO da_access,da_identity_runtime,da_identity_maintenance,da_identity_provisioning;
GRANT EXECUTE ON FUNCTION rss_ledger.prepare_append(uuid,text,text,smallint),rss_ledger.insert_entry(uuid,text,text,bigint,bytea,bytea,bytea,text,smallint) TO da_access,da_identity_runtime,da_identity_maintenance,da_identity_provisioning;
