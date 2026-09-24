GRANT USAGE ON SCHEMA rss_audit,rss_ledger,mdm_audit TO mdm_access,mdm_management_runtime,mdm_command_runtime,mdm_software_driver;
GRANT SELECT ON rss_audit.heads,rss_audit.records,rss_ledger.heads,rss_ledger.entries TO mdm_access,mdm_management_runtime,mdm_command_runtime,mdm_software_driver;
GRANT EXECUTE ON FUNCTION rss_audit.reserve(uuid),rss_audit.append(uuid,text,text,bigint,bytea,bigint) TO mdm_access,mdm_management_runtime,mdm_command_runtime,mdm_software_driver;
GRANT EXECUTE ON FUNCTION rss_ledger.prepare_append(uuid,text,text,smallint),rss_ledger.insert_entry(uuid,text,text,bigint,bytea,bytea,bytea,text,smallint) TO mdm_access,mdm_management_runtime,mdm_command_runtime,mdm_software_driver;
GRANT SELECT,INSERT ON mdm_audit.receipts TO mdm_access,mdm_management_runtime,mdm_command_runtime,mdm_software_driver;
