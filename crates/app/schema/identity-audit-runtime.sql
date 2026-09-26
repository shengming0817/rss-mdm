-- Identity supplies message/Audit grants through grant_worker. Ledger uses its published SQL surface.
GRANT USAGE ON SCHEMA rss_ledger TO mdm_identity_audit;
GRANT SELECT ON rss_ledger.heads,rss_ledger.entries TO mdm_identity_audit;
GRANT EXECUTE ON FUNCTION rss_ledger.prepare_append(uuid,text,text,smallint),rss_ledger.insert_entry(uuid,text,text,bigint,bytea,bytea,bytea,text,smallint) TO mdm_identity_audit;
