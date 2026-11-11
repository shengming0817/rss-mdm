-- No asset/owner table permissions: this role only consumes and schedules.
GRANT SELECT,INSERT ON rss_transactional_messaging.consumer_dead_letter TO mdm_asset_ingress_consumer;
