//! Emit the exact selected schema units for an external migrator; executes no DDL.
fn main() {
    println!("{}", rss_transactional_messaging_postgres::MIGRATION_SQL);
    println!("{}", rss_mdm_group_postgres::MIGRATION_SQL);
    println!("{}", rss_mdm_group_postgres::OUTBOX_MIGRATION_SQL);
    println!(
        r#"
GRANT USAGE ON SCHEMA rss_transactional_messaging TO mdm_scope_runtime;
GRANT SELECT ON rss_transactional_messaging.policy,rss_transactional_messaging.outbox TO mdm_scope_runtime;
GRANT EXECUTE ON FUNCTION rss_transactional_messaging.check_execution(),
 rss_transactional_messaging.prepare_outbox_partitions(jsonb),
 rss_transactional_messaging.append_outbox(bytea,jsonb) TO mdm_scope_runtime;
"#
    );
}
