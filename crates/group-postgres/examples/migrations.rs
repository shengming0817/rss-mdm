//! Emit the exact selected schema units for an external migrator; executes no DDL.
fn main() {
    println!("{}", rss_transactional_messaging_postgres::MIGRATION_SQL);
    println!("{}", rss_mdm_group_postgres::MIGRATION_SQL);
    println!("{}", rss_mdm_group_postgres::OUTBOX_MIGRATION_SQL);
    println!("{}", rss_mdm_group_postgres::GENERATIONS_MIGRATION_SQL);
}
