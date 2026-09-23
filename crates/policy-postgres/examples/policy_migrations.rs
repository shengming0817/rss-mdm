fn main() {
    println!("{}", rss_transactional_messaging_postgres::MIGRATION_SQL);
    println!("{}", rss_mdm_policy_postgres::MIGRATION_SQL);
    println!("{}", rss_mdm_policy_postgres::OUTBOX_MIGRATION_SQL);
    println!("{}", rss_mdm_policy_postgres::CANDIDATES_MIGRATION_SQL);
    println!(
        "{}",
        rss_mdm_policy_postgres::EXECUTION_ADMISSION_MIGRATION_SQL
    );
}
