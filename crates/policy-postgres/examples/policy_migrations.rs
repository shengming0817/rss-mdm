fn main() {
    println!("{}", rss_transactional_messaging_postgres::MIGRATION_SQL);
    println!(
        "{}",
        rss_mdm_policy_postgres::migration_sql(rss_mdm_install_support::StorageProfile::Mdm)
    );
    println!(
        "{}",
        rss_mdm_policy_postgres::outbox_migration_sql(rss_mdm_install_support::StorageProfile::Mdm)
    );
}
