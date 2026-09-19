fn main() {
    println!("{}", rss_transactional_messaging_postgres::MIGRATION_SQL);
    println!("{}", rss_mdm_software_release_postgres::MIGRATION_SQL);
    println!(
        "{}",
        rss_mdm_software_release_postgres::OUTBOX_MIGRATION_SQL
    );
}
