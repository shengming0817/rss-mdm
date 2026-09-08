#[tokio::test]
async fn real_pg_inventory_and_recovery() -> anyhow::Result<()> {
    tokio::time::timeout(
        std::time::Duration::from_secs(180),
        Box::pin(rss_mdm::app::test_support::matrix(env!(
            "CARGO_BIN_EXE_rss-mdm"
        ))),
    )
    .await?
}
