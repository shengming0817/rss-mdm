#[tokio::test]
async fn real_pg_inventory_and_recovery() -> anyhow::Result<()> {
    tokio::time::timeout(
        std::time::Duration::from_secs(180),
        Box::pin(rss_mdm_examples::app::test_support::matrix(&std::env::var(
            "MDM_FIXTURE_BIN",
        )?)),
    )
    .await?
}
