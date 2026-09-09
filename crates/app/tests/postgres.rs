use rss_mdm_inventory_postgres::InventoryReader;
use sqlx::{
    Connection, Executor, PgConnection,
    postgres::{PgConnectOptions, PgSslMode},
};
fn options(user: &str) -> anyhow::Result<PgConnectOptions> {
    Ok(std::env::var("DATABASE_URL")?
        .parse::<PgConnectOptions>()?
        .username(user)
        .password(if user == "mdm_api" {
            "api-fixture"
        } else {
            "runtime-fixture"
        })
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert(std::env::var("PG_CA_FILE")?))
}
fn scope(tenant: &str, source: &str) -> rss_observation::Scope {
    serde_json::from_value(serde_json::json!({"tenant":tenant,"object":"reader-device","registration":"reg","source":source,"dataset":"inventory","epoch":"one"})).unwrap()
}
#[tokio::test]
#[ignore = "make t2: real TLS PostgreSQL"]
async fn reader_is_exact_tenant_scoped_and_read_only() -> anyhow::Result<()> {
    let mut writer = PgConnection::connect_with(&options("mdm_runtime")?).await?;
    let a = "77777777-7777-4777-8777-777777777777";
    let b = "88888888-8888-4888-8888-888888888888";
    for (tenant, source, value) in [(a, "one", "A"), (b, "one", "B"), (a, "two", "C")] {
        let mut tx = writer.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(tenant)
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO mdm.inventory VALUES($1::uuid,'mdm.observation.v1','inventory-v1',$2,'coverage','device.model',$3,'read-test',1,2) ON CONFLICT DO NOTHING")
            .bind(tenant).bind(scope(tenant,source).encode()?).bind(value).execute(&mut *tx).await?;
        tx.commit().await?;
    }
    assert!(
        InventoryReader::connect(options("mdm_runtime")?)
            .await
            .is_err()
    );
    let reader = InventoryReader::connect(options("mdm_api")?).await?;
    for _ in 0..5 {
        assert_eq!(reader.read(&scope(a, "one")).await?[0].value, "A");
        assert_eq!(reader.read(&scope(b, "one")).await?[0].value, "B");
        assert_eq!(reader.read(&scope(a, "two")).await?[0].value, "C");
    }
    assert!(reader.read(&scope(a, "absent")).await?.is_empty());
    let mut api = PgConnection::connect_with(&options("mdm_api")?).await?;
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM mdm.inventory")
            .fetch_one(&mut api)
            .await?,
        0
    );
    assert!(api.execute("DELETE FROM mdm.inventory").await.is_err());
    assert!(
        api.execute("SELECT * FROM rss_observation.batches")
            .await
            .is_err()
    );
    let owner: PgConnectOptions = std::env::var("MDM_OWNER_URL")?
        .parse::<PgConnectOptions>()?
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert(std::env::var("PG_CA_FILE")?);
    let mut owner = PgConnection::connect_with(&owner).await?;
    for (grant, revoke) in [
        (
            "GRANT INSERT ON mdm.inventory TO mdm_api",
            "REVOKE INSERT ON mdm.inventory FROM mdm_api",
        ),
        (
            "GRANT SELECT(scope) ON rss_observation.batches TO mdm_api",
            "REVOKE SELECT(scope) ON rss_observation.batches FROM mdm_api",
        ),
        (
            "ALTER TABLE mdm.inventory NO FORCE ROW LEVEL SECURITY",
            "ALTER TABLE mdm.inventory FORCE ROW LEVEL SECURITY",
        ),
    ] {
        owner.execute(grant).await?;
        let rejected = InventoryReader::connect(options("mdm_api")?).await.is_err();
        owner.execute(revoke).await?;
        assert!(rejected, "reader accepted privilege drift");
    }
    owner.close().await?;
    api.close().await?;
    reader.close().await;
    writer.close().await?;
    Ok(())
}
