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
    let mut catalog_writer = PgConnection::connect_with(&options("mdm_flow_runtime")?).await?;
    let a = "77777777-7777-4777-8777-777777777777";
    let b = "88888888-8888-4888-8888-888888888888";
    for (tenant, source, value) in [
        (a, "mdm.windows", "A"),
        (b, "mdm.windows", "B"),
        (a, "agent.builtin", "C"),
    ] {
        let definition = rss_mdm_inventory::CollectionDefinition::new(
            "inventory",
            1,
            rss_mdm_inventory::Source::parse(source)?,
            rss_mdm_inventory::builtin::fields()
                .into_iter()
                .filter(|f| f.key == rss_mdm_inventory::builtin::MODEL)
                .collect(),
        )?;
        let mut catalog_tx = catalog_writer.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(tenant)
            .execute(&mut *catalog_tx)
            .await?;
        rss_mdm_inventory_postgres::register_collection_in(
            &mut catalog_tx,
            scope(tenant, source).tenant(),
            &definition,
        )
        .await?;
        catalog_tx.commit().await?;
        let mut tx = writer.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(tenant)
            .execute(&mut *tx)
            .await?;
        let projection =
            rss_mdm_inventory_postgres::projection_scope(scope(tenant, source).tenant());
        sqlx::query("INSERT INTO mdm.inventory(tenant_id,journal,generation,scope,coverage,field,value,batch_id,observed_at,received_at,state,registration,source,epoch,collection_sequence) VALUES($1::uuid,$5,$6,$2,$4,'device.model',$3,'read-test',1,2,'known','reg',$7,'one',0) ON CONFLICT DO NOTHING")
            .bind(tenant).bind(scope(tenant,source).encode()?).bind(serde_json::to_string(&rss_mdm_inventory::Scalar::String(value.into()))?).bind(serde_json::to_string(&definition.coverage()?)?).bind(projection.source().source()).bind(projection.generation()).bind(source).execute(&mut *tx).await?;
        tx.commit().await?;
    }
    assert!(
        InventoryReader::connect(options("mdm_runtime")?)
            .await
            .is_err()
    );
    let reader = InventoryReader::connect(options("mdm_api")?).await?;
    for _ in 0..5 {
        assert_eq!(
            reader
                .read(scope(a, "mdm.windows").tenant(), &[scope(a, "mdm.windows")])
                .await?[0]
                .fact
                .state,
            rss_mdm_inventory::State::Known(rss_mdm_inventory::Scalar::String("A".into()))
        );
        assert_eq!(
            reader
                .read(scope(b, "mdm.windows").tenant(), &[scope(b, "mdm.windows")])
                .await?[0]
                .fact
                .state,
            rss_mdm_inventory::State::Known(rss_mdm_inventory::Scalar::String("B".into()))
        );
        assert_eq!(
            reader
                .read(
                    scope(a, "agent.builtin").tenant(),
                    &[scope(a, "agent.builtin")]
                )
                .await?[0]
                .fact
                .state,
            rss_mdm_inventory::State::Known(rss_mdm_inventory::Scalar::String("C".into()))
        );
    }
    assert!(
        reader
            .read(scope(a, "absent").tenant(), &[scope(a, "absent")])
            .await
            .is_err()
    );
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
            "GRANT INSERT ON public.mdm_migrations TO mdm_api",
            "REVOKE INSERT ON public.mdm_migrations FROM mdm_api",
        ),
        (
            "GRANT SELECT ON public.mdm_migrations TO mdm_api",
            "REVOKE SELECT ON public.mdm_migrations FROM mdm_api",
        ),
        (
            "REVOKE USAGE ON SCHEMA mdm FROM mdm_api",
            "GRANT USAGE ON SCHEMA mdm TO mdm_api",
        ),
        (
            "GRANT INSERT ON mdm.inventory TO mdm_api",
            "REVOKE INSERT ON mdm.inventory FROM mdm_api",
        ),
        (
            "GRANT SELECT(scope) ON rss_observation.batches TO mdm_api",
            "REVOKE SELECT(scope) ON rss_observation.batches FROM mdm_api",
        ),
        (
            "DROP INDEX mdm.inventory_source",
            "CREATE INDEX inventory_source ON mdm.inventory(tenant_id,registration,source,epoch)",
        ),
        (
            "ALTER TABLE mdm.inventory ALTER COLUMN epoch DROP NOT NULL",
            "ALTER TABLE mdm.inventory ALTER COLUMN epoch SET NOT NULL",
        ),
        (
            "ALTER TABLE mdm.inventory DROP CONSTRAINT inventory_value_state; ALTER TABLE mdm.inventory ADD CONSTRAINT inventory_value_state CHECK(true)",
            "ALTER TABLE mdm.inventory DROP CONSTRAINT inventory_value_state; ALTER TABLE mdm.inventory ADD CONSTRAINT inventory_value_state CHECK((state='known')=(value IS NOT NULL))",
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
    for (create, drop) in [
        (
            "CREATE SEQUENCE mdm.reader_test_sequence; GRANT USAGE ON SEQUENCE mdm.reader_test_sequence TO mdm_api",
            "DROP SEQUENCE mdm.reader_test_sequence",
        ),
        (
            "CREATE FUNCTION mdm.reader_test_function() RETURNS integer LANGUAGE sql AS 'SELECT 1'",
            "DROP FUNCTION mdm.reader_test_function()",
        ),
    ] {
        sqlx::raw_sql(create).execute(&mut owner).await?;
        let rejected = InventoryReader::connect(options("mdm_api")?).await.is_err();
        owner.execute(drop).await?;
        assert!(
            rejected,
            "reader accepted additional sequence/function privilege"
        );
    }
    let administrator: PgConnectOptions = std::env::var("MDM_ADMIN_URL")?
        .parse::<PgConnectOptions>()?
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert(std::env::var("PG_CA_FILE")?);
    let database = administrator
        .get_database()
        .ok_or_else(|| anyhow::anyhow!("fixture database absent"))?
        .replace('"', "\"\"");
    let grant_database = format!("GRANT CREATE ON DATABASE \"{database}\" TO mdm_api");
    let revoke_database = format!("REVOKE CREATE ON DATABASE \"{database}\" FROM mdm_api");
    let mut administrator = PgConnection::connect_with(&administrator).await?;
    for (grant, revoke) in [
        (grant_database.as_str(), revoke_database.as_str()),
        (
            "GRANT CREATE ON SCHEMA public TO mdm_api",
            "REVOKE CREATE ON SCHEMA public FROM mdm_api",
        ),
    ] {
        sqlx::raw_sql(sqlx::AssertSqlSafe(grant))
            .execute(&mut administrator)
            .await?;
        let rejected = InventoryReader::connect(options("mdm_api")?).await.is_err();
        sqlx::raw_sql(sqlx::AssertSqlSafe(revoke))
            .execute(&mut administrator)
            .await?;
        assert!(rejected, "reader accepted CREATE privilege");
    }
    administrator
        .execute("CREATE ROLE reader_inheritor LOGIN")
        .await?;
    administrator
        .execute("GRANT mdm_api TO reader_inheritor")
        .await?;
    let rejected = InventoryReader::connect(options("mdm_api")?).await.is_err();
    administrator
        .execute("REVOKE mdm_api FROM reader_inheritor")
        .await?;
    administrator.execute("DROP ROLE reader_inheritor").await?;
    assert!(rejected, "reader accepted incoming role membership");
    administrator.close().await?;
    owner.close().await?;
    api.close().await?;
    reader.close().await;
    writer.close().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "MODULE=inventory.reader: watermark fence rejects unrelated runtime authority"]
async fn watermark_fence_rejects_unrelated_grantee() -> anyhow::Result<()> {
    let mut connection = PgConnection::connect_with(&options("mdm_flow_runtime")?).await?;
    let admin = std::env::var("MDM_ADMIN_URL")?
        .parse::<PgConnectOptions>()?
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert(std::env::var("PG_CA_FILE")?);
    let mut root = PgConnection::connect_with(&admin).await?;
    rss_mdm_inventory_postgres::verify_watermark_fence(&mut connection).await?;
    root.execute("GRANT EXECUTE ON FUNCTION mdm.lock_asset_watermark(uuid) TO mdm_api")
        .await?;
    let rejected = rss_mdm_inventory_postgres::verify_watermark_fence(&mut connection)
        .await
        .is_err();
    root.execute("REVOKE EXECUTE ON FUNCTION mdm.lock_asset_watermark(uuid) FROM mdm_api")
        .await?;
    anyhow::ensure!(rejected, "watermark fence accepted an unrelated grantee");
    rss_mdm_inventory_postgres::verify_watermark_fence(&mut connection).await?;
    root.close().await?;
    connection.close().await?;
    Ok(())
}
