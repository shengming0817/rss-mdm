//! Manual inventory transaction behavior. The host supplies the tenant transaction.
#[path = "../../../tests/support/context.rs"]
mod case;
use rss_mdm_inventory::{Evidence, KnownValue, Scalar, Source, SourceFact, State};
use rss_mdm_inventory_postgres as pg;
use sqlx::{
    Connection,
    postgres::{PgConnectOptions, PgSslMode},
};
#[tokio::test]
#[ignore = "make t2 MODULE=inventory.manual: real TLS PostgreSQL"]
async fn public_manual_cas_rollback_and_tenant_isolation() -> Result<(), Box<dyn std::error::Error>>
{
    let config: serde_json::Value =
        serde_json::from_slice(&std::fs::read(std::env::var("BACKEND_PG_CONFIG")?)?)?;
    let options = PgConnectOptions::new()
        .host("localhost")
        .port(config["port"].as_u64().unwrap() as u16)
        .database(config["database"].as_str().unwrap())
        .username("mdm_flow_runtime")
        .password("runtime-fixture")
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert(config["ca"].as_str().unwrap());
    let mut c = sqlx::PgConnection::connect_with(&options).await?;
    let tenant = rss_request_context::TenantId::parse(case::tenant())?;
    let foreign = rss_request_context::TenantId::parse(case::peer())?;
    let evidence = Evidence {
        source: Source::Manual,
        dataset: None,
        registration: None,
        registration_generation: None,
        epoch: None,
        snapshot_id: "manual-operation".into(),
        observed_at: 1,
        received_at: 2,
        actor: Some("fixture-authority".into()),
    };
    let fact = SourceFact {
        state: State::Known(Scalar::Integer(7)),
        last_known: Some(KnownValue {
            value: Scalar::Integer(7),
            evidence: evidence.clone(),
        }),
        evidence,
    };
    let mut tx = c.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await?;
    assert!(
        pg::manual_in(&mut tx, foreign, &["manual-device".into()])
            .await
            .is_err()
    );
    assert_eq!(
        pg::assign_in(
            &mut tx,
            tenant,
            "manual-device",
            rss_mdm_inventory::builtin::OFFICE_FLOOR,
            0,
            &fact
        )
        .await?,
        Some(1)
    );
    assert_eq!(
        pg::assign_in(
            &mut tx,
            tenant,
            "manual-device",
            rss_mdm_inventory::builtin::OFFICE_FLOOR,
            0,
            &fact
        )
        .await?,
        None
    );
    assert_eq!(
        pg::manual_in(&mut tx, tenant, &["manual-device".into()]).await?[0].fact,
        fact
    );
    tx.rollback().await?;
    let mut tx = c.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await?;
    assert!(
        pg::manual_in(&mut tx, tenant, &["manual-device".into()])
            .await?
            .is_empty()
    );
    tx.rollback().await?;
    c.close().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "make t2 MODULE=inventory.manual: real TLS PostgreSQL"]
async fn field_catalog_cas_history_and_rollback_are_atomic()
-> Result<(), Box<dyn std::error::Error>> {
    let config: serde_json::Value =
        serde_json::from_slice(&std::fs::read(std::env::var("BACKEND_PG_CONFIG")?)?)?;
    let options = PgConnectOptions::new()
        .host("localhost")
        .port(config["port"].as_u64().unwrap() as u16)
        .database(config["database"].as_str().unwrap())
        .username("mdm_flow_runtime")
        .password("runtime-fixture")
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert(config["ca"].as_str().unwrap());
    let mut c = sqlx::PgConnection::connect_with(&options).await?;
    let tenant = rss_request_context::TenantId::parse(case::tenant())?;
    let mut field = rss_mdm_inventory::builtin::fields()
        .into_iter()
        .find(|f| f.key == rss_mdm_inventory::builtin::OFFICE_FLOOR)
        .unwrap();
    field.key = rss_mdm_inventory::FieldKey::parse("custom.catalog_test.floor")?;
    let mut tx = c.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await?;
    pg::verify_collections(&mut tx).await?;
    let before = pg::watermark_in(&mut tx, tenant).await?;
    assert!(pg::publish_field_in(&mut tx, tenant, 0, &field).await?);
    assert!(!pg::publish_field_in(&mut tx, tenant, 0, &field).await?);
    assert!(
        pg::catalog_at_in(&mut tx, tenant, before)
            .await?
            .definition(field.key)
            .is_err()
    );
    assert_eq!(
        pg::catalog_in(&mut tx, tenant)
            .await?
            .definition(field.key)?,
        &field
    );
    tx.rollback().await?;
    let mut tx = c.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await?;
    assert!(
        pg::catalog_in(&mut tx, tenant)
            .await?
            .definition(field.key)
            .is_err()
    );
    assert!(pg::publish_field_in(&mut tx, tenant, 0, &field).await?);
    let published = pg::watermark_in(&mut tx, tenant).await?;
    assert!(pg::retire_field_in(&mut tx, tenant, field.key, 1).await?);
    assert!(
        pg::catalog_in(&mut tx, tenant)
            .await?
            .definition(field.key)
            .is_err()
    );
    assert_eq!(
        pg::catalog_at_in(&mut tx, tenant, published)
            .await?
            .definition(field.key)?,
        &field
    );
    field.version = 3;
    assert!(!pg::publish_field_in(&mut tx, tenant, 2, &field).await?);
    // Retired identities stay reserved without consuming the active catalog budget.
    field.version = 1;
    for index in 0..1025 {
        field.key = rss_mdm_inventory::FieldKey::parse(&format!("custom.retired_{index}"))?;
        assert!(pg::publish_field_in(&mut tx, tenant, 0, &field).await?);
        assert!(pg::retire_field_in(&mut tx, tenant, field.key, 1).await?);
    }
    field.key = rss_mdm_inventory::FieldKey::parse("custom.after_retirement")?;
    assert!(pg::publish_field_in(&mut tx, tenant, 0, &field).await?);
    assert_eq!(
        pg::catalog_in(&mut tx, tenant)
            .await?
            .definition(field.key)?,
        &field
    );
    assert!(
        pg::catalog_at_in(&mut tx, tenant, published)
            .await?
            .definition(rss_mdm_inventory::FieldKey::parse(
                "custom.catalog_test.floor"
            )?)
            .is_ok()
    );
    tx.commit().await?;
    c.close().await?;
    Ok(())
}
