//! Independently executable public adapter proof. The host supplies the tenant transaction.
use rss_mdm_inventory_postgres::{
    self as pg,
    core::{Evidence, FieldKey, KnownValue, Scalar, SourceFact, State},
};
use sqlx::{
    Connection,
    postgres::{PgConnectOptions, PgSslMode},
};
#[tokio::test]
#[ignore = "inventory_consumer.py: real TLS PostgreSQL"]
async fn public_manual_cas_rollback_and_tenant_isolation() -> Result<(), Box<dyn std::error::Error>>
{
    let config: serde_json::Value =
        serde_json::from_slice(&std::fs::read(std::env::var("BACKEND_PG_CONFIG")?)?)?;
    let options = PgConnectOptions::new()
        .host("localhost")
        .port(config["port"].as_u64().unwrap() as u16)
        .database("backend")
        .username("mdm_management_runtime")
        .password("backend-fixture")
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert(config["ca"].as_str().unwrap());
    let mut c = sqlx::PgConnection::connect_with(&options).await?;
    let tenant = rss_request_context::TenantId::parse("11111111-1111-1111-1111-111111111111")?;
    let foreign = rss_request_context::TenantId::parse("22222222-2222-2222-2222-222222222222")?;
    let evidence = Evidence {
        source: pg::core::Source::Manual,
        registration: None,
        registration_generation: None,
        epoch: None,
        snapshot_id: "independent-operation".into(),
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
        pg::manual_in(&mut tx, foreign, &["consumer".into()])
            .await
            .is_err()
    );
    assert_eq!(
        pg::assign_in(&mut tx, tenant, "consumer", FieldKey::OfficeFloor, 0, &fact).await?,
        Some(1)
    );
    assert_eq!(
        pg::assign_in(&mut tx, tenant, "consumer", FieldKey::OfficeFloor, 0, &fact).await?,
        None
    );
    assert_eq!(
        pg::manual_in(&mut tx, tenant, &["consumer".into()]).await?[0].fact,
        fact
    );
    tx.rollback().await?;
    let mut tx = c.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await?;
    assert!(
        pg::manual_in(&mut tx, tenant, &["consumer".into()])
            .await?
            .is_empty()
    );
    tx.rollback().await?;
    c.close().await?;
    Ok(())
}
