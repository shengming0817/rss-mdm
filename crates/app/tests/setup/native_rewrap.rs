use anyhow::{Result, ensure};
use rss_mdm_native_protection::{ProtectionContext, Protector};
use sqlx::Connection;
use uuid::Uuid;

#[tokio::test]
#[ignore = "MODULE=installation.native_rewrap: retained ADE credentials re-encrypt atomically without changing identity or replay metadata"]
async fn ade_original_material_survives_rotation_and_corrupt_rows_roll_back() -> Result<()> {
    let tenant = crate::test_support::case::tenant();
    let mut c = sqlx::PgConnection::connect_with(
        &std::env::var("MDM_OWNER_URL")?
            .parse::<sqlx::postgres::PgConnectOptions>()?
            .ssl_mode(sqlx::postgres::PgSslMode::VerifyFull)
            .ssl_root_cert(std::env::var("PG_CA_FILE")?),
    )
    .await?;
    let old = Protector::new(&[81; 32])?;
    let next = Protector::with_fingerprint(&[82; 32], &[&[81; 32]], &[81; 32])?;
    let organization = Uuid::new_v4();
    let mut tx = c.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant)
        .execute(&mut *tx)
        .await?;
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&mut *tx)
            .await?;
    let token = serde_json::to_vec(
        &serde_json::json!({"consumer_key":"fixture","consumer_secret":"original-consumer-secret","access_token":"fixture","access_secret":"original-access-secret","access_token_expiry":"2030-01-01T00:00:00Z"}),
    )?;
    rss_mdm_apple_channel::ade::fixture::seed_in(&mut tx,&old,rss_mdm_apple_channel::ade::fixture::Directory {
        tenant,organization,profile:Uuid::new_v4(),remote_profile:Uuid::new_v4(),serial:"rewrap-fixture",
        token:&token,configuration:serde_json::json!({"name":"Rewrap","mandatory":true,"removable":false,"skip":[]}),origin:"https://mdm.example.test",now,
    }).await?;
    let (id,original_key,original_token):(Uuid,Vec<u8>,Vec<u8>)=sqlx::query_as("SELECT key_id,private_key,token FROM mdm_apple.ade_servers WHERE tenant_id=$1::uuid AND organization=$2").bind(tenant).bind(organization).fetch_one(&mut *tx).await?;
    tx.commit().await?;
    let aad = |version: &str, purpose: &str| -> Result<_> {
        Ok(ProtectionContext::new(
            rss_request_context::TenantId::parse(tenant)?,
            &format!("{organization}:{version}"),
            purpose,
            1,
        )?
        .derive())
    };
    let mut tx = c.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE mdm_apple.ade_servers SET token=decode('00','hex') WHERE tenant_id=$1::uuid AND organization=$2").bind(tenant).bind(organization).execute(&mut *tx).await?;
    ensure!(
        rss_mdm_apple_channel::rewrap::run(&mut tx, tenant, &next)
            .await
            .is_err()
    );
    tx.rollback().await?;
    let mut tx = c.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant)
        .execute(&mut *tx)
        .await?;
    ensure!(rss_mdm_apple_channel::rewrap::run(&mut tx, tenant, &next).await? == 2);
    ensure!(rss_mdm_apple_channel::rewrap::run(&mut tx, tenant, &next).await? == 0);
    let (after_id,key,cipher,revision):(Uuid,Vec<u8>,Vec<u8>,i64)=sqlx::query_as("SELECT key_id,private_key,token,token_revision FROM mdm_apple.ade_servers WHERE tenant_id=$1::uuid AND organization=$2").bind(tenant).bind(organization).fetch_one(&mut *tx).await?;
    ensure!(id == after_id && revision == 1 && key != original_key && cipher != original_token);
    ensure!(
        next.open_bytes(&key, &aad(&id.to_string(), "apple.ade.key")?)?
            .expose()
            == old
                .open_bytes(&original_key, &aad(&id.to_string(), "apple.ade.key")?)?
                .expose()
    );
    ensure!(
        next.open_bytes(&cipher, &aad("1", "apple.ade.token")?)?
            .expose()
            == old
                .open_bytes(&original_token, &aad("1", "apple.ade.token")?)?
                .expose()
    );
    ensure!(
        old.open_bytes(&cipher, &aad("1", "apple.ade.token")?)
            .is_err()
    );
    tx.commit().await?;
    c.close().await?;
    Ok(())
}
