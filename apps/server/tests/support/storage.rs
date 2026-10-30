//! 受控 S3 夹具显式建立领域材料；生产运行时不读取夹具凭据。
use super::*;
use sqlx::Connection;
use std::str::FromStr;
pub(crate) async fn seed(config: &crate::config::Config) -> Result<()> {
    if !matches!(
        config.content.as_ref().map(|c| &c.storage),
        Some(rss_mdm_content_service::Storage::S3(_))
    ) {
        return Ok(());
    }
    let provider: Value =
        serde_json::from_slice(&std::fs::read(std::env::var("MDM_S3_FIXTURE")?)?)?;
    seed_provider(config, &provider).await
}
pub(crate) async fn seed_provider(config: &crate::config::Config, provider: &Value) -> Result<()> {
    use rss_mdm_content_service::connections as c;
    let options = sqlx::postgres::PgConnectOptions::from_str(&std::env::var("MDM_OWNER_URL")?)?
        .ssl_mode(sqlx::postgres::PgSslMode::VerifyFull)
        .ssl_root_cert(std::env::var("PG_CA_FILE")?);
    let mut connection = sqlx::PgConnection::connect_with(&options).await?;
    let mut tx = connection.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(&config.identity.tenant_id)
        .execute(&mut *tx)
        .await?;
    let tenant = rss_request_context::TenantId::parse(&config.identity.tenant_id)?;
    let source = c::Source::Import {
        access_key: provider["accessKey"].as_str().unwrap().to_owned().into(),
        secret_key: provider["secretKey"].as_str().unwrap().to_owned().into(),
        session_token: None,
        expires_at: None,
    };
    let metadata = c::Metadata {
        endpoint: provider["endpoint"].as_str().unwrap().into(),
        region: provider["region"].as_str().unwrap().into(),
        bucket: provider["bucket"].as_str().unwrap().into(),
        namespace: provider["namespace"].as_str().unwrap().into(),
        private_ca: std::fs::read(provider["ca"].as_str().unwrap())?,
    };
    c::qualified_fixture_in(
        &mut tx,
        tenant,
        source,
        &metadata,
        config.native_protector()?.as_ref(),
    )
    .await?;
    tx.commit().await?;
    connection.close().await?;
    Ok(())
}
