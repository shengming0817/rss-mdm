//! Explicit durable signing fixtures; production loads no fixture files.
use super::*;
use sqlx::Connection;
pub(crate) async fn seed(tenant: &str, config: &crate::config::Config) -> Result<()> {
    let input = super::agent::fixture_signing_input()?;
    let private = crate::config::read(
        std::path::Path::new(input["private_key_file"].as_str().unwrap()),
        4096,
        true,
    )?;
    let mut c = sqlx::PgConnection::connect_with(&config.access_options()?).await?;
    let mut tx = c.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant)
        .execute(&mut *tx)
        .await?;
    rss_mdm_execution_service::task_signing::trust::import(
        &mut tx,
        rss_request_context::TenantId::parse(tenant)?,
        Uuid::from_u128(1),
        "https://mdm.example.test:9445",
        input["key_id"].as_str().unwrap(),
        &private,
        &serde_json::from_value(input["trusted_keys"].clone())?,
        config.native_protector()?.as_ref(),
    )
    .await?;
    tx.commit().await?;
    c.close().await?;
    Ok(())
}
/// The controlled device participant validates and persists the complete set before acknowledging.
pub(crate) async fn acknowledge(
    service: &rss_mdm_registration_service::agent::Service,
    peer: &rss_mdm_certificate::HandshakePeer,
) -> Result<()> {
    let p = service.authenticate(peer).await?;
    let config = super::identity::config(&p.tenant().to_string())?;
    let mut c = sqlx::PgConnection::connect_with(&config.access_options()?).await?;
    let mut tx = c.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(p.tenant().to_string())
        .execute(&mut *tx)
        .await?;
    let trust =
        rss_mdm_execution_service::task_signing::trust::current(&mut tx, p.tenant()).await?;
    trust.validate()?;
    anyhow::ensure!(
        trust.origin == "https://mdm.example.test:9445"
            && trust.tenant.to_string() == p.tenant().to_string()
    );
    let root = std::path::PathBuf::from(std::env::var("MDM_TEST_CONFIG")?);
    let path = root.parent().unwrap().join(format!(
        "task-trust-{}-{}.json",
        p.registration(),
        p.generation()
    ));
    if path.exists() {
        let previous = serde_json::from_slice(&std::fs::read(&path)?)?;
        trust.validate_successor(&previous)?;
    }
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let temporary = path.with_extension(format!("{}.tmp", Uuid::new_v4()));
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(&serde_json::to_vec(&trust)?)?;
    file.sync_all()?;
    std::fs::rename(temporary, &path)?;
    std::fs::File::open(root.parent().unwrap())?.sync_all()?;
    let ack = rss_mdm_agent_wire::task_trust::Acknowledgement {
        operation: Uuid::new_v4(),
        version: 1,
        registration: p.registration(),
        generation: p.generation() as u64,
        revision: trust.revision,
        digest: trust.installation_digest()?,
    };
    rss_mdm_execution_service::task_signing::trust::acknowledge(&mut tx, &p, &ack).await?;
    tx.commit().await?;
    c.close().await?;
    Ok(())
}
