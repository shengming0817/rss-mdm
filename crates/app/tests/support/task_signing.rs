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
    use rss_mdm_agent_wire::task_trust::{KeyState, PublicKey, Trust};
    use rss_mdm_native_protection::ProtectionContext;
    let tenant_id = rss_request_context::TenantId::parse(tenant)?;
    let operation = Uuid::from_u128(1);
    let key_id = input["key_id"].as_str().unwrap();
    let keys: std::collections::BTreeMap<String, String> =
        serde_json::from_value(input["trusted_keys"].clone())?;
    let trust = Trust {
        version: 1,
        tenant: Uuid::parse_str(tenant)?,
        origin: "https://mdm.example.test:9445".into(),
        revision: 1,
        keys: keys
            .into_iter()
            .map(|(id, public_key)| PublicKey {
                state: if id == key_id {
                    KeyState::Active
                } else {
                    KeyState::VerifyOnly
                },
                id,
                public_key,
            })
            .collect(),
    };
    trust.validate()?;
    let protection = config.native_protector()?;
    let private_context =
        ProtectionContext::new(tenant_id, key_id, "task-signing.private-key", 1)?.derive();
    let sealed = protection.seal_bytes(&private, &private_context)?;
    let request_context = ProtectionContext::new(
        tenant_id,
        &operation.to_string(),
        "task-signing.operation",
        1,
    )?
    .derive();
    let fingerprint = protection.mac(b"fixed task signing fixture", &request_context)?;
    sqlx::query("INSERT INTO mdm_task_signing.heads(tenant_id,revision) VALUES($1::uuid,1) ON CONFLICT DO NOTHING")
        .bind(tenant).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_task_signing.keys(tenant_id,key_id,private_key) VALUES($1::uuid,$2,$3) ON CONFLICT DO NOTHING")
        .bind(tenant).bind(key_id).bind(sealed).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_task_signing.versions(tenant_id,revision,operation_id,fingerprint_key,fingerprint,body,digest) VALUES($1::uuid,1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING")
        .bind(tenant).bind(operation).bind(protection.fingerprint_id()).bind(fingerprint.as_slice())
        .bind(serde_json::to_value(&trust)?).bind(trust.installation_digest()?).execute(&mut *tx).await?;
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
