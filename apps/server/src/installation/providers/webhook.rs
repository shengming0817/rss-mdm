//! Real bounded HTTPS receiver confirmation. Ordinary HTTP callers cannot manufacture qualification.
use crate::installation::{Error, Result, install::Input, local::Journal};
use rss_mdm_webhook_service::materials;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{Connection, PgConnection};
use std::time::Duration;
use uuid::Uuid;
async fn scope(c: &mut PgConnection, tenant: Uuid) -> Result<()> {
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant.to_string())
        .execute(c)
        .await
        .map_err(|_| Error::Storage)?;
    Ok(())
}
async fn probe(
    network: &crate::config::webhooks::Network,
    attempt: &materials::ConfirmationAttempt,
) -> Result<Vec<u8>> {
    let mut http = reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .tls_built_in_root_certs(false)
        .resolve_to_addrs(&network.hostname, &network.addresses)
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(10));
    for file in &network.ca_files {
        let roots = reqwest::Certificate::from_pem_bundle(
            &crate::config::read(file, 1024 * 1024, false).map_err(|_| Error::Input)?,
        )
        .map_err(|_| Error::Input)?;
        for root in roots {
            http = http.add_root_certificate(root);
        }
    }
    let http = http.build().map_err(|_| Error::Input)?;
    let mut response = http
        .post(attempt.endpoint())
        .header("content-type", "application/json")
        .header("webhook-id", attempt.operation_id().to_string())
        .header("webhook-timestamp", attempt.timestamp().to_string())
        .header("webhook-signature", attempt.signature())
        .body(attempt.body().to_vec())
        .send()
        .await
        .map_err(|_| Error::Storage)?;
    if !response.status().is_success() || response.content_length().is_some_and(|n| n > 4096) {
        return Err(Error::Storage);
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| Error::Storage)? {
        if bytes.len() + chunk.len() > 4096 {
            return Err(Error::Storage);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn runtime(input: &Input, host: Uuid) -> Result<Value> {
    let journal = Journal::open(&input.directory.join(format!("rss-mdm-{}", host.simple())))?;
    let runtime: Value = journal
        .load("requested-runtime.json")?
        .ok_or(Error::Corrupt)?;
    let applied: crate::installation::runtime_files::Applied =
        journal.load("applied.json")?.ok_or(Error::Corrupt)?;
    if runtime["runtime_binding"]["host_id"] != json!(host)
        || runtime["runtime_binding"]["operation_id"] != json!(applied.operation_id)
    {
        return Err(Error::Conflict);
    }
    Ok(runtime)
}
pub(in crate::installation) async fn reconcile(input: &Input, c: &mut PgConnection) -> Result<()> {
    let hosts:Vec<Value>=sqlx::query_scalar("SELECT receipt->'result' FROM public.mdm_tenant_operations WHERE action='provision' AND receipt->'result'->>'phase'='enabled'").fetch_all(&mut *c).await.map_err(|_|Error::Storage)?;
    for host in hosts {
        qualify_host(input, c, host).await?;
    }
    Ok(())
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Export {
    pub installation: Input,
    pub operation_id: Uuid,
    pub host_id: Uuid,
    pub reference: String,
    pub revision: i64,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportReceipt {
    pub operation_id: Uuid,
    pub host_id: Uuid,
    pub reference: String,
    pub revision: i64,
    pub key_digest: String,
}
pub async fn export(input: Export) -> Result<ExportReceipt> {
    if input.operation_id.is_nil() {
        return Err(Error::Input);
    }
    let root = Journal::open(&input.installation.directory)?;
    if root
        .load::<Option<Uuid>>("backup-operation.json")?
        .flatten()
        .is_some()
    {
        return Err(Error::Busy);
    }
    let journal = Journal::open(
        &input
            .installation
            .directory
            .join(format!("webhook-delivery-{}", input.operation_id)),
    )?;
    journal.secret(
        "request.json",
        &serde_json::to_vec(&input).map_err(|_| Error::Input)?,
    )?;
    let config: crate::config::Config =
        serde_json::from_value(runtime(&input.installation, input.host_id)?)
            .map_err(|_| Error::Input)?;
    let tenant = Uuid::parse_str(&config.identity.tenant_id).map_err(|_| Error::Corrupt)?;
    let mut c = PgConnection::connect_with(
        &input
            .installation
            .database("mdm_owner")?
            .options()
            .map_err(|_| Error::Input)?,
    )
    .await
    .map_err(|_| Error::Storage)?;
    crate::migration::verify_identity(
        &mut c,
        &crate::migration::Installation {
            instance_id: config.identity.instance_id.clone(),
            target: config.storage_binding.target,
            lineage: config.storage_binding.lineage,
            audit_mode: config.audit.mode(),
        },
    )
    .await
    .map_err(|_| Error::Conflict)?;
    let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
    scope(&mut tx, tenant).await?;
    let protection = config.native_protector().map_err(|_| Error::Corrupt)?;
    let (material, secret) = materials::export(
        &mut tx,
        tenant,
        &input.reference,
        input.revision,
        &protection,
    )
    .await
    .map_err(|_| Error::Conflict)?;
    tx.rollback().await.map_err(|_| Error::Storage)?;
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Delivery<'a> {
        tenant_id: Uuid,
        reference: &'a str,
        revision: i64,
        configuration_sha256: &'a str,
        secret: &'a str,
        confirmation_message: String,
    }
    let delivery = Delivery {
        tenant_id: tenant,
        reference: &material.reference,
        revision: material.revision,
        configuration_sha256: &material.configuration_sha256,
        secret: &secret,
        confirmation_message: String::from_utf8(materials::confirmation_message(tenant, &material))
            .map_err(|_| Error::Corrupt)?,
    };
    let bytes = zeroize::Zeroizing::new(serde_json::to_vec(&delivery).map_err(|_| Error::Corrupt)?);
    journal.secret("delivery.json", &bytes)?;
    c.close().await.map_err(|_| Error::Storage)?;
    Ok(ExportReceipt {
        operation_id: input.operation_id,
        host_id: input.host_id,
        reference: input.reference,
        revision: input.revision,
        key_digest: material.key_digest,
    })
}

async fn qualify_host(input: &Input, c: &mut PgConnection, host: Value) -> Result<()> {
    let id: Uuid = serde_json::from_value(host["hostId"].clone()).map_err(|_| Error::Corrupt)?;
    let Ok(runtime) = runtime(input, id) else {
        return Ok(());
    };
    let config: crate::config::Config =
        serde_json::from_value(runtime).map_err(|_| Error::Corrupt)?;
    let tenant = Uuid::parse_str(&config.identity.tenant_id).map_err(|_| Error::Corrupt)?;
    let protection = config.native_protector().map_err(|_| Error::Corrupt)?;
    let configuration = config
        .webhooks
        .material_configuration()
        .map_err(|_| Error::Corrupt)?;
    let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
    scope(&mut tx, tenant).await?;
    let directory = materials::directory(&mut tx, tenant)
        .await
        .map_err(|_| Error::Storage)?;
    tx.rollback().await.map_err(|_| Error::Storage)?;
    for material in directory.materials {
        qualify_material(
            c,
            tenant,
            &config.webhooks,
            protection.as_ref(),
            &configuration,
            material,
        )
        .await?;
    }

    Ok(())
}

async fn qualify_material(
    c: &mut PgConnection,
    tenant: Uuid,
    config: &crate::config::webhooks::Config,
    protection: &rss_mdm_native_protection::Protector,
    configuration: &str,
    material: materials::Material,
) -> Result<()> {
    let now = crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)
        .map_err(|_| Error::Storage)?;
    let policies = config.compile().map_err(|_| Error::Input)?;
    if policies.digest() != configuration {
        return Err(Error::Conflict);
    }
    let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
    scope(&mut tx, tenant).await?;
    let attempt = materials::begin_confirmation(
        &mut tx,
        tenant,
        &material.reference,
        material.revision,
        &policies,
        now,
        protection,
    )
    .await
    .map_err(|_| Error::Storage)?;
    let Some(attempt) = attempt else {
        tx.rollback().await.map_err(|_| Error::Storage)?;
        return Ok(());
    };
    tx.commit().await.map_err(|_| Error::Storage)?;
    let network = config
        .networks
        .iter()
        .find(|network| {
            network.tenant == tenant && network.reference == attempt.network_reference()
        })
        .ok_or(Error::Conflict)?;
    let response = probe(network, &attempt).await;
    let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
    scope(&mut tx, tenant).await?;
    materials::finish_confirmation(
        &mut tx,
        &attempt,
        response.as_ref().ok().map(Vec::as_slice),
        protection,
    )
    .await
    .map_err(|_| Error::Conflict)?;
    tx.commit().await.map_err(|_| Error::Storage)?;

    Ok(())
}

#[cfg(test)]
#[path = "../../../tests/setup/webhook.rs"]
mod tests;
