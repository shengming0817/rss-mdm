//! Real bounded HTTPS receiver confirmation. Ordinary HTTP callers cannot manufacture qualification.
use crate::installation::{Error, Result, install::Input, local::Journal};
use base64::{Engine, engine::general_purpose::STANDARD};
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
    network: &crate::webhooks::Network,
    material: &materials::Material,
    tenant: Uuid,
    secret: &str,
) -> Result<String> {
    let endpoint = material.endpoint.as_deref().ok_or(Error::Input)?;
    let url = url::Url::parse(endpoint).map_err(|_| Error::Input)?;
    if network.tenant != tenant
        || url.scheme() != "https"
        || url.host_str() != Some(network.hostname.as_str())
        || url.port_or_known_default() != Some(network.port)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.query().is_some()
    {
        return Err(Error::Input);
    }
    rss_mdm_webhook_service::transport::NetworkAccess::new(
        network.addresses.clone(),
        network.cidrs.clone(),
    )
    .map_err(|_| Error::Input)?;
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
    let body = serde_json::to_vec(&materials::ConfirmationRequest {
        kind: materials::ConfirmationKind::V1,
        tenant_id: tenant,
        operation_id: material.operation_id,
        reference: material.reference.clone(),
        revision: material.revision,
        configuration_sha256: material.configuration_sha256.clone(),
        challenge: material.challenge.clone(),
    })
    .map_err(|_| Error::Input)?;
    let now = crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)
        .map_err(|_| Error::Storage)?;
    let key = zeroize::Zeroizing::new(
        STANDARD
            .decode(secret.strip_prefix("whsec_").ok_or(Error::Corrupt)?)
            .map_err(|_| Error::Corrupt)?,
    );
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key);
    let mut signing = ring::hmac::Context::with_key(&key);
    signing.update(format!("{}.{now}.", material.operation_id).as_bytes());
    signing.update(&body);
    let signature = format!("v1,{}", STANDARD.encode(signing.sign().as_ref()));
    let mut response = http
        .post(url)
        .header("content-type", "application/json")
        .header("webhook-id", material.operation_id.to_string())
        .header("webhook-timestamp", now.to_string())
        .header("webhook-signature", signature)
        .body(body)
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
    let proof: materials::ConfirmationResponse =
        serde_json::from_slice(&bytes).map_err(|_| Error::Input)?;
    let supplied = STANDARD
        .decode(&proof.confirmation_proof)
        .map_err(|_| Error::Input)?;
    ring::hmac::verify(
        &key,
        &materials::confirmation_message(tenant, material),
        &supplied,
    )
    .map_err(|_| Error::Conflict)?;
    Ok(proof.confirmation_proof)
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
    config: &crate::webhooks::Config,
    protection: &rss_mdm_native_protection::Protector,
    configuration: &str,
    material: materials::Material,
) -> Result<()> {
    let now = crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)
        .map_err(|_| Error::Storage)?;
    if material.confirmed
        || material.revoked
        || material.configuration_sha256 != configuration
        || material.attempted_at.is_some_and(|at| now - at < 60)
    {
        return Ok(());
    }
    let Some(network) = config.networks.iter().find(|n| {
        n.tenant == tenant && material.network_reference.as_deref() == Some(&n.reference)
    }) else {
        return Ok(());
    };
    let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
    scope(&mut tx, tenant).await?;
    let (_, secret) = materials::export(
        &mut tx,
        tenant,
        &material.reference,
        material.revision,
        protection,
    )
    .await
    .map_err(|_| Error::Storage)?;
    sqlx::query("UPDATE mdm_webhook.key_materials SET attempted_at=$4,failure_reason='confirmation_pending' WHERE tenant_id=$1 AND reference=$2 AND revision=$3 AND NOT confirmed AND NOT revoked").bind(tenant).bind(&material.reference).bind(material.revision).bind(now).execute(&mut *tx).await.map_err(|_|Error::Storage)?;
    tx.commit().await.map_err(|_| Error::Storage)?;
    let response = probe(network, &material, tenant, &secret).await;
    let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
    scope(&mut tx, tenant).await?;
    match response {
        Ok(proof) => materials::confirm(
            &mut tx,
            tenant,
            &material.reference,
            material.revision,
            &proof,
            protection,
        )
        .await
        .map_err(|_| Error::Conflict)?,
        Err(_) => {
            sqlx::query("UPDATE mdm_webhook.key_materials SET failure_reason='receiver_confirmation_unavailable' WHERE tenant_id=$1 AND reference=$2 AND revision=$3 AND NOT confirmed").bind(tenant).bind(&material.reference).bind(material.revision).execute(&mut *tx).await.map_err(|_|Error::Storage)?;
        }
    }
    tx.commit().await.map_err(|_| Error::Storage)?;

    Ok(())
}

#[cfg(test)]
#[path = "../../../tests/setup/webhook.rs"]
mod tests;
