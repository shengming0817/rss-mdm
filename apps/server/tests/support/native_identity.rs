//! Legal registered native identities and real certificate material, shared by both protocol proofs.
use crate::authority_t2_support::Context;
use anyhow::Result;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;
pub struct Native {
    pub request: Uuid,
    pub attempt: Uuid,
    pub credential: Uuid,
    pub epoch: Uuid,
    pub device: rss_mdm_agent_wire::DeviceId,
    pub directory: std::path::PathBuf,
    pub certificate: Vec<u8>,
    pub csr: Vec<u8>,
    pub root: Vec<u8>,
    pub trust: rss_mdm_agent_wire::pki::Trust,
}
pub async fn der(kind: &str, path: &std::path::Path) -> Result<Vec<u8>> {
    let o = tokio::process::Command::new("openssl")
        .args([kind, "-in"])
        .arg(path)
        .args(["-outform", "DER"])
        .output()
        .await?;
    anyhow::ensure!(
        o.status.success(),
        "DER conversion: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    Ok(o.stdout)
}
pub async fn seed(c: &Context, purpose: &str) -> Result<Native> {
    let request = Uuid::new_v4();
    let attempt = Uuid::new_v4();
    let credential = Uuid::new_v4();
    let epoch = Uuid::new_v4();
    let grant = Uuid::new_v4();
    let device = rss_mdm_agent_wire::DeviceId::new_v4();
    let out = tokio::process::Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../hack/native_protocol_materials.py"
        ))
        .arg(&c.inputs.directory)
        .args([
            purpose,
            &device.to_string(),
            &request.to_string(),
            &attempt.to_string(),
        ])
        .output()
        .await?;
    anyhow::ensure!(
        out.status.success(),
        "native material: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let paths: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    let directory = std::path::PathBuf::from(paths["directory"].as_str().unwrap());
    let certificate = der("x509", &directory.join("client.pem")).await?;
    let csr = der("req", &directory.join("client.csr")).await?;
    let root = der(
        "x509",
        std::path::Path::new(paths["root"].as_str().unwrap()),
    )
    .await?;
    let crl = der("crl", std::path::Path::new(paths["crl"].as_str().unwrap())).await?;
    let trust = serde_json::from_value(
        json!({"version":1,"service_id":c.inputs.installation.instance_id,"origin":"https://localhost","tenant":c.tenant.to_string(),"purpose":purpose,"revision":1,"issuers":[{"digest":format!("{:x}",Sha256::digest(&root)),"mode":"active","certificate":STANDARD.encode(&root),"root":STANDARD.encode(&root),"crl":STANDARD.encode(&crl),"root_crl":STANDARD.encode(&crl),"provisioner":"rss-agent","kid":"task-trust"}]}),
    )?;
    let mut tx = crate::command_runtime_t2_support::seed_transaction(c).await?;
    sqlx::query("INSERT INTO mdm_access.grants(tenant_id,id,actor,instance,device,purpose,state,expires_at) VALUES($1::uuid,$2,'native-fixture',$3,$4,'enrollment','consumed',clock_timestamp()+interval '4 minutes')").bind(c.tenant.to_string()).bind(grant).bind(&c.inputs.installation.instance_id).bind(device.into_uuid()).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_access.requests(tenant_id,id,source,state,grant_id,device,expires_at,issuance_operation,password_digest,password_version,credential_ref,windows_profile) VALUES($1::uuid,$2,$3,'bound',$4,$8,clock_timestamp()+interval '4 minutes',$5,repeat('a',64),1,$6,$7)").bind(c.tenant.to_string()).bind(request).bind(format!("mdm.{purpose}")).bind(grant).bind(attempt).bind(credential).bind(if purpose=="windows" {Some("Device")}else{None}).bind(device.into_uuid()).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_access.devices (tenant_id, id, channel, request_id, state, purpose, epoch) VALUES (CAST($1 AS uuid), $2, 'mdm', $3, 'active', 'primary', $4)").bind(c.tenant.to_string()).bind(device.into_uuid()).bind(request).bind(epoch).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_access.credentials (tenant_id, id, device, channel, locator, state, purpose) VALUES (CAST($1 AS uuid), $2, $3, 'mdm', $4, 'active', 'primary')").bind(c.tenant.to_string()).bind(credential).bind(device.into_uuid()).bind(format!("{:x}",Sha256::digest(&certificate))).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_access.report_sources (tenant_id, device, source, epoch, next_sequence, enabled) VALUES (CAST($1 AS uuid), $2, $3, $4, 0, TRUE)").bind(c.tenant.to_string()).bind(device.into_uuid()).bind(format!("mdm.{purpose}")).bind(epoch).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Native {
        request,
        attempt,
        credential,
        epoch,
        device,
        directory,
        certificate,
        csr,
        root,
        trust,
    })
}
pub struct Clock;
impl rss_mdm_inventory_service::clock::Clock for Clock {
    fn unix_seconds(&self) -> Option<i64> {
        Some(time::OffsetDateTime::now_utc().unix_timestamp())
    }
}
