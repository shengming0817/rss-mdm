//! Controlled native SCEP producer with real CSR signatures and completed TLS possession.
use super::*;
use crate::clock::Clock;
use base64::{Engine, engine::general_purpose::STANDARD};
use rss_mdm_certificate::HandshakePeer;
use rss_mdm_execution_service::{Task, storage, transaction};
use rss_mdm_windows_mdm::native::{Execution, Request as Native, Value as NativeValue};
use sqlx::Row;

pub(crate) async fn issue(
    app: &crate::api::Assembly,
    router: &Router,
    _root: &std::path::Path,
    installation: uuid::Uuid,
) -> Result<HandshakePeer> {
    let root = std::path::PathBuf::from(std::env::var("MDM_AGENT_PKI_FIXTURES")?);
    let root = root.as_path();
    let (id, deadline, task) = transaction::inspect(&app.execution_runtime, rss_request_context::TenantId::parse(case_tenant())?, (&app.protection, installation), |ctx, tx| Box::pin(async move {
        let (key, installation) = *ctx;
        let tenant = tx.tenant_id();
        let row = tx.with_connection(move |c| Box::pin(async move {
            sqlx::query("SELECT id,delivery,deadline FROM mdm_access.agent_bootstraps WHERE tenant_id=$1::uuid AND installation=$2")
                .bind(tenant.to_string()).bind(installation).fetch_one(c).await
        })).await?;
        let delivery = row.try_get("delivery")?;
        let op = storage::load(tx,key,delivery).await?;
        Ok((row.try_get::<uuid::Uuid,_>("id")?, row.try_get::<i64,_>("deadline")?, op.request.task))
    })).await?;
    // Read only the protected command emitted by the product; the challenge API checks dispatch.
    let secret = match task {
        Task::Windows {
            request:
                Execution::SyncMl {
                    request: Native::Sequence { operations },
                },
        } => {
            let value = operations
                .into_iter()
                .find_map(|op| match op {
                    Native::Node {
                        node,
                        value: Some(NativeValue::Text(value)),
                        ..
                    } if node.ends_with("/Challenge") => Some(value),
                    _ => None,
                })
                .ok_or_else(|| anyhow::anyhow!("SCEP challenge missing"))?;
            String::from_utf8(STANDARD.decode(value)?)?
        }
        Task::Macos {
            request: rss_mdm_apple_mdm::native::request::Request::InstallProfile { profile },
        } => {
            let value = profile.payloads[0].fields.to_plist()?;
            // Fields retain their schema-facing plist dictionary in JSON.
            value["PayloadContent"]
                .as_dictionary()
                .and_then(|v| v.get("Challenge"))
                .and_then(plist::Value::as_string)
                .ok_or_else(|| anyhow::anyhow!("SCEP challenge missing: field structure"))?
                .to_owned()
        }
        _ => anyhow::bail!("unexpected bootstrap command"),
    };
    let temp = tempfile::tempdir()?;
    let csr_file = temp.path().join("bootstrap.csr");
    let key = temp.path().join("bootstrap.pk8");
    let run = |cmd: &mut Command| -> Result<()> {
        let output = cmd.output()?;
        ensure!(
            output.status.success(),
            "bootstrap crypto producer: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(())
    };
    run(Command::new("openssl")
        .args([
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-outform",
            "DER",
            "-out",
        ])
        .arg(&key))?;
    let cn = rss_mdm_certificate::apple::subject(installation, id);
    run(Command::new("openssl")
        .args(["req", "-new", "-keyform", "DER", "-key"])
        .arg(&key)
        .args([
            "-subj",
            &format!("/OU=rss-mdm-agent-bootstrap/CN={cn}"),
            "-outform",
            "DER",
            "-out",
        ])
        .arg(&csr_file))?;
    let csr = std::fs::read(csr_file)?;
    let config = app
        .agent_enrollment
        .as_ref()
        .unwrap()
        .bootstrap_configuration()?;
    let now = crate::clock::SystemClock.unix_seconds()?;
    let mut request = json!({"timestamp":time::OffsetDateTime::from_unix_timestamp(now)?.format(&time::format_description::well_known::Rfc3339)?,"provisionerName":config.trust.active()?.provisioner,"x509CertificateRequest":{"raw":STANDARD.encode(&csr)},"scepChallenge":secret,"scepTransactionID":id.to_string()});
    webhook(router, config, "challenge", &request).await?;
    let chain = super::pki::leaf(
        root,
        &csr,
        &rss_mdm_certificate::bootstrap::subject(installation, id),
        &[],
        now - 1,
        deadline,
    )?;
    request["x509Certificate"] = json!({"raw":STANDARD.encode(&chain[0])});
    webhook(router, config, "notify", &request).await?;
    super::agent_tls::peer_with_verifier(
        config.trust.verifier(false),
        &chain,
        root,
        key.to_str().unwrap(),
    )
    .await
}
async fn webhook(
    router: &Router,
    config: &rss_mdm_registration_service::agent::bootstrap::Configuration,
    phase: &str,
    input: &Value,
) -> Result<()> {
    let (id, key) = if phase == "challenge" {
        (&config.challenge_id, &config.challenge_key)
    } else {
        (&config.notify_id, &config.notify_key)
    };
    let bytes = serde_json::to_vec(input)?;
    let signature = ring::hmac::sign(key, &bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/agent/enroll/bootstrap/scep/{phase}"))
                .header("content-type", "application/json")
                .header(
                    "host",
                    url::Url::parse(&config.trust.public()?.origin)?.authority(),
                )
                .header("x-smallstep-webhook-id", id)
                .header("x-smallstep-signature", signature)
                .body(Body::from(bytes))?,
        )
        .await?;
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 128 * 1024).await?;
    ensure!(
        status.is_success(),
        "bootstrap {phase}: {status} {}",
        String::from_utf8_lossy(&body)
    );
    Ok(())
}
pub(crate) async fn grant(
    router: &Router,
    peer: &HandshakePeer,
    input: &Value,
) -> Result<GrantResponse> {
    let mut request = Request::builder()
        .method("POST")
        .uri("/api/v1/agent/enroll/native-grants")
        .header("host", "mdm.example.test:9445")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(input)?))?;
    request.extensions_mut().insert(peer.clone());
    let response = router.clone().oneshot(request).await?;
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024).await?;
    Ok(GrantResponse {
        status,
        body: serde_json::from_slice(&bytes)?,
    })
}

pub(crate) struct GrantResponse {
    status: StatusCode,
    body: Value,
}
impl GrantResponse {
    pub(crate) fn status(&self) -> StatusCode {
        self.status
    }
    pub(crate) async fn json<T: serde::de::DeserializeOwned>(self) -> Result<T> {
        Ok(serde_json::from_value(self.body)?)
    }
}
