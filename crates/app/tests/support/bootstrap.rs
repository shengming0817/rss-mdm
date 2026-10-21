//! Controlled native SCEP producer with real CSR signatures and completed TLS possession.
use super::{process::*, runtime::*, *};
use crate::clock::Clock;
use anyhow::Context;
use base64::{Engine, engine::general_purpose::STANDARD};
use rss_mdm_execution_service::{Task, storage, transaction};
use rss_mdm_windows_mdm::native::{Execution, Request as Native, Value as NativeValue};
use sqlx::Row;

pub(crate) async fn issue(
    app: &Arc<crate::api::Assembly>,
    router: &Router,
    _root: &std::path::Path,
    installation: uuid::Uuid,
) -> Result<BootstrapPeer> {
    issue_observed(app, router, _root, installation, None).await
}
pub(crate) async fn issue_windows(
    app: &Arc<crate::api::Assembly>,
    router: &Router,
    root: &std::path::Path,
    installation: uuid::Uuid,
    message: &rss_mdm_windows_mdm::syncml::Message,
) -> Result<BootstrapPeer> {
    issue_observed(
        app,
        router,
        root,
        installation,
        Some(Observed::Windows(message)),
    )
    .await
}
pub(crate) async fn issue_apple(
    app: &Arc<crate::api::Assembly>,
    router: &Router,
    root: &std::path::Path,
    installation: uuid::Uuid,
    payload: &plist::Dictionary,
) -> Result<BootstrapPeer> {
    issue_observed(
        app,
        router,
        root,
        installation,
        Some(Observed::Apple(payload)),
    )
    .await
}
enum Observed<'a> {
    Windows(&'a rss_mdm_windows_mdm::syncml::Message),
    Apple(&'a plist::Dictionary),
}
async fn issue_observed(
    app: &Arc<crate::api::Assembly>,
    router: &Router,
    _root: &std::path::Path,
    installation: uuid::Uuid,
    observed: Option<Observed<'_>>,
) -> Result<BootstrapPeer> {
    let root = std::path::PathBuf::from(std::env::var("MDM_AGENT_PKI_FIXTURES")?);
    let root = root.as_path();
    let (id, deadline, task) = transaction::inspect(&app.execution_runtime, rss_request_context::TenantId::parse(case_tenant())?, (&app.protection, installation), |ctx, tx| Box::pin(async move {
        let (key, installation) = *ctx;
        let tenant = tx.tenant_id();
        let row = tx.with_connection(move |c| Box::pin(async move {
            sqlx::query("SELECT id,delivery,deadline FROM mdm_access.agent_bootstraps WHERE tenant_id=$1::uuid AND installation=$2 AND active")
                .bind(tenant.to_string()).bind(installation).fetch_one(c).await
        })).await?;
        let delivery = row.try_get("delivery")?;
        let op = storage::load(tx,key,delivery).await?;
        Ok((row.try_get::<uuid::Uuid,_>("id")?, row.try_get::<i64,_>("deadline")?, op.request.task))
    })).await?;
    // Read only the protected command emitted by the product; the challenge API checks dispatch.
    let mut subject_from_profile = None;
    let mut provisioner_from_profile = None;
    let secret = match task {
        Task::Windows {
            request:
                Execution::SyncMl {
                    request: Native::Atomic { operations },
                },
        } => {
            if let Some(Observed::Windows(message)) = observed {
                let fields = windows_fields(&message.commands);
                for operation in &operations {
                    if let Native::Node {
                        node,
                        value: Some(value),
                        ..
                    } = operation
                    {
                        let field = node.rsplit('/').next().unwrap();
                        let expected = match value {
                            NativeValue::Text(v) => v.clone(),
                            NativeValue::Integer(v) => v.to_string(),
                            _ => anyhow::bail!("unexpected SCEP value"),
                        };
                        ensure!(
                            fields.get(field) == Some(&expected),
                            "native SCEP field {field} differs from frozen delivery"
                        );
                    }
                }
                let challenge = fields
                    .get("Challenge")
                    .ok_or_else(|| anyhow::anyhow!("missing delivered challenge"))?;
                String::from_utf8(STANDARD.decode(challenge)?)?
            } else {
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
        }
        Task::Macos {
            request: rss_mdm_apple_mdm::native::request::Request::InstallProfile { profile },
        } => {
            let expected = profile.payloads[0].fields.to_plist()?;
            let expected = expected["PayloadContent"]
                .as_dictionary()
                .context("frozen SCEP content")?;
            let Some(Observed::Apple(payload)) = observed else {
                anyhow::bail!("Apple bootstrap requires the actually delivered profile");
            };
            let bytes = payload
                .get("Payload")
                .and_then(plist::Value::as_data)
                .context("delivered profile bytes")?;
            use x509_cert::der::{Decode, asn1::OctetString};
            let signed = cms::content_info::ContentInfo::from_der(bytes)?
                .content
                .decode_as::<cms::signed_data::SignedData>()?;
            let content = signed
                .encap_content_info
                .econtent
                .context("signed SCEP profile content")?
                .decode_as::<OctetString>()?;
            let profile = plist::Value::from_reader(std::io::Cursor::new(content.as_bytes()))?;
            let scep = profile
                .as_dictionary()
                .and_then(|p| p.get("PayloadContent"))
                .and_then(plist::Value::as_array)
                .and_then(|ps| {
                    ps.iter().filter_map(plist::Value::as_dictionary).find(|p| {
                        p.get("PayloadType").and_then(plist::Value::as_string)
                            == Some("com.apple.security.scep")
                    })
                })
                .and_then(|p| p.get("PayloadContent"))
                .and_then(plist::Value::as_dictionary)
                .context("delivered SCEP payload")?;
            for field in [
                "URL",
                "Name",
                "Subject",
                "Challenge",
                "Key Type",
                "Keysize",
                "Key Usage",
                "KeyIsExtractable",
                "AllowAllAppsAccess",
            ] {
                ensure!(
                    scep.get(field)
                        == Some(expected.get(field).context("required frozen SCEP field")?),
                    "delivered SCEP {field} differs from frozen configuration"
                );
            }
            let subject = scep
                .get("Subject")
                .and_then(plist::Value::as_array)
                .context("delivered SCEP subject")?;
            let mut dn = String::new();
            for rdn in subject {
                for attribute in rdn.as_array().context("SCEP RDN")? {
                    let pair = attribute.as_array().context("SCEP attribute")?;
                    ensure!(pair.len() == 2);
                    let name = pair[0].as_string().context("SCEP attribute name")?;
                    let value = pair[1].as_string().context("SCEP attribute value")?;
                    ensure!(
                        matches!(name, "CN" | "OU") && !value.contains(['/', '\\']),
                        "bounded SCEP subject"
                    );
                    dn.push_str(&format!("/{name}={value}"));
                }
            }
            subject_from_profile = Some(dn);
            provisioner_from_profile = Some(
                scep.get("Name")
                    .and_then(plist::Value::as_string)
                    .context("delivered provisioner")?
                    .to_owned(),
            );
            scep.get("Challenge")
                .and_then(plist::Value::as_string)
                .context("delivered SCEP challenge")?
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
    let subject =
        subject_from_profile.unwrap_or_else(|| format!("/OU=rss-mdm-agent-bootstrap/CN={cn}"));
    run(Command::new("openssl")
        .args(["req", "-new", "-keyform", "DER", "-key"])
        .arg(&key)
        .args(["-subj", &subject, "-outform", "DER", "-out"])
        .arg(&csr_file))?;
    let csr = std::fs::read(csr_file)?;
    let config = app
        .agent_enrollment
        .as_ref()
        .unwrap()
        .bootstrap_configuration()?;
    let now = crate::clock::SystemClock.unix_seconds()?;
    let mut request = json!({"timestamp":time::OffsetDateTime::from_unix_timestamp(now)?.format(&time::format_description::well_known::Rfc3339)?,"provisionerName":provisioner_from_profile.unwrap_or(config.trust.active()?.provisioner.clone()),"x509CertificateRequest":{"raw":STANDARD.encode(&csr)},"scepChallenge":secret,"scepTransactionID":id.to_string()});
    let approval = webhook(router, config, "challenge", &request).await?;
    // Simulate the CA losing the first approved response after the transaction commits.
    ensure!(
        webhook(router, config, "challenge", &request).await? == approval,
        "exact challenge retry must reuse the approval"
    );
    let mut changed = request.clone();
    changed["scepTransactionID"] = json!(Uuid::new_v4());
    ensure!(
        webhook_response(router, config, "challenge", &changed)
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    changed = request.clone();
    changed["scepChallenge"] = json!(credential("different-bootstrap-challenge"));
    ensure!(
        webhook_response(router, config, "challenge", &changed)
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    let approved = &approval["data"]["subject"];
    ensure!(
        approved["commonName"] == cn
            && approved["organizationalUnit"] == json!([rss_mdm_certificate::bootstrap::PURPOSE])
    );
    let expiry = time::OffsetDateTime::parse(
        approval["data"]["notAfter"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("missing approved expiry"))?,
        &time::format_description::well_known::Rfc3339,
    )?
    .unix_timestamp();
    ensure!(expiry <= deadline && expiry >= now.min(deadline - 1) && expiry <= now + 1801);
    let frozen_expiry = pg(&format!(
        "SELECT deadline FROM mdm_access.agent_bootstraps WHERE tenant_id='{}' AND id='{id}'",
        case_tenant()
    ))?;
    ensure!(
        expiry == frozen_expiry.trim().parse::<i64>()?,
        "approval must retain its committed deadline"
    );
    let subject = format!(
        "OU={},CN={}",
        approved["organizationalUnit"][0].as_str().unwrap(),
        approved["commonName"].as_str().unwrap()
    );
    let chain = super::pki::leaf(root, &csr, &subject, &[], now - 1, expiry)?;
    request["x509Certificate"] = json!({"raw":STANDARD.encode(&chain[0])});
    webhook(router, config, "notify", &request).await?;
    Ok(BootstrapPeer {
        app: app.clone(),
        chain,
        directory: temp,
    })
}
async fn webhook(
    router: &Router,
    config: &rss_mdm_registration_service::agent::bootstrap::Configuration,
    phase: &str,
    input: &Value,
) -> Result<Value> {
    let (status, body) = webhook_response(router, config, phase, input).await?;
    ensure!(status.is_success(), "bootstrap {phase}: {status} {body}");
    Ok(body)
}
async fn webhook_response(
    router: &Router,
    config: &rss_mdm_registration_service::agent::bootstrap::Configuration,
    phase: &str,
    input: &Value,
) -> Result<(StatusCode, Value)> {
    let bytes = serde_json::to_vec(input)?;
    let stage = if phase == "challenge" {
        rss_mdm_pki_service::scep::Stage::Challenge
    } else {
        rss_mdm_pki_service::scep::Stage::Notify
    };
    let (id, signature) =
        config
            .webhooks
            .signature_fixture(&config.trust.active()?.digest, stage, &bytes)?;
    let signature = signature
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
    Ok((status, serde_json::from_slice(&body)?))
}
pub(crate) struct BootstrapPeer {
    app: Arc<crate::api::Assembly>,
    chain: Vec<Vec<u8>>,
    directory: tempfile::TempDir,
}
pub(crate) async fn grant(
    router: &Router,
    peer: &BootstrapPeer,
    input: &Value,
) -> Result<GrantResponse> {
    grant_fault(router, peer, input, None).await
}
pub(crate) async fn grant_fault(
    _router: &Router,
    peer: &BootstrapPeer,
    input: &Value,
    fault: Option<rss_audit_postgres::PgFault>,
) -> Result<GrantResponse> {
    let routers = crate::api::from_state(
        peer.app.clone(),
        "mdm.example.test".into(),
        super::runtime::monotonic(),
    );
    let (_, router) = routers
        .listeners
        .into_iter()
        .find(|(kind, _)| *kind == crate::native::NativeListenerKind::Agent)
        .ok_or_else(|| anyhow::anyhow!("missing production Agent listener"))?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let mut owner = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(5))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    owner
        .startup()?
        .stage_task_with_token(crate::native::tls::registration(
            listener,
            router,
            peer.app.audit_store.clone(),
            case_tenant().into(),
            crate::native::NativeListenerKind::Agent,
        ));
    let result = async {
        let key = peer.directory.path().join("bootstrap.pk8");
        let mut io = super::agent_http::connect_agent_with_key(
            address,
            Some(&peer.chain),
            key.to_str().unwrap(),
        )
        .await?;
        if let Some(fault) = fault {
            // Complete production TLS admission before faulting the business transaction.
            let (status, _) =
                super::agent_http::agent_http(&mut io, "GET", "/api/v1/agent/enroll/trust", None)
                    .await?;
            ensure!(
                status == 401,
                "bootstrap identity must not access daily Agent trust: {status}"
            );
            peer.app.audit_store.inject_next_fault(fault);
        }
        let (status, body) = super::agent_http::agent_http(
            &mut io,
            "POST",
            "/api/v1/agent/enroll/native-grants",
            Some(input.clone()),
        )
        .await?;
        Ok::<_, anyhow::Error>(GrantResponse {
            status: StatusCode::from_u16(status)?,
            body,
        })
    }
    .await;
    ensure!(owner.shutdown().join().await?.is_clean());
    result
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

pub(crate) fn windows_fields(
    commands: &[rss_mdm_windows_mdm::syncml::Command],
) -> BTreeMap<String, String> {
    use rss_mdm_windows_mdm::syncml::Command as C;
    let mut output = BTreeMap::new();
    for command in commands {
        match command {
            C::Sequence { commands, .. } | C::Atomic { commands, .. } => {
                output.extend(windows_fields(commands))
            }
            C::Add { items, .. } => {
                for item in items {
                    if let (Some(uri), Some(value)) = (&item.target, &item.data)
                        && uri.contains("/ClientCertificateInstall/SCEP/")
                    {
                        output.insert(uri.rsplit('/').next().unwrap().to_owned(), value.0.clone());
                    }
                }
            }
            _ => (),
        }
    }
    output
}
