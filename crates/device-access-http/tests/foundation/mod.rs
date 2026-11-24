//! Fresh PostgreSQL, Identity, actual provider dispatch and the production DA TLS listener.
mod accounts;
mod admission;
mod business;
mod configuration;
mod context;
mod credentials;
mod enterprise;
mod exports;
mod host;
mod installation;
mod material;
mod platform;
mod recovery;
mod reports;
mod transport;
use anyhow::{Context as _, Result};
use context::{Context, Inputs};
use rss_mdm_install_support::StorageProfile;
use rss_mdm_registration_service as registration;
use std::{sync::Arc, time::Duration};
use uuid::Uuid;
const DA: StorageProfile = StorageProfile::Da;
fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

#[tokio::test]
#[ignore = "T2: standalone DA owner installation, real TLS/PKI and rolling configuration trust"]
async fn independent_registration_and_rolling_configuration_trust() -> Result<()> {
    use rss_mdm_agent_wire::{
        da, enroll, pki,
        task_trust::{Acknowledgement, KeyState},
    };
    use rss_mdm_task_trust::{Use, service::Change};
    let browser = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let protocol = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let browser_origin = format!("https://localhost:{}", browser.local_addr()?.port());
    let device_origin = format!("https://localhost:{}", protocol.local_addr()?.port());
    let c = Context::open(browser_origin).await?;
    admission::verify_and_reject_drift(&c).await?;
    let material = material::Material::new(&c).await?;
    let registration = material.assemble(&c, &device_origin).await?;
    let (installed_host, stop, running) = Box::pin(host::verify(
        &c,
        &material,
        &registration,
        browser,
        protocol,
    ))
    .await?;
    let token = material::administrator(&c).await?;
    let proof = c
        .sessions
        .authenticate(
            c.execution(),
            &c.authorization,
            rss_mdm_authorization_service::credential::RequestCredential::Bearer(
                rss_identity_core::session::BearerSecret::parse(token.clone())?,
            ),
            rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                std::time::Duration::from_secs(10),
            ),
        )
        .await?;
    let audit = || {
        rss_mdm_audit_integration::RequestAudit::new(
            rss_mdm_audit_integration::Origin::Request,
            DA,
            c.execution(),
            "da_test",
            rss_mdm_audit_integration::AuditIntent::Management,
        )
    };
    let empty = Arc::new(rss_mdm_task_trust::Signing::new(
        DA,
        Use::DaConfiguration,
        material.protection.clone(),
    )?);
    let trust = Arc::new(rss_mdm_task_trust::Service::for_configurations(
        empty,
        material.protection.clone(),
        c.access_audit.clone(),
    )?);
    let request_audit = audit();
    let first = trust
        .change_task_trust(
            &proof,
            &request_audit,
            Uuid::new_v4(),
            &Change::Prepare {
                expected_revision: 0,
            },
        )
        .await?;
    request_audit.finalize(None);
    let old_key = first
        .keys
        .iter()
        .find(|v| v.state == KeyState::Active)
        .unwrap()
        .id
        .clone();
    let device_base = format!("{device_origin}/api/v1/da");
    let base = device_base.as_str();
    transport::bounded_connections(&material, base, c.tenant).await?;
    let client = material.client(None)?;
    let management = c.management_base();
    let address = base
        .trim_start_matches("https://")
        .split('/')
        .next()
        .unwrap();
    let stalled = tokio::net::TcpStream::connect(address).await?;
    let ping = tokio::time::timeout(
        Duration::from_secs(2),
        client
            .get(format!("{base}/pki/trust?tenantId={}", c.tenant))
            .send(),
    )
    .await??;
    assert!(ping.status().is_success());
    drop(stalled);
    let grant_request = da::GrantRequest {
        operation_id: Uuid::new_v4(),
        secret: rss_mdm_agent_wire::runtime::Secret::parse(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaA",
        )?,
        csr: material.csr(1)?,
        expires_in_seconds: 3600,
    };
    let grant_call = || {
        client
            .post(format!("{management}/grants"))
            .bearer_auth(&token)
            .json(&grant_request)
            .send()
    };
    let (first, retry) = tokio::join!(grant_call(), grant_call());
    let grant: da::Grant = material::success(first?).await?;
    let retried: da::Grant = material::success(retry?).await?;
    assert_eq!(
        serde_json::to_value(&grant)?,
        serde_json::to_value(retried)?
    );
    let mut conflicting_grant = serde_json::to_value(&grant_request)?;
    conflicting_grant["expiresInSeconds"] = serde_json::json!(1800);
    assert_eq!(
        client
            .post(format!("{management}/grants"))
            .bearer_auth(&token)
            .json(&conflicting_grant)
            .send()
            .await?
            .status(),
        409
    );
    let issue = da::CertificateRequest {
        operation_id: Uuid::new_v4(),
        grant_id: grant.grant_id,
        secret: grant_request.secret.clone(),
        csr: grant_request.csr.clone(),
    };
    let candidate: enroll::Candidate = material::success(
        client
            .post(format!("{base}/certificates"))
            .json(&issue)
            .send()
            .await?,
    )
    .await?;
    // Identical CA material cannot confer authority in another installation or tenant.
    {
        use base64::{Engine, engine::general_purpose::STANDARD};
        use tokio_rustls::rustls::pki_types::CertificateDer;
        let chain = candidate
            .certificate_chain
            .iter()
            .map(|value| STANDARD.decode(value).map(CertificateDer::from))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        for change_instance in [true, false] {
            let mut other = registration.trust(c.execution()).await?.trust.public()?;
            if change_instance {
                other.service_id = Uuid::new_v4();
            } else {
                other.tenant = Uuid::new_v4();
            }
            let other =
                rss_mdm_device_trust::DeviceTrust::new(other, pki::Purpose::DaDevice, now())?;
            assert!(other.verify(&chain, now()).is_err());
        }
    }
    let replay_call = || {
        client
            .post(format!("{base}/certificates"))
            .json(&issue)
            .send()
    };
    let (left, right) = tokio::join!(replay_call(), replay_call());
    for response in [left?, right?] {
        let replay: enroll::Candidate = material::success(response).await?;
        assert_eq!(candidate.issuance_id, replay.issuance_id);
        assert_eq!(candidate.certificate_chain, replay.certificate_chain);
    }
    let mut conflicting_issue = serde_json::to_value(&issue)?;
    conflicting_issue["csr"] = serde_json::json!(material.csr(2)?);
    assert_eq!(
        client
            .post(format!("{base}/certificates"))
            .json(&conflicting_issue)
            .send()
            .await?
            .status(),
        409
    );
    assert_eq!(material.issued_count()?, 1);
    let peer = material.client(Some((&candidate, 1)))?;
    let activate = enroll::ActivationRequest {
        wire_version: 1,
        operation_id: Uuid::new_v4(),
        issuance_id: candidate.issuance_id,
    };
    assert_eq!(
        client
            .post(format!("{base}/activate"))
            .json(&activate)
            .send()
            .await?
            .status(),
        401
    );
    let activate_call = || peer.post(format!("{base}/activate")).json(&activate).send();
    let (first, retry) = tokio::join!(activate_call(), activate_call());
    let receipt: da::Registration = material::success(first?).await?;
    let retried: da::Registration = material::success(retry?).await?;
    assert_eq!(
        serde_json::to_value(&receipt)?,
        serde_json::to_value(retried)?
    );
    assert_eq!(receipt.device, grant.device);
    let counts:(i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM rss_da.devices WHERE purpose = 'da_device' AND channel IS NULL), (SELECT count(*) FROM rss_da.report_sources), (SELECT count(*) FROM rss_da.requests)").fetch_one(&c.operator).await?;
    assert_eq!(counts, (1, 0, 0));
    assert!(
        sqlx::query_scalar::<_, Option<String>>("SELECT to_regclass('rss_da.agent_tasks')::text")
            .fetch_one(&c.operator)
            .await?
            .is_none()
    );
    let public: pki::Trust = material::success(
        peer.get(format!("{base}/pki/trust?tenantId={}", c.tenant))
            .send()
            .await?,
    )
    .await?;
    assert_eq!(public.purpose, pki::Purpose::DaDevice);
    let trust_public: da::ConfigurationTrust = material::success(
        peer.get(format!("{base}/configuration-trust"))
            .send()
            .await?,
    )
    .await?;
    let publication = rss_mdm_agent_wire::da::Publication {
        id: Uuid::new_v4(),
        version: Uuid::new_v4(),
        revision: 1,
        target: rss_mdm_agent_wire::da::Target::TenantDefault,
        enabled: true,
        managed_fields: vec![],
        configuration: serde_json::from_value(
            serde_json::json!({"mac":null,"windows":{"kind":"whfb"},"selfEnrollment":false,"enabled":true,"role":null}),
        )?,
    };
    let change = rss_mdm_device_access_postgres::configuration::Change {
        operation_id: Uuid::new_v4(),
        expected_revision: 0,
        publication: publication.clone(),
    };
    let (cookie, csrf) =
        credentials::login(&c, &client, Uuid::parse_str(proof.principal_id())?).await?;
    let published: rss_mdm_agent_wire::da::Publication = material::success(
        client
            .post(format!(
                "{}/api/v1/tenants/{}/device-access/configurations",
                c.browser_origin, c.tenant
            ))
            .header("origin", &c.browser_origin)
            .header("x-identity-request", "1")
            .header("x-csrf-token", &csrf)
            .header("cookie", &cookie)
            .json(&change)
            .send()
            .await?,
    )
    .await?;
    let receipt_url = format!(
        "{management}/admin/configuration-operations/{}",
        change.operation_id
    );
    let recovered: rss_mdm_agent_wire::da::Publication = material::success(
        client
            .get(receipt_url)
            .header("cookie", cookie)
            .send()
            .await?,
    )
    .await?;
    assert_eq!(
        serde_json::to_value(&recovered)?,
        serde_json::to_value(&published)?
    );
    assert_eq!(published.version, publication.version);
    let export = da::Export {
        operation_id: Uuid::new_v4(),
        policy: publication.id,
        version: publication.version,
        delivery: da::DeliveryPermission::Da,
        lifetime_seconds: 600,
    };
    configuration::concurrent_export(&c, &client, &token, &proof, &export).await?;
    let signed: da::SignedConfiguration = material::success(
        client
            .post(format!("{management}/configurations"))
            .bearer_auth(&token)
            .json(&export)
            .send()
            .await?,
    )
    .await?;
    assert_eq!(signed.key_id, old_key);
    let mut foreign = export.clone();
    foreign.operation_id = Uuid::new_v4();
    foreign.policy = Uuid::new_v4();
    assert_eq!(
        client
            .post(format!("{management}/configurations"))
            .bearer_auth(&token)
            .json(&foreign)
            .send()
            .await?
            .status(),
        403
    );
    foreign.policy = export.policy;
    foreign.version = Uuid::new_v4();
    assert_eq!(
        client
            .post(format!("{management}/configurations"))
            .bearer_auth(&token)
            .json(&foreign)
            .send()
            .await?
            .status(),
        409
    );
    assert_eq!(
        client
            .post(format!("{management}/configurations"))
            .header("origin", &c.browser_origin)
            .header("x-identity-request", "1")
            .json(&export)
            .send()
            .await?
            .status(),
        401
    );
    material::verify(&signed, &trust_public)?;
    let limited = material::device_administrator(&c, &receipt.device).await?;
    let mut scoped = export.clone();
    scoped.operation_id = Uuid::new_v4();
    assert_eq!(
        client
            .post(format!("{management}/configurations"))
            .bearer_auth(&limited)
            .json(&scoped)
            .send()
            .await?
            .status(),
        403
    );
    // The rejected cross-scope write must not poison the existing publication head.
    let mut next_revision = export.clone();
    next_revision.operation_id = Uuid::new_v4();
    // Multiple immutable exports reference the same publication; no independent configuration counter.
    let _: da::SignedConfiguration = material::success(
        client
            .post(format!("{management}/configurations"))
            .bearer_auth(&token)
            .json(&next_revision)
            .send()
            .await?,
    )
    .await?;

    assert_eq!(
        peer.get(format!("{base}/configurations/{}", export.operation_id))
            .send()
            .await?
            .status(),
        403
    );
    // No signing key has been acknowledged yet. Every current candidate is
    // withheld, independently of the ordering of exports issued in the same second.
    let held: da::CurrentConfiguration =
        material::success(peer.get(format!("{base}/configuration")).send().await?).await?;
    assert_eq!(held.state, da::SourceState::Invalid);
    assert!(held.artifact.is_none());
    assert!(held.authorities.iter().any(|a| a.policy == publication.id));
    let ack = Acknowledgement {
        version: 1,
        operation: Uuid::new_v4(),
        device_id: receipt.device,

        revision: trust_public.revision,
        digest: trust_public.installation_digest()?,
    };
    material::empty(
        peer.post(format!("{base}/configuration-trust/acknowledgements"))
            .json(&ack)
            .send()
            .await?,
    )
    .await?;
    let fetched: da::SignedConfiguration = material::success(
        peer.get(format!("{base}/configurations/{}", export.operation_id))
            .send()
            .await?,
    )
    .await?;
    assert_eq!(fetched.signature, signed.signature);
    reports::verify(&c, &client, &peer, base, &token, &receipt, &signed).await?;
    let request_audit = audit();
    let prepared = trust
        .change_task_trust(
            &proof,
            &request_audit,
            Uuid::new_v4(),
            &Change::Prepare {
                expected_revision: 1,
            },
        )
        .await?;
    request_audit.finalize(None);
    let new_key = prepared
        .keys
        .iter()
        .find(|v| v.state == KeyState::Prepared)
        .unwrap()
        .id
        .clone();
    // No ACK for revision 2: activation succeeds while the already enrolled device is offline.
    let request_audit = audit();
    let active = trust
        .change_task_trust(
            &proof,
            &request_audit,
            Uuid::new_v4(),
            &Change::Activate {
                expected_revision: 2,
                key_id: new_key.clone(),
            },
        )
        .await?;
    request_audit.finalize(None);
    assert_eq!(active.revision, 3);
    let mut second = export.clone();
    second.operation_id = Uuid::new_v4();

    // Rotation is visible to the original running service.
    let next_signed: da::SignedConfiguration = material::success(
        client
            .post(format!("{management}/configurations"))
            .bearer_auth(&token)
            .json(&second)
            .send()
            .await?,
    )
    .await?;
    assert_eq!(next_signed.key_id, new_key);
    assert_eq!(
        peer.get(format!("{base}/configurations/{}", second.operation_id))
            .send()
            .await?
            .status(),
        403
    );
    // Current trust and recovery remain available through rotation.
    let current: da::ConfigurationTrust = material::success(
        peer.get(format!("{base}/configuration-trust"))
            .send()
            .await?,
    )
    .await?;
    let next_ack = Acknowledgement {
        operation: Uuid::new_v4(),
        revision: current.revision,
        digest: current.installation_digest()?,
        ..ack
    };
    material::empty(
        peer.post(format!("{base}/configuration-trust/acknowledgements"))
            .json(&next_ack)
            .send()
            .await?,
    )
    .await?;
    let _: da::SignedConfiguration = material::success(
        peer.get(format!("{base}/configurations/{}", second.operation_id))
            .send()
            .await?,
    )
    .await?;
    assert!(
        trust
            .change_task_trust(
                &proof,
                &audit(),
                Uuid::new_v4(),
                &Change::Retire {
                    expected_revision: 3,
                    key_id: old_key.clone()
                }
            )
            .await
            .is_err()
    );
    // A retained old-key receipt remains available after rotation.
    let old_receipt: da::SignedConfiguration = material::success(
        peer.get(format!("{base}/configurations/{}", export.operation_id))
            .send()
            .await?,
    )
    .await?;
    assert_eq!(old_receipt.signature, signed.signature);
    assert_eq!(
        peer.get(format!("{base}/configurations/{}", Uuid::new_v4()))
            .send()
            .await?
            .status(),
        403
    );
    // Durable export retention survives process reload, even after every live consumer ACKs.
    let retained:i64=sqlx::query_scalar("SELECT max_verify_until FROM rss_da.signing_keys WHERE tenant_id=$1::uuid AND usage='da_configuration' AND key_id=$2").bind(c.tenant.to_string()).bind(old_key).fetch_one(&c.operator).await?;
    assert!(retained >= signed.decode()?.expires_at);
    // Verify configuration trust before the business proof changes current policy selection.
    Box::pin(business::verify(&c, &material, &receipt, &client, base))
        .await
        .context("DA business owner proof")?;
    let (survivor, survivor_peer) = unknown_recovery(
        &c,
        &material,
        &client,
        base,
        &token,
        export.operation_id,
        &receipt.device,
    )
    .await?;

    let (account_registration, account_peer, account_policy) = Box::pin(accounts::verify(
        &c,
        &material,
        &client,
        base,
        &token,
        &survivor_peer,
    ))
    .await
    .context("independent Windows account protocol")?;
    let pending_create = Box::pin(accounts::interrupted_create(
        &c,
        &client,
        &account_registration,
        &account_peer,
        base,
        account_policy,
    ))
    .await
    .context("recover the original expired create permit")?;
    Box::pin(accounts::stopped_create(
        &c,
        &client,
        &account_registration,
        &account_peer,
        base,
        pending_create,
    ))
    .await
    .context("reconcile the stopped native create after renewal")?;
    let pending = Box::pin(credentials::verify(
        &c,
        &material,
        &client,
        &survivor_peer,
        base,
        &survivor,
    ))
    .await
    .context("targeted RSS Login recovery")?;
    let (renewed_receipt, renewed_peer) = activate_grant(
        &material,
        &client,
        peer.post(format!("{base}/renewal-grants")),
        base,
        2,
    )
    .await?;
    let (current_survivor, current_peer) = activate_grant(
        &material,
        &client,
        survivor_peer.post(format!("{base}/renewal-grants")),
        base,
        3,
    )
    .await?;
    assert_eq!(current_survivor.device, survivor.device);
    assert_ne!(current_survivor.credential, survivor.credential);
    assert_eq!(renewed_receipt.device, receipt.device);
    assert_ne!(renewed_receipt.credential, receipt.credential);
    assert_eq!(
        peer.get(format!("{base}/configuration-trust"))
            .send()
            .await?
            .status(),
        401
    );

    let platform_session = Box::pin(platform::verify(
        &c,
        &material,
        &renewed_receipt,
        &renewed_peer,
        &client,
        base,
    ))
    .await
    .context("DA platform owner proof")?;
    c.authority
        .inspect_session(
            c.execution(),
            rss_identity_core::session::SessionSecret::parse(platform_session.expose().into())?,
            platform::deadline(),
        )
        .await
        .context("platform session is active before registration revocation")?;
    let revoke_id = Uuid::new_v4();
    let revoke = || {
        client
            .post(format!(
                "{management}/devices/{}/registration/revoke",
                receipt.device
            ))
            .bearer_auth(&token)
            .json(&serde_json::json!({"operationId":revoke_id}))
            .send()
    };
    let revocation: da::RevocationReceipt = material::success(revoke().await?).await?;
    assert_eq!(
        revocation,
        da::RevocationReceipt {
            operation_id: revoke_id,
            service_id: renewed_receipt.service_id,
            tenant: renewed_receipt.tenant,
            device: renewed_receipt.device,
            credential: renewed_receipt.credential,
        }
    );
    let replay: da::RevocationReceipt = material::success(revoke().await?).await?;
    assert_eq!(revocation, replay);
    let recovery_url = format!("{base}/registrations/revocation");
    for other in [&client, &peer, &current_peer] {
        assert_eq!(other.get(&recovery_url).send().await?.status(), 401);
    }
    assert_eq!(
        renewed_peer
            .get(format!("{base}/configuration-trust"))
            .send()
            .await?
            .status(),
        401
    );
    assert!(
        c.authority
            .inspect_session(c.execution(), platform_session, platform::deadline())
            .await
            .is_err(),
        "registration revocation invalidates the existing platform session"
    );
    assert_eq!(
        renewed_peer
            .get(format!("{base}/platform-sso/status"))
            .send()
            .await?
            .status(),
        401,
        "revoked DA registration cannot access the PSSO channel"
    );

    stop.send(())
        .map_err(|_| anyhow::anyhow!("DA host stopped early"))?;
    tokio::time::timeout(Duration::from_secs(50), running).await???;
    c.close().await;

    Box::pin(recovery::verify(
        &c.inputs,
        &material,
        installed_host,
        recovery::Expected {
            active: current_survivor,
            active_peer: current_peer,
            superseded_peer: survivor_peer,
            revoked: renewed_receipt,
            revocation,
            revoked_peer: renewed_peer,
            pending,
            device_base: base.to_string(),
            management_origin: c.browser_origin.clone(),
        },
    ))
    .await
    .context("DA cold recovery proof")?;
    drop(material);
    Ok(())
}

async fn unknown_recovery(
    c: &Context,
    m: &material::Material,
    client: &reqwest::Client,
    base: &str,
    token: &str,
    old_export: Uuid,
    old_device: &rss_mdm_agent_wire::DeviceId,
) -> Result<(rss_mdm_agent_wire::da::Registration, reqwest::Client)> {
    let management = c.management_base();
    use base64::{Engine, engine::general_purpose::STANDARD};
    use rss_mdm_agent_wire::{da, enroll};
    let grant_request = da::GrantRequest {
        operation_id: Uuid::new_v4(),
        secret: rss_mdm_agent_wire::runtime::Secret::parse(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbA",
        )?,
        // Reusing the same key still creates a distinct product identity.
        csr: m.csr(1)?,
        expires_in_seconds: 3600,
    };
    let grant: da::Grant = material::success(
        client
            .post(format!("{management}/grants"))
            .bearer_auth(token)
            .json(&grant_request)
            .send()
            .await?,
    )
    .await?;
    let issue = da::CertificateRequest {
        operation_id: Uuid::new_v4(),
        grant_id: grant.grant_id,
        secret: grant_request.secret.clone(),
        csr: grant_request.csr,
    };
    let previous = m.issued_count()?;
    std::fs::write(m.directory.join("drop-next"), b"drop after signing")?;
    let response = client
        .post(format!("{base}/certificates"))
        .json(&issue)
        .send()
        .await?;
    assert_eq!(response.status(), 503);
    let error: enroll::ErrorBody = response.json().await?;
    assert_eq!(error.code, enroll::ErrorCode::IssuanceUnknown);
    let id = error.issuance_id.unwrap();
    let retry = client
        .post(format!("{base}/certificates"))
        .json(&issue)
        .send()
        .await?;
    assert_eq!(retry.status(), 503);
    assert_eq!(m.issued_count()?, previous + 1);
    let status: da::Progress = material::success(
        client
            .post(format!("{base}/registrations/status"))
            .json(&enroll::StatusRequest {
                wire_version: 1,
                grant_id: grant.grant_id,
                operation_id: grant.operation_id,
                secret: issue.secret.clone(),
            })
            .send()
            .await?,
    )
    .await?;
    assert!(status.issuance_unknown);
    assert_eq!(status.issuance_id, Some(id));
    let mut chain = Vec::new();
    for file in [
        m.directory.join(id.to_string()).join("leaf.pem"),
        m.directory.join("task-trust-ca/ca.pem"),
    ] {
        let output = tokio::process::Command::new("openssl")
            .args(["x509", "-in"])
            .arg(file)
            .args(["-outform", "DER"])
            .output()
            .await?;
        anyhow::ensure!(output.status.success(), "original CA result");
        chain.push(STANDARD.encode(output.stdout));
    }
    let recovery = enroll::RecoverIssuance {
        wire_version: 1,
        operation_id: Uuid::new_v4(),
        certificate_chain: chain,
    };
    let recovered: enroll::Candidate = material::success(
        client
            .post(format!("{management}/certificates/{id}/recover"))
            .bearer_auth(token)
            .json(&recovery)
            .send()
            .await?,
    )
    .await?;
    assert_eq!(recovered.issuance_id, id);
    let replay: enroll::Candidate = material::success(
        client
            .post(format!("{management}/certificates/{id}/recover"))
            .bearer_auth(token)
            .json(&recovery)
            .send()
            .await?,
    )
    .await?;
    assert_eq!(replay.certificate_chain, recovered.certificate_chain);
    assert_eq!(m.issued_count()?, previous + 1);
    let peer = m.client(Some((&recovered, 1)))?;
    let registration: da::Registration = material::success(
        peer.post(format!("{base}/activate"))
            .json(&enroll::ActivationRequest {
                wire_version: 1,
                operation_id: Uuid::new_v4(),
                issuance_id: id,
            })
            .send()
            .await?,
    )
    .await?;
    assert_eq!(registration.device, grant.device);
    assert_ne!(registration.device, *old_device);
    let history: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT
          (SELECT count(*) FROM rss_da.report_history WHERE tenant_id=$1 AND device=$2),
          (SELECT count(*) FROM rss_da.report_history WHERE tenant_id=$1 AND device=$3),
          (SELECT count(*) FROM rss_da.policies WHERE tenant_id=$1 AND (definition#>>'{target,device}')::uuid=$2),
          (SELECT count(*) FROM rss_da.policies WHERE tenant_id=$1 AND (definition#>>'{target,device}')::uuid=$3)")
        .bind(registration.tenant).bind(old_device.into_uuid()).bind(registration.device.into_uuid())
        .fetch_one(&c.operator).await?;
    assert!(
        history.0 > 0 && history.2 > 0,
        "original history and direct policy remain"
    );
    assert_eq!(
        (history.1, history.3),
        (0, 0),
        "new enrollment inherits neither history nor direct policy"
    );
    let trust: da::ConfigurationTrust = material::success(
        peer.get(format!("{base}/configuration-trust"))
            .send()
            .await?,
    )
    .await?;
    material::empty(
        peer.post(format!("{base}/configuration-trust/acknowledgements"))
            .json(&rss_mdm_agent_wire::task_trust::Acknowledgement {
                version: 1,
                operation: Uuid::new_v4(),
                device_id: registration.device,

                revision: trust.revision,
                digest: trust.installation_digest()?,
            })
            .send()
            .await?,
    )
    .await?;
    // The business proof replaced the tenant default. A new identity cannot fetch an
    // earlier export as though it retained the old device's selected publication.
    assert_eq!(
        peer.get(format!("{base}/configurations/{old_export}"))
            .send()
            .await?
            .status(),
        409
    );
    let mut tx = c.access.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(Uuid::new_v4().to_string())
        .execute(&mut *tx)
        .await?;
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM rss_da.devices")
            .fetch_one(&mut *tx)
            .await?,
        0
    );
    tx.rollback().await?;
    Ok((registration, peer))
}

use rss_mdm_agent_wire::{da, enroll};
async fn activate_grant(
    material: &material::Material,
    client: &reqwest::Client,
    request: reqwest::RequestBuilder,
    base: &str,
    key: u8,
) -> Result<(da::Registration, reqwest::Client)> {
    let input = da::GrantRequest {
        operation_id: Uuid::new_v4(),
        csr: material.csr(key)?,
        expires_in_seconds: 600,
        secret: rss_mdm_agent_wire::runtime::Secret::parse(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaA",
        )?,
    };
    let grant: da::Grant = material::success(request.json(&input).send().await?).await?;
    let candidate: enroll::Candidate = material::success(
        client
            .post(format!("{base}/certificates"))
            .json(&da::CertificateRequest {
                operation_id: Uuid::new_v4(),
                grant_id: grant.grant_id,
                secret: input.secret,
                csr: input.csr,
            })
            .send()
            .await?,
    )
    .await?;
    let peer = material.client(Some((&candidate, key)))?;
    let registration: da::Registration = material::success(
        peer.post(format!("{base}/activate"))
            .json(&enroll::ActivationRequest {
                wire_version: 1,
                operation_id: Uuid::new_v4(),
                issuance_id: candidate.issuance_id,
            })
            .send()
            .await?,
    )
    .await?;
    Ok((registration, peer))
}
