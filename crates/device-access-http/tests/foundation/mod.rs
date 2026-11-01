//! Fresh PostgreSQL, Identity, actual provider dispatch and the production DA TLS listener.
mod admission;
mod context;
mod installation;
mod material;
use anyhow::Result;
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
    let c = Context::open().await?;
    admission::verify_and_reject_drift(&c).await?;
    let material = material::Material::new(&c).await?;
    let registration = material.assemble(&c).await?;
    let token = material::administrator(&c).await?;
    let proof = c
        .sessions
        .authenticate(
            &c.authorization,
            rss_mdm_authorization_service::credential::RequestCredential::Bearer(
                rss_identity_core::session::BearerSecret::parse(token.clone())?,
            ),
        )
        .await?;
    let audit = || {
        rss_mdm_audit_integration::RequestAudit::new(
            DA,
            c.tenant.to_string(),
            "da_test",
            rss_mdm_audit_integration::AuditIntent::Management,
        )
    };
    let empty = Arc::new(rss_mdm_task_trust::Signing::new(
        DA,
        Use::DaConfiguration,
        c.tenant,
        None,
    )?);
    let trust = Arc::new(rss_mdm_task_trust::Service::for_configurations(
        c.tenant,
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
    let loaded = material::load(&c, &material, first.revision).await?;
    let state = material::state(&c, registration.clone(), loaded.clone(), &material)?;
    let server = material.listen(state).await?;
    let client = material.client(None)?;
    let base = &server.origin;
    let address = base
        .trim_start_matches("https://")
        .split('/')
        .next()
        .unwrap();
    let stalled = tokio::net::TcpStream::connect(address).await?;
    let ping = tokio::time::timeout(
        Duration::from_secs(2),
        client.get(format!("{base}/pki/trust")).send(),
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
    let response = client
        .post(format!("{base}/grants"))
        .bearer_auth(&token)
        .json(&grant_request)
        .send()
        .await?;
    let grant: da::Grant = material::success(response).await?;
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
            let mut other = registration.trust().trust.public()?;
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
    let replay: enroll::Candidate = material::success(
        client
            .post(format!("{base}/certificates"))
            .json(&issue)
            .send()
            .await?,
    )
    .await?;
    assert_eq!(candidate.issuance_id, replay.issuance_id);
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
    let receipt: da::Registration = material::success(
        peer.post(format!("{base}/activate"))
            .json(&activate)
            .send()
            .await?,
    )
    .await?;
    assert_eq!(receipt.device, grant.device);
    let counts:(i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM rss_da.registrations WHERE purpose='da_device' AND channel IS NULL),(SELECT count(*) FROM rss_da.report_sources),(SELECT count(*) FROM rss_da.requests)").fetch_one(&c.operator).await?;
    assert_eq!(counts, (1, 0, 0));
    assert!(
        sqlx::query_scalar::<_, Option<String>>("SELECT to_regclass('rss_da.agent_tasks')::text")
            .fetch_one(&c.operator)
            .await?
            .is_none()
    );
    let public: pki::Trust =
        material::success(peer.get(format!("{base}/pki/trust")).send().await?).await?;
    assert_eq!(public.purpose, pki::Purpose::DaDevice);
    let trust_public: da::ConfigurationTrust = material::success(
        peer.get(format!("{base}/configuration-trust"))
            .send()
            .await?,
    )
    .await?;
    let export = da::Export {
        operation_id: Uuid::new_v4(),
        configuration: da::Configuration {
            service_id: receipt.service_id,
            tenant: receipt.tenant,
            id: Uuid::new_v4(),
            revision: 1,
            epoch: 1,
            audience: da::Audience::Tenant,
            delivery: da::DeliveryPermission::Da,
            issued_at: now(),
            expires_at: now() + 600,
            content: serde_json::from_value(
                serde_json::json!({"mac":null,"windows":{"kind":"whfb"},"selfEnrollment":false,"enabled":true,"role":null}),
            )?,
        },
    };
    let signed: da::SignedConfiguration = material::success(
        client
            .post(format!("{base}/configurations"))
            .bearer_auth(&token)
            .json(&export)
            .send()
            .await?,
    )
    .await?;
    assert_eq!(signed.key_id, old_key);
    let mut foreign = export.clone();
    foreign.operation_id = Uuid::new_v4();
    foreign.configuration.id = Uuid::new_v4();
    foreign.configuration.service_id = Uuid::new_v4();
    assert_eq!(
        client
            .post(format!("{base}/configurations"))
            .bearer_auth(&token)
            .json(&foreign)
            .send()
            .await?
            .status(),
        400
    );
    foreign.configuration.service_id = export.configuration.service_id;
    foreign.configuration.tenant = Uuid::new_v4();
    assert_eq!(
        client
            .post(format!("{base}/configurations"))
            .bearer_auth(&token)
            .json(&foreign)
            .send()
            .await?
            .status(),
        400
    );
    assert_eq!(
        client
            .post(format!("{base}/configurations"))
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
    scoped.configuration.revision = i64::MAX as u64;
    scoped.configuration.epoch = i64::MAX as u64;
    scoped.configuration.audience = da::Audience::Device {
        device: receipt.device.clone(),
        registration: receipt.registration,
        generation: receipt.generation,
    };
    assert_eq!(
        client
            .post(format!("{base}/configurations"))
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
    next_revision.configuration.revision = 2;
    let _: da::SignedConfiguration = material::success(
        client
            .post(format!("{base}/configurations"))
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
    let ack = Acknowledgement {
        version: 1,
        operation: Uuid::new_v4(),
        registration: receipt.registration,
        generation: receipt.generation,
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
    second.configuration.id = Uuid::new_v4();
    // A process pinned to the old signer loses signing authority immediately.
    assert_eq!(
        client
            .post(format!("{base}/configurations"))
            .bearer_auth(&token)
            .json(&second)
            .send()
            .await?
            .status(),
        409
    );
    let next = material::load(&c, &material, active.revision).await?;
    let next_server = material
        .listen(material::state(&c, registration.clone(), next, &material)?)
        .await?;
    let base2 = &next_server.origin;
    let next_signed: da::SignedConfiguration = material::success(
        client
            .post(format!("{base2}/configurations"))
            .bearer_auth(&token)
            .json(&second)
            .send()
            .await?,
    )
    .await?;
    assert_eq!(next_signed.key_id, new_key);
    assert_eq!(
        peer.get(format!("{base2}/configurations/{}", second.operation_id))
            .send()
            .await?
            .status(),
        403
    );
    // Current trust and recovery remain available while signing is gated.
    let current: da::ConfigurationTrust = material::success(
        peer.get(format!("{base2}/configuration-trust"))
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
        peer.post(format!("{base2}/configuration-trust/acknowledgements"))
            .json(&next_ack)
            .send()
            .await?,
    )
    .await?;
    let _: da::SignedConfiguration = material::success(
        peer.get(format!("{base2}/configurations/{}", second.operation_id))
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
        peer.get(format!("{base2}/configurations/{}", export.operation_id))
            .send()
            .await?,
    )
    .await?;
    assert_eq!(old_receipt.signature, signed.signature);
    assert_eq!(
        peer.get(format!("{base2}/configurations/{}", Uuid::new_v4()))
            .send()
            .await?
            .status(),
        403
    );
    // Durable export retention survives process reload, even after every live consumer ACKs.
    let retained:i64=sqlx::query_scalar("SELECT max_verify_until FROM rss_da.signing_keys WHERE tenant_id=$1::uuid AND usage='da_configuration' AND key_id=$2").bind(c.tenant.to_string()).bind(old_key).fetch_one(&c.operator).await?;
    assert_eq!(retained, export.configuration.expires_at);
    let renewal = da::GrantRequest {
        operation_id: Uuid::new_v4(),
        csr: material.csr(2)?,
        ..grant_request
    };
    let renewed_grant: da::Grant = material::success(
        peer.post(format!("{base2}/renewal-grants"))
            .json(&renewal)
            .send()
            .await?,
    )
    .await?;
    let renewed: enroll::Candidate = material::success(
        client
            .post(format!("{base2}/certificates"))
            .json(&da::CertificateRequest {
                operation_id: Uuid::new_v4(),
                grant_id: renewed_grant.grant_id,
                secret: renewal.secret,
                csr: renewal.csr,
            })
            .send()
            .await?,
    )
    .await?;
    let renewed_peer = material.client(Some((&renewed, 2)))?;
    let renewed_receipt: da::Registration = material::success(
        renewed_peer
            .post(format!("{base2}/activate"))
            .json(&enroll::ActivationRequest {
                wire_version: 1,
                operation_id: Uuid::new_v4(),
                issuance_id: renewed.issuance_id,
            })
            .send()
            .await?,
    )
    .await?;
    assert_eq!(renewed_receipt.registration, receipt.registration);
    assert_eq!(renewed_receipt.generation, receipt.generation);
    assert_ne!(renewed_receipt.credential, receipt.credential);
    assert_eq!(
        peer.get(format!("{base2}/configuration-trust"))
            .send()
            .await?
            .status(),
        401
    );
    material::empty(
        client
            .post(format!(
                "{base2}/registrations/{}/revoke",
                receipt.registration
            ))
            .bearer_auth(&token)
            .json(&serde_json::json!({"operationId":Uuid::new_v4()}))
            .send()
            .await?,
    )
    .await?;
    assert_eq!(
        renewed_peer
            .get(format!("{base2}/configuration-trust"))
            .send()
            .await?
            .status(),
        401
    );
    unknown_recovery(&c, &material, &client, base2, &token, export.operation_id).await?;
    drop(next_server);
    drop(server);
    drop(material);
    c.close().await;
    Ok(())
}

async fn unknown_recovery(
    c: &Context,
    m: &material::Material,
    client: &reqwest::Client,
    base: &str,
    token: &str,
    old_export: Uuid,
) -> Result<()> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use rss_mdm_agent_wire::{da, enroll};
    let grant_request = da::GrantRequest {
        operation_id: Uuid::new_v4(),
        secret: rss_mdm_agent_wire::runtime::Secret::parse(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbA",
        )?,
        csr: m.csr(3)?,
        expires_in_seconds: 3600,
    };
    let grant: da::Grant = material::success(
        client
            .post(format!("{base}/grants"))
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
            .post(format!("{base}/status"))
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
            .post(format!("{base}/certificates/{id}/recover"))
            .bearer_auth(token)
            .json(&recovery)
            .send()
            .await?,
    )
    .await?;
    assert_eq!(recovered.issuance_id, id);
    let replay: enroll::Candidate = material::success(
        client
            .post(format!("{base}/certificates/{id}/recover"))
            .bearer_auth(token)
            .json(&recovery)
            .send()
            .await?,
    )
    .await?;
    assert_eq!(replay.certificate_chain, recovered.certificate_chain);
    assert_eq!(m.issued_count()?, previous + 1);
    let peer = m.client(Some((&recovered, 3)))?;
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
                registration: registration.registration,
                generation: registration.generation,
                revision: trust.revision,
                digest: trust.installation_digest()?,
            })
            .send()
            .await?,
    )
    .await?;
    // This newly enrolled device has never acknowledged the old key as Prepared/Active.
    let _: da::SignedConfiguration = material::success(
        peer.get(format!("{base}/configurations/{old_export}"))
            .send()
            .await?,
    )
    .await?;
    let mut tx = c.access.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(Uuid::new_v4().to_string())
        .execute(&mut *tx)
        .await?;
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM rss_da.registrations")
            .fetch_one(&mut *tx)
            .await?,
        0
    );
    tx.rollback().await?;
    Ok(())
}
