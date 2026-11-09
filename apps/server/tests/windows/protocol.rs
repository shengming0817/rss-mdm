//! Real TLS, HTTP adapter and persisted SyncML package recovery with the real business participant.
#[path = "fixture.rs"]
mod fixture;
mod identity_cases;
use crate::{
    authority_t2_support::Context, command_runtime_t2_support as command,
    native_identity_t2_support as identity,
};
use anyhow::Result;
use axum::{
    extract::{ConnectInfo, Request, State},
    middleware::Next,
    response::Response,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use fixture::Fixture;
use rss_mdm_windows_mdm::{CodecLimits, Secret, syncml as s};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        self,
        pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    },
};
#[derive(Clone)]
struct Peer {
    address: SocketAddr,
    certificate: Option<rss_mdm_certificate::ClientCertificateEvidence>,
}
impl std::fmt::Debug for Peer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Peer")
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}
struct Listener {
    tcp: tokio::net::TcpListener,
    tls: TlsAcceptor,
}
impl axum::serve::Listener for Listener {
    type Io = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
    type Addr = Peer;
    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let Ok((socket, address)) = self.tcp.accept().await else {
                continue;
            };
            let gateway = rss_mdm_certificate::GatewayConnection::from_stream(
                &socket,
                "127.0.0.1".parse().unwrap(),
            )
            .unwrap();
            let Ok(stream) = self.tls.accept(socket).await else {
                continue;
            };
            use x509_cert::der::{Decode, EncodePem};
            let der = &stream.get_ref().1.peer_certificates().unwrap()[0];
            let pem = x509_cert::Certificate::from_der(der)
                .unwrap()
                .to_pem(x509_cert::der::pem::LineEnding::LF)
                .unwrap();
            let certificate = gateway.client_certificate(&pem).unwrap();
            return (
                stream,
                Peer {
                    address,
                    certificate: Some(certificate),
                },
            );
        }
    }
    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(Peer {
            address: self.tcp.local_addr()?,
            certificate: None,
        })
    }
}
impl<'a> axum::extract::connect_info::Connected<axum::serve::IncomingStream<'a, Listener>>
    for Peer
{
    fn connect_info(stream: axum::serve::IncomingStream<'a, Listener>) -> Self {
        stream.remote_addr().clone()
    }
}
async fn attest(
    State(admission): State<Arc<crate::native::admission::Admission>>,
    ConnectInfo(peer): ConnectInfo<Peer>,
    mut request: Request,
    next: Next,
) -> Response {
    request
        .extensions_mut()
        .insert(peer.certificate.expect("actual TLS handshake"));
    request.extensions_mut().insert(
        admission
            .gate(peer.address.ip())
            .expect("isolated transport budget"),
    );
    next.run(request).await
}
struct Host {
    address: SocketAddr,
    stop: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
    assembly: Fixture,
    lifecycle: rss_runtime::ShutdownStack,
    control: rss_runtime::AdmissionControl,
}
impl Host {
    async fn close(self) -> Result<()> {
        self.control.close();
        let mut drain = self.lifecycle.shutdown();
        anyhow::ensure!(
            drain.wait().await.as_ref().is_ok_and(|r| r.is_clean()),
            "lifecycle drain"
        );
        self.stop
            .send(())
            .map_err(|_| anyhow::anyhow!("listener stopped early"))?;
        tokio::time::timeout(Duration::from_secs(15), self.task).await???;
        anyhow::ensure!(
            tokio::net::TcpStream::connect(self.address).await.is_err(),
            "listener must close"
        );
        Fixture::close(self.assembly).await
    }
}
#[allow(
    clippy::disallowed_methods,
    reason = "the real host monotonic clock is part of this fixture"
)]
async fn host(
    c: &Context,
    n: &identity::Native,
    w: Arc<rss_mdm_windows_channel::Windows>,
) -> Result<Host> {
    let a = Fixture::open(c, false).await?;
    let monotonic = Arc::new(crate::Monotonic(std::time::Instant::now));
    let audit = Arc::new(
        c.audit
            .on_runtime(
                a.resources.storage.runtime.clone(),
                c.tenant,
                &rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5))
                    .control(),
            )
            .await?,
    );
    let requests = Arc::new(tokio::sync::Semaphore::new(16));
    let state = Arc::new(rss_mdm_windows_channel::HttpState {
        query_cursor: rss_mdm_query::cursor::CursorCodec::new(&[7; 32])?,
        protection: a.resources.protection.clone(),
        mount: rss_mdm_registration_service::device::ChannelMount::new(
            rss_mdm_install_support::StorageProfile::Mdm,
            c.tenant,
            rss_mdm_inventory::ReportSource::MdmWindows,
            rss_mdm_registration_service::Purpose::Primary,
        ),
        audit_store: c.audit.clone(),
        access: c.database.windows_store(),
        clock: Arc::new(identity::Clock),
        delivery: Arc::new(rss_mdm_windows_channel::management::exchange::Delivery {
            runtime: a.resources.storage.runtime.clone(),
            tenant: c.tenant,
            audit,
            protection: a.resources.protection.clone(),
            business: Arc::new(crate::assembly::windows_business::WindowsBusiness(
                a.service.clone(),
                a.configuration.clone(),
                a.collections.clone(),
                a.software.service.clone(),
                a.registration.native.clone(),
            )),
        }),
        enrollment_authority: a.registration.enrollment.clone(),
        departure: Arc::new(crate::assembly::windows_business::WindowsBusiness(
            a.service.clone(),
            a.configuration.clone(),
            a.collections.clone(),
            a.software.service.clone(),
            a.registration.native.clone(),
        )),
        credentials: Arc::new(crate::enrollment::credentials::Credentials::new(
            monotonic.clone(),
            32,
        )),
        devices: Arc::new(crate::device::DeviceService::new(
            c.database.registration(),
            c.tenant.to_string(),
            c.audit.clone(),
        )),
        identity: Arc::new(
            rss_mdm_authorization_service::session::SessionAuthority::new(
                c.authority.clone(),
                c.tenant,
            ),
        ),
        requests: requests.clone(),
        windows: Some(w.clone()),
    });
    let boundary = || rss_mdm_windows_channel::boundary::Envelope {
        admission: Arc::new(tokio::sync::Semaphore::new(16)),
        host: "localhost".into(),
        clock: monotonic.clone(),
        audit_store: c.audit.clone(),
        requests: requests.clone(),
        tenant: c.tenant.to_string(),
    };
    let (_, router) = rss_mdm_windows_channel::routers(state, boundary(), boundary());
    let admission = crate::native::admission::Admission::new(monotonic, requests, "windows-t2");
    let mut lifecycle = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(15))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let (control, gate) = lifecycle
        .startup()?
        .commit()
        .finish_with_admission("windows-t2", Duration::from_secs(10));
    control.open()?;
    let router = router
        .layer(axum::middleware::from_fn(
            crate::native::admission::admit_windows,
        ))
        .into_checked_axum(rss_mdm_http_contract::module::Listener::WindowsManagement)
        .layer(axum::middleware::from_fn_with_state(admission, attest))
        .layer(axum::Extension(gate));
    let cert = CertificateDer::from_pem_file(n.directory.join("server.pem"))?;
    let key = PrivateKeyDer::from_pem_file(n.directory.join("server.key"))?;
    let tls = rustls::ServerConfig::builder()
        .with_client_cert_verifier(w.ca.verifier())
        .with_single_cert(vec![cert], key)?;
    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = tcp.local_addr()?;
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        axum::serve(
            Listener {
                tcp,
                tls: TlsAcceptor::from(Arc::new(tls)),
            },
            router.into_make_service_with_connect_info::<Peer>(),
        )
        .with_graceful_shutdown(async {
            let _ = stopped.await;
        })
        .await
    });
    Ok(Host {
        address,
        stop,
        task,
        assembly: a,
        lifecycle,
        control,
    })
}
fn client(n: &identity::Native) -> Result<reqwest::Client> {
    let mut pem = std::fs::read(n.directory.join("client.pem"))?;
    pem.extend(std::fs::read(n.directory.join("client.key"))?);
    Ok(reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(reqwest::Certificate::from_der(&n.root)?)
        .identity(reqwest::Identity::from_pem(&pem)?)
        .timeout(Duration::from_secs(10))
        .build()?)
}
async fn send(client: &reqwest::Client, host: &Host, bytes: &[u8]) -> Result<Vec<u8>> {
    send_at(client, host, "/ManagementServer/MDM.svc", bytes).await
}
async fn send_at(
    client: &reqwest::Client,
    host: &Host,
    path: &str,
    bytes: &[u8],
) -> Result<Vec<u8>> {
    let r = client
        .post(format!("https://{}{path}", host.address))
        .header("host", "localhost")
        .header("content-type", "application/vnd.syncml.dm+xml")
        .header("connection", "close")
        .body(bytes.to_vec())
        .send()
        .await?;
    let status = r.status();
    let bytes = r.bytes().await?.to_vec();
    anyhow::ensure!(
        status.is_success(),
        "HTTP {status}: {}",
        String::from_utf8_lossy(&bytes)
    );
    Ok(bytes)
}
fn next(n: &identity::Native, id: u32, code: u16, final_message: bool) -> s::Message {
    s::Message {
        header: s::Header {
            session_id: 17,
            message_id: id,
            target: "https://localhost/ManagementServer/MDM.svc".into(),
            source: n.device.clone(),
            credential: None,
            meta: None,
        },
        commands: vec![s::Command::Status(s::Status {
            id: 1,
            message_ref: id - 1,
            command_ref: 0,
            command: s::CommandName::SyncHdr,
            target_refs: vec![],
            source_refs: vec![],
            code,
            items: vec![],
            challenge: None,
            credential: None,
        })],
        final_message,
    }
}
async fn windows(
    c: &Context,
    n: &identity::Native,
) -> Result<Arc<rss_mdm_windows_channel::Windows>> {
    let protection = crate::device_material_support::protection(c)?;
    let trust = rss_mdm_device_trust::DeviceTrust::new(
        n.trust.clone(),
        rss_mdm_agent_wire::pki::Purpose::Windows,
        time::OffsetDateTime::now_utc().unix_timestamp(),
    )?;
    let ca = rss_mdm_device_trust::windows::WindowsDeviceTrust::from_trust(trust)?;
    let poll = serde_json::from_value(
        serde_json::json!({"interval_for_first_set_of_retries":1,"number_of_first_retries":3,"interval_for_second_set_of_retries":5,"number_of_second_retries":3,"interval_for_remaining_scheduled_retries":15,"number_of_remaining_scheduled_retries":0,"poll_on_login":false,"all_users_poll_on_first_login":false}),
    )?;
    let configuration = rss_mdm_windows_channel::protocol_identity(
        "https://localhost",
        "https://localhost",
        "rss-t2",
        &protection,
        &poll,
    )?;
    let csr = rss_mdm_certificate::windows::Csr::verify(&n.csr)?;
    let profile = ca
        .profile(
            &csr,
            &n.device,
            time::OffsetDateTime::now_utc().unix_timestamp(),
        )?
        .encode()?;
    let aad = rss_mdm_native_protection::ProtectionContext::new(
        c.tenant,
        &n.request.to_string(),
        "windows.registration-secrets",
        1,
    )?
    .derive();
    let secrets=protection.seal_bytes(&serde_json::to_vec(&serde_json::json!({"client_password":"client-secret","server_password":"server-secret","server_nonce":vec![7u8;32]}))?,&aad)?;
    let mut tx = command::seed_transaction(c).await?;
    sqlx::query("INSERT INTO mdm_access.enrollment_intents (tenant_id, request_id, csr, profile, issuer, configuration, device, credential, epoch, secrets, signing_attempt, protocol_device) VALUES (CAST($1 AS uuid), $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)").bind(c.tenant.to_string()).bind(n.request).bind(&n.csr).bind(profile).bind(&n.root).bind(configuration).bind(n.device.clone()).bind(n.credential).bind(n.epoch).bind(secrets).bind(n.attempt).bind(&n.device).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_access.enrollment_certificates(tenant_id,request_id,certificate,server_nonce) VALUES($1::uuid,$2,$3,$4)").bind(c.tenant.to_string()).bind(n.request).bind(&n.certificate).bind(vec![7u8;32]).execute(&mut *tx).await?;
    tx.commit().await?;
    let w = Arc::new(rss_mdm_windows_channel::Windows::new(
        "https://localhost".into(),
        "https://localhost".into(),
        "rss-t2".into(),
        ca,
        Arc::new(rss_mdm_pki_service::providers::Providers::new(vec![])?),
        protection,
        poll,
    )?);
    Ok(w)
}

#[tokio::test]
#[ignore = "T2: actual TLS/HTTP and persisted unfinished SyncML package across owner restart"]
async fn unfinished_package_resumes_after_restart_and_replays_exact_bytes() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let n = identity::seed(&c, "windows").await?;
    let w = windows(&c, &n).await?;
    let h = host(&c, &n, w.clone()).await?;
    let http = client(&n)?;
    let mut first = s::decode(
        include_bytes!("../../../../crates/windows-mdm/tests/fixtures/initialization.xml"),
        &CodecLimits::default(),
    )?;
    first.header.session_id = 17;
    first.header.target = "https://localhost/ManagementServer/MDM.svc".into();
    first.header.source = n.device.clone();
    for command in &mut first.commands {
        if let s::Command::DevInfo { items, .. } = command {
            for item in items {
                if item.source.as_deref() == Some("./DevInfo/DevId") {
                    item.data = Some(Secret(n.device.clone()));
                }
            }
        }
    }
    first.header.credential = Some(s::Credential {
        meta: s::Meta {
            media_type: Some("syncml:auth-basic".into()),
            format: Some("b64".into()),
            ..Default::default()
        },
        data: Secret(STANDARD.encode(format!("{}:client-secret", n.device.clone()))),
    });
    first.final_message = false;
    let response = send(&http, &h, &s::encode(&first, &CodecLimits::default())?).await?;
    assert!(
        !s::decode_request(&response, &CodecLimits::default())?
            .0
            .final_message
    );
    let second = s::encode(&next(&n, 2, 212, false), &CodecLimits::default())?;
    send(&http, &h, &second).await?;
    let before:(String,i64)=sqlx::query_as("SELECT state, last_message FROM mdm_access.management_sessions WHERE tenant_id = CAST($1 AS uuid) AND device = $2 AND session_id = '17'").bind(c.tenant.to_string()).bind(n.device.clone()).fetch_one(&c.operator).await?;
    assert_eq!(before, ("collecting".into(), 2));
    drop(http);
    h.close().await?;
    let h = host(&c, &n, w).await?;
    let http = client(&n)?;
    let third = s::encode(&next(&n, 3, 200, true), &CodecLimits::default())?;
    let response = send(&http, &h, &third).await?;
    let decoded = s::decode_request(&response, &CodecLimits::default())?.0;
    assert_eq!(decoded.header.session_id, 17);
    assert_eq!(decoded.header.message_id, 3);
    assert!(
        decoded
            .commands
            .iter()
            .any(|cmd| matches!(cmd, s::Command::Get { .. })),
        "continuation must dispatch a real prerequisite query"
    );
    let count = || {
        sqlx::query_as::<_,(i64,i64)>("SELECT (SELECT count(*) FROM mdm_access.management_messages WHERE tenant_id = CAST($1 AS uuid) AND device = $2 AND session_id = '17'), (SELECT count(*) FROM mdm_windows.capability_queries WHERE tenant_id = CAST($1 AS uuid) AND device = $2 AND session_id = '17')").bind(c.tenant.to_string()).bind(n.device.clone()).fetch_one(&c.operator)
    };
    let committed = count().await?;
    assert_eq!(committed, (3, 1));
    assert_eq!(send(&http, &h, &third).await?, response);
    assert_eq!(count().await?, committed);
    let wrong = s::encode(&next(&n, 5, 200, true), &CodecLimits::default())?;
    assert!(send(&http, &h, &wrong).await.is_err());
    assert_eq!(count().await?, committed);
    drop(http);
    h.close().await?;
    c.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "T2: revoke a Windows registration through the real MDM runtime role and replay the original receipt"]
async fn windows_revocation_preserves_device_access_role_isolation() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let n = identity::seed(&c, "windows").await?;
    let account = c
        .account(&[rss_mdm_authorization_service::Permission::Credentials])
        .await?;
    let proof = c.authenticate(&account).await?;
    let devices = crate::device::DeviceService::new(
        c.database.registration(),
        c.tenant.to_string(),
        c.audit.clone(),
    );
    let da_binding_access: bool = sqlx::query_scalar(
        "SELECT has_any_column_privilege('mdm_access','rss_da.bindings','SELECT,UPDATE')",
    )
    .fetch_one(&c.operator)
    .await?;
    assert!(!da_binding_access);
    let operation = uuid::Uuid::new_v4();
    let audit = || -> Result<_> {
        let audit = c.request(&proof)?;
        audit.operation(
            operation,
            "credential_revoke",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        Ok(audit)
    };
    let receipt = devices
        .revoke_inner(&proof, &n.device, operation, &audit()?)
        .await?;
    let replay = devices
        .revoke_inner(&proof, &n.device, operation, &audit()?)
        .await?;
    assert_eq!(receipt, replay);
    let state: (String, String, bool) = sqlx::query_as(
        "SELECT r.state,k.state,s.enabled FROM mdm_access.devices r \
         JOIN mdm_access.credentials k ON (r.tenant_id,r.id)=(k.tenant_id,k.device) \
         JOIN mdm_access.report_sources s ON (r.tenant_id,r.id)=(s.tenant_id,s.device) \
         WHERE r.tenant_id=$1::uuid AND r.id=$2 AND k.id=$3 AND s.source='mdm.windows'",
    )
    .bind(c.tenant.to_string())
    .bind(&n.device)
    .bind(n.credential)
    .fetch_one(&c.operator)
    .await?;
    assert_eq!(state, ("revoked".into(), "revoked".into(), false));
    drop(devices);
    c.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "T2: installation facts use the channel adapter and original SQL transaction"]
async fn installation_facts_correlate_receipts_and_post_dispatch_collection() -> Result<()> {
    use rss_mdm_windows_channel::results::{InstallationDelivery as Delivery, InstallationRead};
    use uuid::Uuid;
    let c = Context::open("shared", &[]).await?;
    let n = identity::seed(&c, "windows").await?;
    let a = Fixture::open(&c, false).await?;
    let operation = Uuid::new_v4();
    let before = Uuid::new_v4();
    let after = Uuid::new_v4();
    let mut tx = command::seed_transaction(&c).await?;
    let command_device = Uuid::new_v4();
    let sentinel = Uuid::new_v4();
    sqlx::query("INSERT INTO mdm_access.command_authorities (tenant_id, device, command_device, generation, epoch) VALUES (CAST($1 AS uuid), $2, $3, 1, 1)").bind(c.tenant.to_string()).bind(&n.device).bind(command_device).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO rss_device_command.authorities(tenant_id,device_id,generation,authority_epoch) VALUES($1::uuid,$2,1,1)").bind(c.tenant.to_string()).bind(command_device).execute(&mut *tx).await?;
    for id in [operation, sentinel] {
        sqlx::query("INSERT INTO rss_device_command.commands(tenant_id,command_id,device_id,generation,authority_epoch,expected_digest,deadline,queued_at,outbox_domain,outbox_message_id,outbox_fingerprint,status,published_at,version) VALUES($1::uuid,$2,$3,1,1,$4,100000000000000000,1,'mdm.commands.v1',$2,$4,'published',1,2)").bind(c.tenant.to_string()).bind(id.to_string()).bind(command_device).bind(vec![0u8;32]).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO mdm_windows.native_commands (tenant_id, id, device) VALUES (CAST($1 AS uuid), $2, $3)").bind(c.tenant.to_string()).bind(id).bind(n.device.clone()).execute(&mut *tx).await?;
    }
    for (ordinal, phase, status, accepted, id) in [
        (1i64, "prepare", 500i32, true, operation),
        (2, "execute", 202, true, operation),
        (3, "execute", 500, false, operation),
        (4, "observe", 500, true, operation),
        (5, "execute", 500, true, sentinel),
    ] {
        let attempt = Uuid::new_v4();
        sqlx::query("INSERT INTO mdm_windows.attempts (tenant_id, id, operation, device, ordinal, credential, session, message, phase, request, protocol_epoch) VALUES (CAST($1 AS uuid), $2, $3, $4, $5, $6, 17, 1, $7, $8, $9)").bind(c.tenant.to_string()).bind(attempt).bind(id).bind(n.device.clone()).bind(ordinal).bind(n.credential).bind(phase).bind(vec![0u8;68]).bind(n.epoch).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO mdm_windows.attempt_items(tenant_id,attempt,command,item_ordinal,kind,uri,status,receipt_accepted) VALUES($1::uuid,$2,2048,0,'exec','./Vendor/MSFT/EnterpriseDesktopAppManagement',$3,$4)").bind(c.tenant.to_string()).bind(attempt).bind(status).bind(accepted).execute(&mut *tx).await?;
    }
    let state = serde_json::json!({"probes":[],"statuses":[200],"values":["1"]});
    for (snapshot, first_command) in [(before, 2048i64), (after, 2049)] {
        sqlx::query("INSERT INTO mdm_access.collection_runs (tenant_id, id, device, source, epoch, scope, sequence, started_at, attempts, result, evidence) VALUES (CAST($1 AS uuid), $2, $3, 'mdm.windows', $4, 'device', $5, 1, '{\"fields\":{}}', 'pending', '{}')")
            .bind(c.tenant.to_string()).bind(snapshot).bind(n.device.clone()).bind(n.epoch).bind(first_command).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO mdm_windows.collections (tenant_id, id, device, session_id, request_message, first_command, kind, template_state, channel_state, protocol_epoch) VALUES (CAST($1 AS uuid), $2, $3, '17', 1, $4, 'agent', $5, $6, $7)")
            .bind(c.tenant.to_string()).bind(snapshot).bind(n.device.clone()).bind(first_command).bind(vec![0u8;68]).bind(&state).bind(n.epoch).execute(&mut *tx).await?;
    }
    sqlx::query("SET LOCAL ROLE mdm_command_runtime")
        .execute(&mut *tx)
        .await?;
    for (device, snapshot, expected_delivery, correlated) in [
        (n.device.clone(), before, Delivery::Acknowledged, false),
        (n.device.clone(), after, Delivery::Acknowledged, true),
        (Uuid::new_v4().to_string(), after, Delivery::Unknown, false),
    ] {
        let facts = rss_mdm_windows_channel::results::Results {
            protection: a.resources.protection.clone(),
        }
        .installations(
            &mut tx,
            c.tenant,
            &[InstallationRead {
                id: operation,
                device,

                snapshot: Some(snapshot),
            }],
        )
        .await?;
        assert_eq!(facts[&operation].delivery, expected_delivery);
        assert_eq!(
            facts[&operation].channel_state.as_ref(),
            correlated.then_some(&state)
        );
    }
    let sentinel_facts = rss_mdm_windows_channel::results::Results {
        protection: a.resources.protection.clone(),
    }
    .installations(
        &mut tx,
        c.tenant,
        &[InstallationRead {
            id: sentinel,
            device: n.device.clone().to_string(),

            snapshot: Some(after),
        }],
    )
    .await?;
    assert_eq!(sentinel_facts[&sentinel].delivery, Delivery::Rejected);
    // Same borrowed transaction sees uncommitted receipt progress; no second checkout can substitute.
    sqlx::query("UPDATE mdm_windows.attempt_items i SET receipt_accepted=false FROM mdm_windows.attempts a WHERE (i.tenant_id,i.attempt)=(a.tenant_id,a.id) AND a.tenant_id=$1::uuid AND a.operation=$2 AND a.phase='execute'")
        .bind(c.tenant.to_string()).bind(operation).execute(&mut *tx).await?;
    let facts = rss_mdm_windows_channel::results::Results {
        protection: a.resources.protection.clone(),
    }
    .installations(
        &mut tx,
        c.tenant,
        &[InstallationRead {
            id: operation,
            device: n.device.clone().to_string(),

            snapshot: None,
        }],
    )
    .await?;
    assert_eq!(
        facts[&operation].delivery,
        Delivery::Rejected,
        "accepted prepare failure is authoritative without an accepted execute receipt"
    );
    tx.rollback().await?;
    let persisted: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM mdm_windows.attempts WHERE tenant_id=$1::uuid AND operation=$2",
    )
    .bind(c.tenant.to_string())
    .bind(operation)
    .fetch_one(&c.operator)
    .await?;
    assert_eq!(persisted, 0);
    Fixture::close(a).await?;
    c.close().await;
    Ok(())
}

/// Legal signed channel material; binding and renewal below use the production identity owner.
async fn protocol_peer(c: &Context, n: &identity::Native, label: &str) -> Result<identity::Native> {
    use uuid::Uuid;
    let request = Uuid::new_v4();
    let attempt = Uuid::new_v4();
    let output = tokio::process::Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../hack/native_protocol_materials.py"
        ))
        .arg(&c.inputs.directory)
        .args([
            "windows",
            &n.device,
            &request.to_string(),
            &attempt.to_string(),
            label,
        ])
        .output()
        .await?;
    anyhow::ensure!(
        output.status.success(),
        "independent native certificate material"
    );
    let paths: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let directory = std::path::PathBuf::from(paths["directory"].as_str().unwrap());
    Ok(identity::Native {
        certificate: identity::der("x509", &directory.join("client.pem")).await?,
        csr: identity::der("req", &directory.join("client.csr")).await?,
        directory,
        request,
        attempt,
        credential: Uuid::new_v4(),
        epoch: Uuid::new_v4(),
        device: n.device.clone(),
        root: n.root.clone(),
        trust: n.trust.clone(),
    })
}

fn first_package(
    n: &identity::Native,
    path: &str,
    password: &str,
    session: u32,
) -> Result<Vec<u8>> {
    let mut first = s::decode(
        include_bytes!("../../../../crates/windows-mdm/tests/fixtures/initialization.xml"),
        &CodecLimits::default(),
    )?;
    first.header.session_id = session;
    first.header.target = format!("https://localhost{path}");
    first.header.source = n.device.clone();
    for command in &mut first.commands {
        if let s::Command::DevInfo { items, .. } = command {
            for item in items {
                if item.source.as_deref() == Some("./DevInfo/DevId") {
                    item.data = Some(Secret(n.device.clone()));
                }
            }
        }
    }
    first.header.credential = Some(s::Credential {
        meta: s::Meta {
            media_type: Some("syncml:auth-basic".into()),
            format: Some("b64".into()),
            ..Default::default()
        },
        data: Secret(STANDARD.encode(format!("{}:{password}", n.device))),
    });
    first.final_message = false;
    Ok(s::encode(&first, &CodecLimits::default())?)
}

#[tokio::test]
#[ignore = "T2: production WinDC identity transactions and real TLS SyncML isolate equal session IDs"]
async fn declared_context_isolates_sessions_and_survives_exact_credential_replacement() -> Result<()>
{
    use rss_mdm_install_support::StorageProfile::Mdm;
    use rss_mdm_inventory::ReportSource::MdmWindows;
    use rss_mdm_registration_service::{
        Purpose,
        device::{self, store},
    };
    use sha2::{Digest, Sha256};
    use uuid::Uuid;
    let c = Context::open("shared", &[]).await?;
    let n = identity::seed(&c, "windows").await?;
    let w = windows(&c, &n).await?;
    let old_child = protocol_peer(&c, &n, "declared-old").await?;
    let child = protocol_peer(&c, &n, "declared").await?;
    let primary_mount = device::ChannelMount::new(Mdm, c.tenant, MdmWindows, Purpose::Primary);
    let declared_mount =
        device::ChannelMount::new(Mdm, c.tenant, MdmWindows, Purpose::WindowsDeclared);
    let parent_evidence = primary_mount.credential(Sha256::digest(&n.certificate).into())?;
    let child_evidence = declared_mount.credential(Sha256::digest(&child.certificate).into())?;
    let protection = crate::device_material_support::protection(&c)?;
    let aad = rss_mdm_native_protection::ProtectionContext::new(
        c.tenant,
        &child.request.to_string(),
        "windows.registration-secrets",
        1,
    )?
    .derive();
    let secrets = protection.seal_bytes(
        &serde_json::to_vec(&serde_json::json!({
            "client_password": "declared-secret", "server_password": "declared-server",
            "server_nonce": vec![9u8;32]
        }))?,
        &aad,
    )?;
    let profile =
        w.ca.profile(
            &rss_mdm_certificate::windows::Csr::verify(&child.csr)?,
            &n.device,
            time::OffsetDateTime::now_utc().unix_timestamp(),
        )?
        .encode()?;
    let mut tx = command::seed_transaction(&c).await?;
    sqlx::query(
        "UPDATE mdm_access.requests SET windows_profile='Full' WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(c.tenant.to_string())
    .bind(n.request)
    .execute(&mut *tx)
    .await?;
    let parent = store::management_in(Mdm, &mut tx, &parent_evidence).await?;
    let old_evidence = declared_mount.credential(Sha256::digest(&old_child.certificate).into())?;
    device::linked::request_in(Mdm, &mut tx, &parent, old_child.request, Uuid::new_v4()).await?;
    device::linked::bind_in(
        Mdm,
        &mut tx,
        &parent,
        &old_evidence,
        old_child.request,
        [old_child.credential, old_child.epoch],
    )
    .await?;
    device::linked::request_in(Mdm, &mut tx, &parent, child.request, Uuid::new_v4()).await?;
    let receipt = device::linked::bind_in(
        Mdm,
        &mut tx,
        &parent,
        &child_evidence,
        child.request,
        [child.credential, child.epoch],
    )
    .await?;
    assert_eq!(receipt.device, n.device);
    assert_ne!(receipt.epoch, n.epoch);
    // The primary enrollment query must select its credential while WinDC is also active.
    sqlx::query("INSERT INTO mdm_pki.trust(tenant_id,purpose,revision,body) VALUES($1::uuid,'windows',1,$2)")
        .bind(c.tenant.to_string()).bind(serde_json::to_vec(&n.trust)?).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_pki.issuers(tenant_id,purpose,digest,revision,state,chain,provider,not_after) VALUES($1::uuid,'windows',$2,1,'active',$3,'step_ca',$4)")
        .bind(c.tenant.to_string()).bind(&n.trust.issuers[0].digest).bind(&n.root)
        .bind(time::OffsetDateTime::now_utc().unix_timestamp() + 86400).execute(&mut *tx).await?;
    for peer in [&n, &child] {
        rss_mdm_pki_service::certificates::record_in(
            Mdm,
            &mut tx,
            &c.tenant.to_string(),
            "windows",
            &n.device,
            &n.trust.issuers[0].digest,
            &peer.certificate,
        )
        .await?;
    }
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    assert!(
        rss_mdm_pki_service::certificates::current_native_credential_in(
            Mdm,
            &mut tx,
            &c.tenant.to_string(),
            &n.device,
            rss_mdm_agent_wire::pki::Purpose::Windows,
            now,
        )
        .await?
    );
    sqlx::query("SAVEPOINT primary_availability")
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "UPDATE mdm_access.credentials SET state='revoked' WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(c.tenant.to_string())
    .bind(n.credential)
    .execute(&mut *tx)
    .await?;
    assert!(
        !rss_mdm_pki_service::certificates::current_native_credential_in(
            Mdm,
            &mut tx,
            &c.tenant.to_string(),
            &n.device,
            rss_mdm_agent_wire::pki::Purpose::Windows,
            now,
        )
        .await?,
        "WinDC cannot make an unavailable primary credential usable"
    );
    sqlx::query("ROLLBACK TO SAVEPOINT primary_availability")
        .execute(&mut *tx)
        .await?;
    // Signed certificate and provisioning material are prerequisites to this session proof.
    sqlx::query("INSERT INTO mdm_access.enrollment_intents(tenant_id,request_id,csr,profile,issuer,configuration,device,credential,epoch,secrets,signing_attempt,protocol_device)
        SELECT tenant_id,$2,$3,$4,issuer,configuration,device,$5,$6,$7,$8,protocol_device FROM mdm_access.enrollment_intents WHERE tenant_id=$1::uuid AND request_id=$9")
        .bind(c.tenant.to_string()).bind(child.request).bind(&child.csr).bind(profile)
        .bind(child.credential).bind(child.epoch).bind(secrets).bind(child.attempt).bind(n.request)
        .execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_access.enrollment_certificates(tenant_id,request_id,certificate,server_nonce) VALUES($1::uuid,$2,$3,$4)")
        .bind(c.tenant.to_string()).bind(child.request).bind(&child.certificate).bind(vec![9u8;32])
        .execute(&mut *tx).await?;
    tx.commit().await?;
    let h = host(&c, &n, w.clone()).await?;
    identity_cases::prepare(&c, &n, &child, &old_child, &h.assembly).await?;
    let parent_http = client(&n)?;
    let child_http = client(&child)?;
    let parent_bytes = first_package(&n, "/ManagementServer/MDM.svc", "client-secret", 17)?;
    let child_bytes = first_package(
        &child,
        "/ManagementServer/Declared.svc",
        "declared-secret",
        17,
    )?;
    let parent_reply = send(&parent_http, &h, &parent_bytes).await?;
    let child_reply = send_at(
        &child_http,
        &h,
        "/ManagementServer/Declared.svc",
        &child_bytes,
    )
    .await?;
    assert_ne!(parent_reply, child_reply);
    // Finish each authenticated package before expecting native work to dispatch.
    let parent_work = s::encode(&next(&n, 2, 212, true), &CodecLimits::default())?;
    let mut child_work = next(&child, 2, 212, true);
    child_work.header.target = "https://localhost/ManagementServer/Declared.svc".into();
    let child_work = s::encode(&child_work, &CodecLimits::default())?;
    let parent_work_reply = send(&parent_http, &h, &parent_work).await?;
    let child_work_reply = send_at(
        &child_http,
        &h,
        "/ManagementServer/Declared.svc",
        &child_work,
    )
    .await?;
    identity_cases::routed(&c, &n, &child, &old_child).await?;
    let rows: Vec<(Uuid, Uuid, i64)> = sqlx::query_as(
        "SELECT protocol_epoch,credential,last_message FROM mdm_access.management_sessions
         WHERE tenant_id=$1::uuid AND device=$2 AND session_id='17' ORDER BY protocol_epoch",
    )
    .bind(c.tenant.to_string())
    .bind(&n.device)
    .fetch_all(&c.operator)
    .await?;
    assert_eq!(rows.len(), 2);
    assert!(rows.contains(&(n.epoch, n.credential, 2)));
    assert!(rows.contains(&(child.epoch, child.credential, 2)));
    // Reload both contexts and replay each immutable transcript under its own epoch.
    h.close().await?;
    let h = host(&c, &n, w).await?;
    assert_eq!(send(&parent_http, &h, &parent_bytes).await?, parent_reply);
    assert_eq!(
        send_at(
            &child_http,
            &h,
            "/ManagementServer/Declared.svc",
            &child_bytes
        )
        .await?,
        child_reply
    );
    let messages: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM mdm_access.management_messages WHERE tenant_id=$1::uuid AND device=$2 AND session_id='17'")
        .bind(c.tenant.to_string()).bind(&n.device).fetch_one(&c.operator).await?;
    assert_eq!(messages, 4);
    assert_eq!(
        send(&parent_http, &h, &parent_work).await?,
        parent_work_reply
    );
    assert_eq!(
        send_at(
            &child_http,
            &h,
            "/ManagementServer/Declared.svc",
            &child_work
        )
        .await?,
        child_work_reply
    );
    let renewed = protocol_peer(&c, &n, "declared-renewed").await?;
    let fingerprint = format!("{:x}", Sha256::digest(&renewed.certificate));
    let mut tx = command::seed_transaction(&c).await?;
    store::replace_mdm_credential_in(
        Mdm,
        &mut tx,
        &c.tenant.to_string(),
        &n.device,
        child.credential,
        &fingerprint,
    )
    .await?;
    assert!(
        store::replace_mdm_credential_in(
            Mdm,
            &mut tx,
            &c.tenant.to_string(),
            &n.device,
            child.credential,
            &fingerprint
        )
        .await
        .is_err(),
        "exact predecessor is single use"
    );
    let renewed_evidence =
        declared_mount.credential(Sha256::digest(&renewed.certificate).into())?;
    let active = store::management_in(Mdm, &mut tx, &renewed_evidence).await?;
    assert_eq!(active.device(), n.device);
    assert_eq!(active.protocol_request(), Some(child.request));
    assert_eq!(active.epoch(), child.epoch);
    assert_ne!(active.credential(), child.credential);
    assert_eq!(
        store::management_in(Mdm, &mut tx, &parent_evidence)
            .await?
            .credential(),
        n.credential
    );
    assert!(
        store::management_in(Mdm, &mut tx, &child_evidence)
            .await
            .is_err()
    );
    let devices: i64 =
        sqlx::query_scalar("SELECT count(*) FROM mdm_access.devices WHERE tenant_id=$1::uuid")
            .bind(c.tenant.to_string())
            .fetch_one(&mut *tx)
            .await?;
    assert_eq!(
        devices, 1,
        "WinDC and credential replacement never allocate a device"
    );
    tx.commit().await?;
    let renewed_http = client(&renewed)?;
    let renewed_bytes = first_package(
        &renewed,
        "/ManagementServer/Declared.svc",
        "declared-secret",
        18,
    )?;
    send_at(
        &renewed_http,
        &h,
        "/ManagementServer/Declared.svc",
        &renewed_bytes,
    )
    .await?;
    assert!(
        send_at(
            &child_http,
            &h,
            "/ManagementServer/Declared.svc",
            &child_bytes
        )
        .await
        .is_err()
    );
    assert_eq!(send(&parent_http, &h, &parent_bytes).await?, parent_reply);
    h.close().await?;
    c.close().await;
    Ok(())
}
