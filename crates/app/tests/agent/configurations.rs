//! Real HTTP/Postgres publication, signed files and independent mTLS activation.
#![allow(
    clippy::cognitive_complexity,
    reason = "integration matrices preserve independent authority and recovery assertions"
)]
use crate::test_support::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use rss_mdm_agent_wire::{enroll as w, runtime as r};
use software::{Fixture, write};
use uuid::Uuid;
fn root() -> std::path::PathBuf {
    std::env::var("MDM_AGENT_PKI_FIXTURES").unwrap().into()
}
fn profile(windows: bool) -> Value {
    json!({"capabilities":["inventory.collect.v1"],"platform":if windows{"windows"}else{"macos"},"architecture":if windows{"x86_64"}else{"aarch64"},"executionContext":software_execution::context(if windows{software_execution::Platform::Windows}else{software_execution::Platform::MacOs})})
}
async fn fixture() -> Result<Fixture> {
    let f = Fixture::with_peer_and_uploads(None, Some(1)).await?;
    let tenant = [
        "resource_read",
        "resource_write",
        "software_read",
        "software_write",
        "release_publish",
        "software_withdraw",
        "agent_enrollment_read",
        "agent_enrollment_write",
    ];
    let mut grants = tenant
        .into_iter()
        .map(|name| {
            Ok(crate::authorization::Grant {
                operation: serde_json::from_value(json!(name))?,
                scope: crate::authorization::Scope::Tenant,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    for name in ["enrollment", "credentials"] {
        grants.push(crate::authorization::Grant {
            operation: serde_json::from_value(json!(name))?,
            scope: crate::authorization::Scope::AllDevices,
        });
    }
    identity::set_grants(case_tenant(), &f.subject, grants).await?;
    Ok(f)
}
async fn upload(
    f: &Fixture,
    user: &Browser,
    id: &str,
    platform: &str,
    architecture: &str,
    artifact: &str,
    bytes: &[u8],
) -> Result<()> {
    let cookie = user
        .cookies
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("; ");
    let response=f.client.post(format!("{}/api/v1/resources/{id}/content?version=v1&variant=default&platform={platform}&architecture={architecture}&artifact={artifact}&operation={}",f.origin,Uuid::new_v4()))
  .header("host","mdm.example.test").header("origin","https://mdm.example.test").header("x-identity-request","1").header("x-csrf-token",user.csrf.as_ref().unwrap()).header("cookie",cookie).header("content-type","application/octet-stream").body(bytes.to_vec()).send().await?;
    let status = response.status();
    let body = response.text().await?;
    ensure!(
        status == StatusCode::CREATED,
        "upload {artifact}: {status} {body}"
    );
    Ok(())
}
async fn publish(
    f: &Fixture,
    user: &mut Browser,
    windows: bool,
) -> Result<w::configuration::Package> {
    publish_version(f, user, windows, "1+enterprise").await
}
async fn publish_version(
    f: &Fixture,
    user: &mut Browser,
    windows: bool,
    version: &str,
) -> Result<w::configuration::Package> {
    let base: Value = serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
    let (platform, architecture, format, _filename) = if windows {
        ("windows", "x86_64", "exe", "rss-agent.exe")
    } else {
        ("macos", "aarch64", "pkg", "rss-agent.pkg")
    };
    let bytes = vec![if windows { 0x4e } else { 0x50 }; 128 * 1024 + 3];
    let candidate = serde_json::to_vec(
        &json!({"wireVersion":1,"tenantId":case_tenant(),"target":{"platform":platform,"architecture":architecture},"version":version,"origin":"https://mdm.example.test:9445","signingKeys":base["task_signing"]["trusted_keys"],"packaging":if windows{json!({"kind":"nsis_exe","publisher":"RSS Test Publisher","signature_evidence":"external-signed-build:1"})}else{json!({"kind":"macos_pkg","team":"ABCDEFGHIJ","notarization_evidence":"external-notarized-build:1"})}}),
    )?;
    let mut definition =
        publication_support::private_definition(f.registered["snapshot"].clone(), &bytes);
    definition["version"] = json!(version);
    definition["artifacts"]["candidate"] = json!({"reference":"candidate","length":candidate.len(),"sha256":rss_mdm_resource::Digest::of(&candidate).bytes()});
    definition["behavior"]["kind"] = json!(format);
    if windows {
        definition["behavior"]["layout"] =
            json!({"rss-agent.exe":"package","rss-agent.candidate.json":"candidate"});
        definition["behavior"]["install"]["arguments"] = json!(["/S"]);
        definition["behavior"]["upgradeInvocation"]["arguments"] = json!(["/S"]);
    } else {
        definition["behavior"]["install"]["arguments"] = json!([]);
        definition["behavior"]["upgradeInvocation"]["arguments"] = json!([]);
        definition["behavior"]["detect"] =
            json!({"kind":"pkg_receipt","receipt":"com.rss.agent","version":version});
    }
    let id = Uuid::new_v4().to_string();
    let path = format!("/api/v1/resources/{id}");
    write(
        user,
        &f.router,
        &path,
        0,
        json!({"action":"create","kind":"software"}),
    )
    .await?;
    write(user,&f.router,&path,1,json!({"action":"version","version":"v1","kind":"software","variants":[{"platform":platform,"architecture":architecture,"key":"default","declaration":{"kind":"software","definition":definition}}]})).await?;
    upload(f, user, &id, platform, architecture, "installer", &bytes).await?;
    upload(
        f,
        user,
        &id,
        platform,
        architecture,
        "candidate",
        &candidate,
    )
    .await?;
    write(
        user,
        &f.router,
        &path,
        2,
        json!({"action":"activate","version":"v1"}),
    )
    .await?;
    write(
        user,
        &f.router,
        &format!("/api/v1/software/resources/{id}/versions/v1"),
        0,
        json!({"action":"enable"}),
    )
    .await?;
    let input = json!({"operationId":Uuid::new_v4(),"resource":id,"version":"v1","variant":"default","target":{"platform":platform,"architecture":architecture},"channel":"production","manifestArtifact":"candidate"});
    let (status, document) = user
        .call(
            &f.router,
            Method::POST,
            "/api/v1/agent-packages",
            Some(input.clone()),
        )
        .await?;
    ensure!(status == StatusCode::OK, "publication {status} {document}");
    ensure!(
        user.call(
            &f.router,
            Method::POST,
            "/api/v1/agent-packages",
            Some(input.clone())
        )
        .await?
        .1 == document
    );
    let package: w::configuration::Package = serde_json::from_value(document)?;
    ensure!(
        package.installer_sha256 == rss_mdm_resource::Digest::of(&bytes).bytes()
            && package.candidate_sha256 == rss_mdm_resource::Digest::of(&candidate).bytes()
            && package.installer_sha256 != package.candidate_sha256
    );
    let response = f
        .client
        .get(format!(
            "{}/api/v1/agent/enroll/packages/{}/content",
            f.origin, package.release_id
        ))
        .header("host", "mdm.example.test:9445")
        .header("range", "bytes=0-4")
        .send()
        .await?;
    ensure!(response.status() == StatusCode::PARTIAL_CONTENT);
    ensure!(response.bytes().await?.as_ref() == &bytes[..5]);
    Ok(package)
}
async fn configuration(
    f: &Fixture,
    user: &mut Browser,
    quantity: Value,
    lifetime: Option<u32>,
) -> Result<w::configuration::ConfigurationFile> {
    let mut input = json!({"operationId":Uuid::new_v4(),"secret":credential(&Uuid::new_v4().to_string()),"quantity":quantity,"targets":[{"platform":"windows","architecture":"x86_64"},{"platform":"macos","architecture":"aarch64"}],"channels":["production"]});
    if let Some(seconds) = lifetime {
        input["lifetimeSeconds"] = json!(seconds);
    }
    let response = user
        .call(
            &f.router,
            Method::POST,
            "/api/v1/agent-configurations",
            Some(input.clone()),
        )
        .await?;
    ensure!(response.0 == StatusCode::OK, "configuration {response:?}");
    let operation = input["operationId"].as_str().unwrap().to_owned();
    ensure!(
        user.call(
            &f.router,
            Method::POST,
            "/api/v1/agent-configurations",
            Some(input)
        )
        .await?
        .1 == response.1
    );
    let found = user
        .call(
            &f.router,
            Method::GET,
            &format!("/api/v1/agent-configuration-operations/{operation}"),
            None,
        )
        .await?;
    ensure!(
        found.0 == StatusCode::OK && found.1["configuration"] == response.1["configuration"],
        "operation lookup {found:?}"
    );
    ensure!(
        found.1.get("secret").is_none() && found.1.get("signature").is_none(),
        "operation disclosed file"
    );
    ensure!(found.1["remaining"] == quantity.get("count").cloned().unwrap_or(Value::Null));
    let mut other = authority::Authority::open().await?.browser("other")?;
    let forbidden = other
        .call(
            &f.router,
            Method::GET,
            &format!("/api/v1/agent-configuration-operations/{operation}"),
            None,
        )
        .await?;
    ensure!(
        forbidden.0 == StatusCode::FORBIDDEN,
        "operation read bypassed management permission {forbidden:?}"
    );

    let unknown = user
        .call(
            &f.router,
            Method::GET,
            &format!("/api/v1/agent-configuration-operations/{}", Uuid::new_v4()),
            None,
        )
        .await?;
    ensure!(
        unknown.0 == StatusCode::OK && unknown.1.is_null(),
        "missing operation must remain unknown"
    );
    let file = serde_json::from_value(response.1)?;
    Ok(file)
}
fn exchange(
    file: &w::configuration::ConfigurationFile,
    package: &w::configuration::Package,
    n: usize,
) -> Result<w::configuration::Exchange> {
    Ok(w::configuration::Exchange {
        file: file.clone(),
        operation_id: Uuid::new_v4(),
        secret: r::Secret::parse(&credential(&Uuid::new_v4().to_string()))?,
        csr: STANDARD.encode(std::fs::read(
            root().join(format!("configuration-{n}.der")),
        )?),
        runtime: serde_json::from_value(profile(
            package.target.platform == r::TaskPlatform::Windows,
        ))?,
        installation: w::configuration::Installation {
            release_id: package.release_id,
            candidate_sha256: package.candidate_sha256,
        },
    })
}
async fn machine(
    f: &Fixture,
    path: &str,
    input: &impl serde::Serialize,
) -> Result<(StatusCode, Value)> {
    let response = f
        .client
        .post(format!("{}{path}", f.origin))
        .header("host", "mdm.example.test:9445")
        .json(input)
        .send()
        .await?;
    let status = response.status();
    let value = response.json().await?;
    Ok((status, value))
}
async fn read(f: &Fixture, user: &mut Browser, id: Uuid) -> Result<Value> {
    let out = user
        .call(
            &f.router,
            Method::GET,
            &format!("/api/v1/agent-configurations/{id}"),
            None,
        )
        .await?;
    ensure!(out.0 == StatusCode::OK, "read {out:?}");
    ensure!(out.1.get("secret").is_none() && out.1["responsibleUser"].is_null());
    let expected = out.1["configuration"]["quantity"]
        .get("count")
        .and_then(Value::as_u64)
        .map(|n| {
            json!(n - out.1["reserved"].as_u64().unwrap() - out.1["consumed"].as_u64().unwrap())
        })
        .unwrap_or(Value::Null);
    ensure!(
        out.1["remaining"] == expected,
        "remaining disagrees with durable usage {out:?}"
    );
    Ok(out.1)
}
struct Tls {
    address: std::net::SocketAddr,
    owner: rss_runtime::ShutdownStack,
}
impl Tls {
    async fn start(authority: &authority::Authority) -> Result<Self> {
        let service = agent::service(authority).await?;
        let base = authority.base.clone();
        let pki = serde_json::from_value::<crate::agent_pki::Config>(base["agent_pki"].clone())?
            .load(
                authority.audit.clone(),
                Arc::new(crate::clock::SystemClock),
                crate::device_pki::providers(&serde_json::from_value::<
                    Vec<crate::device_pki::Provider>,
                >(base["device_pki"].clone())?)?,
            )?
            .unwrap();
        let envelope = rss_mdm_agent_channel::boundary::Envelope {
            admission: Arc::new(tokio::sync::Semaphore::new(32)),
            host: pki.origin.trim_start_matches("https://").into(),
            clock: monotonic(),
            audit_store: authority.audit.clone(),
            requests: Arc::new(tokio::sync::Semaphore::new(4)),
            tenant: case_tenant().into(),
        };
        let router = Router::new().nest(
            "/api/v1/agent/enroll",
            crate::agent::enroll::router(service, envelope),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let tls = crate::native::TlsRouter {
            listen: address,
            tls: pki.tls.clone(),
            router,
            admission: crate::native::admission::Admission::new(
                monotonic(),
                Arc::new(tokio::sync::Semaphore::new(4)),
                "configuration-tls",
            ),
        };
        let mut owner = rss_runtime::ShutdownStack::try_new(
            rss_runtime::TotalDrainBudget::new(Duration::from_secs(5))?,
            Arc::new(crate::lifecycle::RuntimeTimer),
        )?;
        owner
            .startup()?
            .stage_task_with_token(crate::native::tls::registration(
                listener,
                tls,
                authority.audit.clone(),
                case_tenant().into(),
                crate::native::NativeListenerKind::Agent,
            ));
        Ok(Self { address, owner })
    }
    async fn activate(&self, candidate: &Value, n: usize) -> Result<Value> {
        let chain = candidate["certificateChain"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| STANDARD.decode(v.as_str().unwrap()))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let mut io = crate::test_support::agent_http::connect_agent_with_key(
            self.address,
            Some(&chain),
            &format!("configuration-{n}.pk8"),
        )
        .await?;
        let (status,receipt)=crate::test_support::agent_http::agent_http(&mut io,"POST","/api/v1/agent/enroll/activate",Some(json!({"wireVersion":1,"issuanceId":candidate["issuanceId"],"operationId":Uuid::new_v4()}))).await?;
        ensure!(
            status == 200,
            "independent mTLS activation {status} {receipt}"
        );
        Ok(receipt)
    }
}
async fn enroll(
    f: &Fixture,
    tls: &Tls,
    file: &w::configuration::ConfigurationFile,
    package: &w::configuration::Package,
    n: usize,
) -> Result<String> {
    let input = exchange(file, package, n)?;
    let (status, grant) =
        machine(f, "/api/v1/agent/enroll/configurations/exchange", &input).await?;
    ensure!(status == StatusCode::OK, "exchange {n} {status} {grant}");
    ensure!(
        machine(f, "/api/v1/agent/enroll/configurations/exchange", &input)
            .await?
            .1
            == grant
    );
    let request = json!({"wireVersion":1,"operationId":Uuid::new_v4(),"grantId":grant["grantId"],"secret":input.secret,"csr":input.csr,"runtime":input.runtime});
    let (status, candidate) = machine(f, "/api/v1/agent/enroll/certificates", &request).await?;
    ensure!(
        status == StatusCode::OK,
        "certificate {n} {status} {candidate}"
    );
    // Independent devices share one loopback IP; respect the native one-connection-per-second refill.
    tokio::time::sleep(Duration::from_secs(1)).await;
    Ok(tls.activate(&candidate, n).await?["runtime"]["deviceId"]
        .as_str()
        .unwrap()
        .to_owned())
}
/// Prepare current configuration peers; allocation boundaries below remain real API calls.
async fn configuration_prefix(
    service: &rss_mdm_registration_service::agent::Service,
    file: &w::configuration::ConfigurationFile,
    windows: &w::configuration::Package,
    macos: &w::configuration::Package,
    start: usize,
) -> Result<Vec<String>> {
    let file = file.clone();
    let windows = windows.clone();
    let macos = macos.clone();
    let configuration_id = file.configuration.configuration_id;
    let seeds = tokio::task::spawn_blocking(move || -> Result<Vec<_>> {
        use crate::clock::Clock;
        let now = crate::clock::SystemClock.unix_seconds()?;
        (start..start + 19)
            .map(|n| {
                let package = if n % 2 == 0 { &windows } else { &macos };
                let request = exchange(&file, package, n)?;
                let device = Uuid::new_v4().to_string();
                let identity =
                    rss_mdm_certificate::agent::identity(file.configuration.tenant_id, &device)?;
                let csr = STANDARD.decode(&request.csr)?;
                let chain = crate::test_support::pki::leaf(
                    &root(),
                    &csr,
                    "rss-mdm-agent",
                    &[identity],
                    now,
                    now + 86400,
                )?;
                let validity = crate::test_support::pki::validity(&chain[0])?;
                Ok(rss_mdm_registration_service::agent::ConfigurationPeerSeed {
                    device,
                    request,
                    chain,
                    validity,
                })
            })
            .collect()
    })
    .await??;
    Ok(service
        .seed_configuration_peers(configuration_id, seeds)
        .await?)
}
#[tokio::test]
#[ignore = "MODULE=agent.configurations: 42 independent peers, quota boundaries and representative mTLS HTTP"]
async fn fixed_packages_and_configurations_activate_beyond_self_quota() -> Result<()> {
    let f = fixture().await?;
    let mut user = f.user.clone();
    let windows = publish(&f, &mut user, true).await?;
    let macos = publish(&f, &mut user, false).await?;
    let file = configuration(&f, &mut user, json!({"kind":"finite","count":21}), None).await?;
    let authority = authority::Authority::open().await?;
    let tls = Tls::start(&authority).await?;
    let service = crate::test_support::agent::service(&authority).await?;
    let mut devices = configuration_prefix(&service, &file, &windows, &macos, 0)
        .await?
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    ensure!(devices.len() == 19);
    let state = read(&f, &mut user, file.configuration.configuration_id).await?;
    ensure!(state["reserved"] == 0 && state["consumed"] == 19);
    for n in 19..21 {
        let package = if n % 2 == 0 { &windows } else { &macos };
        ensure!(devices.insert(enroll(&f, &tls, &file, package, n).await?));
        let state = read(&f, &mut user, file.configuration.configuration_id).await?;
        ensure!(state["reserved"] == 0 && state["consumed"] == n + 1);
    }
    let state = read(&f, &mut user, file.configuration.configuration_id).await?;
    ensure!(state["reserved"] == 0 && state["consumed"] == 21);
    ensure!(
        machine(
            &f,
            "/api/v1/agent/enroll/configurations/exchange",
            &exchange(&file, &macos, 21)?
        )
        .await?
        .0 == StatusCode::TOO_MANY_REQUESTS
    );
    let unlimited = configuration(&f, &mut user, json!({"kind":"unlimited"}), None).await?;
    for device in configuration_prefix(&service, &unlimited, &windows, &macos, 21).await? {
        ensure!(devices.insert(device));
    }
    let state = read(&f, &mut user, unlimited.configuration.configuration_id).await?;
    ensure!(state["reserved"] == 0 && state["consumed"] == 19);
    for n in 40..42 {
        let package = if n % 2 == 0 { &windows } else { &macos };
        ensure!(devices.insert(enroll(&f, &tls, &unlimited, package, n).await?));
        let state = read(&f, &mut user, unlimited.configuration.configuration_id).await?;
        ensure!(state["reserved"] == 0 && state["consumed"] == n - 20);
    }
    ensure!(devices.len() == 42);
    let state = read(&f, &mut user, unlimited.configuration.configuration_id).await?;
    ensure!(state["reserved"] == 0 && state["consumed"] == 21);
    let me = user
        .call(
            &f.router,
            Method::GET,
            "/api/v1/registration-quotas/me",
            None,
        )
        .await?;
    ensure!(me.0 == StatusCode::OK && me.1["channels"][0]["used"] == 0);
    for device in &devices {
        let responsibility = user
            .call(
                &f.router,
                Method::GET,
                &format!("/api/v1/devices/{device}/registration-user"),
                None,
            )
            .await?;
        ensure!(responsibility.0 == StatusCode::OK && responsibility.1["user"].is_null());
    }
    user.call(
        &f.router,
        Method::POST,
        &format!(
            "/api/v1/agent-configurations/{}/revoke",
            file.configuration.configuration_id
        ),
        Some(json!({"operationId":Uuid::new_v4()})),
    )
    .await?;
    let live:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND channel='agent' AND state='active'").bind(case_tenant()).fetch_one(&mut *authority.access.begin(case_tenant()).await?).await?;
    ensure!(
        live == 42,
        "configuration revoke deactivated existing devices"
    );
    ensure!(tls.owner.shutdown().join().await?.is_clean());
    Ok(())
}
#[tokio::test]
#[ignore = "MODULE=agent.configurations: concurrent finite allocation, cancellation, revoke and frozen TTL"]
async fn finite_reservations_and_frozen_authority_survive_revoke() -> Result<()> {
    let f = fixture().await?;
    let mut user = f.user.clone();
    let package = publish(&f, &mut user, false).await?;
    let file = configuration(&f, &mut user, json!({"kind":"finite","count":2}), None).await?;
    let mut other = authority::Authority::open().await?.browser("other")?;
    ensure!(other.call(&f.router,Method::POST,"/api/v1/agent-configurations",Some(json!({"operationId":Uuid::new_v4(),"secret":credential("forbidden"),"quantity":{"kind":"unlimited"},"targets":[{"platform":"macos","architecture":"aarch64"}],"channels":["production"]}))).await?.0==StatusCode::FORBIDDEN);
    for quantity in [
        json!({"kind":"finite","count":0}),
        json!({"kind":"finite","count":-1}),
    ] {
        ensure!(user.call(&f.router,Method::POST,"/api/v1/agent-configurations",Some(json!({"operationId":Uuid::new_v4(),"secret":credential("invalid-count"),"quantity":quantity,"targets":[{"platform":"macos","architecture":"aarch64"}],"channels":["production"]}))).await?.0==StatusCode::BAD_REQUEST);
    }
    let mut bad = exchange(&file, &package, 0)?;
    bad.file.configuration.origin = "https://untrusted.example".into();
    ensure!(
        machine(&f, "/api/v1/agent/enroll/configurations/exchange", &bad)
            .await?
            .0
            == StatusCode::UNAUTHORIZED
    );
    bad = exchange(&file, &package, 0)?;
    bad.secret = file.secret.clone();
    ensure!(
        machine(&f, "/api/v1/agent/enroll/configurations/exchange", &bad)
            .await?
            .0
            == StatusCode::BAD_REQUEST
    );
    bad = exchange(&file, &package, 0)?;
    bad.installation.candidate_sha256 = package.installer_sha256;
    ensure!(
        machine(&f, "/api/v1/agent/enroll/configurations/exchange", &bad)
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    let inputs = (0..4)
        .map(|n| exchange(&file, &package, n))
        .collect::<Result<Vec<_>>>()?;
    let replies = futures::future::join_all(
        inputs
            .iter()
            .map(|input| machine(&f, "/api/v1/agent/enroll/configurations/exchange", input)),
    )
    .await;
    let mut accepted = Vec::new();
    for (n, result) in replies.into_iter().enumerate() {
        let (status, grant) = result?;
        if status == StatusCode::OK {
            accepted.push((n, grant));
        } else {
            ensure!(
                status == StatusCode::TOO_MANY_REQUESTS,
                "concurrent result {status} {grant}"
            );
        }
    }
    ensure!(accepted.len() == 2);
    let first = accepted[0].0;
    let second = accepted[1].0;
    let mut changed = inputs[first].clone();
    changed.csr = STANDARD.encode(std::fs::read(root().join("other.der"))?);
    ensure!(
        machine(&f, "/api/v1/agent/enroll/configurations/exchange", &changed)
            .await?
            .0
            == StatusCode::CONFLICT
    );
    let cancellation = w::configuration::Cancel {
        wire_version: 1,
        grant_id: serde_json::from_value(accepted[0].1["grantId"].clone())?,
        operation_id: Uuid::new_v4(),
        creation_operation_id: inputs[first].operation_id,
        secret: inputs[first].secret.clone(),
    };
    let canceled = machine(
        &f,
        "/api/v1/agent/enroll/reservations/cancel",
        &cancellation,
    )
    .await?;
    ensure!(canceled.0 == StatusCode::OK && canceled.1["state"] == "revoked");
    ensure!(
        machine(
            &f,
            "/api/v1/agent/enroll/reservations/cancel",
            &cancellation
        )
        .await?
            == canceled
    );
    let replacement = exchange(&file, &package, 4)?;
    ensure!(
        machine(
            &f,
            "/api/v1/agent/enroll/configurations/exchange",
            &replacement
        )
        .await?
        .0 == StatusCode::OK
    );
    let state = read(&f, &mut user, file.configuration.configuration_id).await?;
    ensure!(state["reserved"] == 2 && state["consumed"] == 0);
    let revoke = user
        .call(
            &f.router,
            Method::POST,
            &format!(
                "/api/v1/agent-configurations/{}/revoke",
                file.configuration.configuration_id
            ),
            Some(json!({"operationId":Uuid::new_v4()})),
        )
        .await?;
    ensure!(revoke.0 == StatusCode::NO_CONTENT);
    ensure!(
        machine(
            &f,
            "/api/v1/agent/enroll/configurations/exchange",
            &exchange(&file, &package, 5)?
        )
        .await?
        .0 == StatusCode::FORBIDDEN
    );
    let status = w::configuration::ExchangeStatus {
        wire_version: 1,
        configuration_id: file.configuration.configuration_id,
        operation_id: inputs[second].operation_id,
        secret: inputs[second].secret.clone(),
    };
    ensure!(
        machine(&f, "/api/v1/agent/enroll/configurations/status", &status)
            .await?
            .1
            == accepted[1].1
    );
    let candidate=machine(&f,"/api/v1/agent/enroll/certificates",&json!({"wireVersion":1,"operationId":Uuid::new_v4(),"grantId":accepted[1].1["grantId"],"secret":inputs[second].secret,"csr":inputs[second].csr,"runtime":inputs[second].runtime})).await?;
    ensure!(
        candidate.0 == StatusCode::OK,
        "assigned grant lost frozen TTL after revoke {candidate:?}"
    );
    let authority = authority::Authority::open().await?;
    let tls = Tls::start(&authority).await?;
    tls.activate(&candidate.1, second).await?;
    let mut consumed_cancel = cancellation;
    consumed_cancel.grant_id = serde_json::from_value(accepted[1].1["grantId"].clone())?;
    consumed_cancel.creation_operation_id = inputs[second].operation_id;
    consumed_cancel.secret = inputs[second].secret.clone();
    consumed_cancel.operation_id = Uuid::new_v4();
    ensure!(
        machine(
            &f,
            "/api/v1/agent/enroll/reservations/cancel",
            &consumed_cancel
        )
        .await?
        .0 == StatusCode::CONFLICT
    );
    let state = read(&f, &mut user, file.configuration.configuration_id).await?;
    ensure!(state["consumed"] == 1 && state["reserved"] == 1);
    ensure!(tls.owner.shutdown().join().await?.is_clean());
    Ok(())
}
#[tokio::test]
#[ignore = "MODULE=agent.configurations: HTTP lost commits, permanent issuance accounting and lookup"]
async fn unknown_exchange_and_issuance_do_not_reset_quantity() -> Result<()> {
    let f = fixture().await?;
    let mut user = f.user.clone();
    let package = publish(&f, &mut user, false).await?;
    let file = configuration(&f, &mut user, json!({"kind":"finite","count":1}), None).await?;
    let authority = authority::Authority::open().await?;
    let service = agent::service(&authority).await?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let origin = format!("http://{}", listener.local_addr()?);
    let _server = software::HttpServer::start(listener, agent::router(&authority).await?);
    let post = |path: &str, value: Value| {
        let url = format!("{origin}{path}");
        let client = f.client.clone();
        async move {
            let response = client
                .post(url)
                .header("host", "mdm.example.test:9445")
                .json(&value)
                .send()
                .await?;
            let status = response.status();
            Ok::<_, anyhow::Error>((status, response.json::<Value>().await?))
        }
    };
    let input = exchange(&file, &package, 0)?;
    authority
        .audit
        .inject_next_fault(rss_audit_postgres::PgFault::BeforeCommitPending);
    ensure!(
        post(
            "/api/v1/agent/enroll/configurations/exchange",
            serde_json::to_value(&input)?
        )
        .await?
        .0 == StatusCode::SERVICE_UNAVAILABLE
    );
    ensure!(read(&f, &mut user, file.configuration.configuration_id).await?["reserved"] == 0);
    authority
        .audit
        .inject_next_fault(rss_audit_postgres::PgFault::CommitUnknownAfterAck);
    ensure!(
        post(
            "/api/v1/agent/enroll/configurations/exchange",
            serde_json::to_value(&input)?
        )
        .await?
        .0 == StatusCode::SERVICE_UNAVAILABLE
    );
    let lookup = w::configuration::ExchangeStatus {
        wire_version: 1,
        configuration_id: file.configuration.configuration_id,
        operation_id: input.operation_id,
        secret: input.secret.clone(),
    };
    let status = post(
        "/api/v1/agent/enroll/configurations/status",
        serde_json::to_value(&lookup)?,
    )
    .await?;
    ensure!(status.0 == StatusCode::OK);
    ensure!(
        post(
            "/api/v1/agent/enroll/configurations/exchange",
            serde_json::to_value(&input)?
        )
        .await?
        .1 == status.1
    );
    let signing = json!({"wireVersion":1,"operationId":Uuid::new_v4(),"grantId":status.1["grantId"],"secret":input.secret,"csr":input.csr,"runtime":input.runtime});
    authority
        .audit
        .inject_next_fault(rss_audit_postgres::PgFault::CommitUnknownAfterAck);
    ensure!(
        post("/api/v1/agent/enroll/certificates", signing.clone())
            .await?
            .0
            == StatusCode::SERVICE_UNAVAILABLE
    );
    let replay = post("/api/v1/agent/enroll/certificates", signing).await?;
    ensure!(replay.0 == StatusCode::SERVICE_UNAVAILABLE && replay.1["code"] == "issuance_unknown");
    let state = read(&f, &mut user, file.configuration.configuration_id).await?;
    ensure!(state["reserved"] == 0 && state["consumed"] == 1);
    let cancellation = w::configuration::Cancel {
        wire_version: 1,
        grant_id: serde_json::from_value(status.1["grantId"].clone())?,
        operation_id: Uuid::new_v4(),
        creation_operation_id: input.operation_id,
        secret: input.secret.clone(),
    };
    ensure!(
        post(
            "/api/v1/agent/enroll/reservations/cancel",
            serde_json::to_value(&cancellation)?
        )
        .await?
        .0 == StatusCode::CONFLICT
    );
    pg(&format!(
        "UPDATE mdm_access.agent_grants SET created_at=clock_timestamp()-interval '25 hours',expires_at=clock_timestamp()-interval '1 hour' WHERE tenant_id='{}' AND id='{}'",
        case_tenant(),
        cancellation.grant_id
    ))?;
    ensure!(service.configuration_exchange_status(&lookup).await?.state == w::GrantState::Expired);
    ensure!(
        post(
            "/api/v1/agent/enroll/configurations/exchange",
            serde_json::to_value(exchange(&file, &package, 1)?)?
        )
        .await?
        .0 == StatusCode::TOO_MANY_REQUESTS
    );
    ensure!(read(&f, &mut user, file.configuration.configuration_id).await?["consumed"] == 1);
    Ok(())
}
#[tokio::test]
#[ignore = "MODULE=agent.configurations: first claim waits across grant expiry before a slot is reused"]
async fn expired_reservation_cannot_be_consumed_after_configuration_lock_wait() -> Result<()> {
    use sqlx::Connection;
    let f = fixture().await?;
    let mut user = f.user.clone();
    let package = publish(&f, &mut user, false).await?;
    let file = configuration(&f, &mut user, json!({"kind":"finite","count":1}), None).await?;
    let input = exchange(&file, &package, 0)?;
    let (status, grant) =
        machine(&f, "/api/v1/agent/enroll/configurations/exchange", &input).await?;
    ensure!(status == StatusCode::OK);
    let mut owner =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    sqlx::query("SELECT pg_sleep(greatest(0,0.75-mod(extract(epoch FROM clock_timestamp()),1)))")
        .execute(&mut owner)
        .await?;
    sqlx::query("UPDATE mdm_access.agent_grants SET created_at=clock_timestamp()-interval '1 hour',expires_at=to_timestamp(floor(extract(epoch FROM clock_timestamp()))+1) WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(case_tenant()).bind(grant["grantId"].as_str().unwrap()).execute(&mut owner).await?;
    let mut blocker = owner.begin().await?;
    sqlx::query("SELECT id FROM mdm_access.agent_configurations WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE").bind(case_tenant()).bind(file.configuration.configuration_id).fetch_one(&mut *blocker).await?;
    let signing = json!({"wireVersion":1,"operationId":Uuid::new_v4(),"grantId":grant["grantId"],"secret":input.secret,"csr":input.csr,"runtime":input.runtime});
    let issue = tokio::spawn({
        let client = f.client.clone();
        let url = format!("{}/api/v1/agent/enroll/certificates", f.origin);
        async move {
            let response = client
                .post(url)
                .header("host", "mdm.example.test:9445")
                .json(&signing)
                .send()
                .await?;
            Ok::<_, anyhow::Error>((response.status(), response.json::<Value>().await?))
        }
    });
    let observer = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(crate::device::test_support::options("postgres")?)
        .await?;
    tokio::time::timeout(Duration::from_millis(800),async {
  loop {let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND usename='mdm_access' AND wait_event_type='Lock' AND query LIKE '%agent_configurations%')").fetch_one(&observer).await?;if waiting{break;}tokio::time::sleep(Duration::from_millis(10)).await;}
  Ok::<_,sqlx::Error>(())
 }).await??;
    let next = exchange(&file, &package, 1)?;
    let allocation = machine(&f, "/api/v1/agent/enroll/configurations/exchange", &next);
    tokio::pin!(allocation);
    let delayed = async {
        tokio::time::sleep(Duration::from_millis(400)).await;
        blocker.commit().await
    };
    let (new, release) = tokio::join!(&mut allocation, delayed);
    release?;
    let issued = issue.await??;
    ensure!(
        issued.0 == StatusCode::FORBIDDEN && issued.1["code"] == "grant_expired",
        "stale live test admitted issuance {issued:?}"
    );
    ensure!(new?.0 == StatusCode::OK);
    let state = read(&f, &mut user, file.configuration.configuration_id).await?;
    ensure!(state["reserved"] == 1 && state["consumed"] == 0);
    observer.close().await;
    owner.close().await?;
    Ok(())
}
#[tokio::test]
#[ignore = "MODULE=agent.configurations: durable settings, permission/CAS, expiry and removed self API"]
async fn backend_settings_are_the_only_grant_lifetime_authority() -> Result<()> {
    let f = fixture().await?;
    let mut user = f.user.clone();
    let package = publish(&f, &mut user, false).await?;
    let initial = user
        .call(
            &f.router,
            Method::GET,
            "/api/v1/agent-enrollment-settings",
            None,
        )
        .await?;
    ensure!(initial.0 == StatusCode::OK && initial.1["values"]["grantSeconds"] == 86400);
    ensure!(initial.1["configurationFilename"] == "rss-agent-enrollment.json");
    for seconds in [0, 604801] {
        let out=user.call(&f.router,Method::PUT,"/api/v1/agent-enrollment-settings",Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":initial.1["revision"],"values":{"grantSeconds":seconds,"configurationDefaultSeconds":86400,"platforms":["windows","macos"]}}))).await?;
        ensure!(out.0 == StatusCode::BAD_REQUEST);
    }
    let update = json!({"operationId":Uuid::new_v4(),"expectedRevision":initial.1["revision"],"values":{"grantSeconds":604800,"configurationDefaultSeconds":86400,"platforms":["windows","macos"]}});
    let updated = user
        .call(
            &f.router,
            Method::PUT,
            "/api/v1/agent-enrollment-settings",
            Some(update.clone()),
        )
        .await?;
    ensure!(updated.0 == StatusCode::OK, "seven day bound {updated:?}");
    ensure!(
        user.call(
            &f.router,
            Method::PUT,
            "/api/v1/agent-enrollment-settings",
            Some(update.clone())
        )
        .await?
        .1 == updated.1
    );
    let mut stale = update;
    stale["operationId"] = json!(Uuid::new_v4());
    ensure!(
        user.call(
            &f.router,
            Method::PUT,
            "/api/v1/agent-enrollment-settings",
            Some(stale)
        )
        .await?
        .0 == StatusCode::CONFLICT
    );
    let file = configuration(&f, &mut user, json!({"kind":"finite","count":2}), Some(5)).await?;
    let input = exchange(&file, &package, 0)?;
    let assigned = machine(&f, "/api/v1/agent/enroll/configurations/exchange", &input).await?;
    ensure!(
        assigned.0 == StatusCode::OK,
        "seven day grant insert {assigned:?}"
    );
    let authority = authority::Authority::open().await?;
    let service = agent::service(&authority).await?;
    let principal = crate::device::test_support::admin(case_tenant(), "admin-a").await?;
    ensure!(
        service.settings(&principal).await?.values.grant_seconds == 604800,
        "restart lost persistent lifetime settings"
    );
    tokio::time::sleep(Duration::from_secs(6)).await;
    ensure!(
        machine(
            &f,
            "/api/v1/agent/enroll/configurations/exchange",
            &exchange(&file, &package, 1)?
        )
        .await?
        .0 == StatusCode::FORBIDDEN
    );
    let candidate=machine(&f,"/api/v1/agent/enroll/certificates",&json!({"wireVersion":1,"operationId":Uuid::new_v4(),"grantId":assigned.1["grantId"],"secret":input.secret,"csr":input.csr,"runtime":input.runtime})).await?;
    ensure!(
        candidate.0 == StatusCode::OK,
        "frozen grant lost authority at file expiry {candidate:?}"
    );
    let ordinary = json!({"wireVersion":1,"operationId":Uuid::new_v4(),"secret":credential("no-client-expiry"),"platform":"macos","csr":STANDARD.encode(std::fs::read(root().join("other.der"))?),"lifetimeSeconds":86400});
    ensure!(
        machine(&f, "/api/v1/agent/enroll/requests", &ordinary)
            .await?
            .0
            == StatusCode::BAD_REQUEST
    );
    for path in [
        "/api/v1/agent-grants",
        "/api/v1/agent-authorization-requests",
    ] {
        ensure!(
            user.call(&f.router, Method::POST, path, Some(ordinary.clone()))
                .await?
                .0
                == StatusCode::NOT_FOUND,
            "old self enrollment route survived"
        );
    }
    let disable = json!({"operationId":Uuid::new_v4(),"expectedRevision":updated.1["revision"],"values":{"grantSeconds":86400,"configurationDefaultSeconds":86400,"platforms":[]}});
    ensure!(
        user.call(
            &f.router,
            Method::PUT,
            "/api/v1/agent-enrollment-settings",
            Some(disable)
        )
        .await?
        .0 == StatusCode::OK
    );
    let mut request = ordinary;
    request.as_object_mut().unwrap().remove("lifetimeSeconds");
    ensure!(
        machine(&f, "/api/v1/agent/enroll/requests", &request)
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    Ok(())
}

#[tokio::test]
#[ignore = "MODULE=agent.configurations: expired unpolled download releases shared Content capacity"]
async fn expired_unpolled_download_releases_capacity() -> Result<()> {
    use futures::StreamExt;
    let f = fixture().await?;
    let mut user = f.user.clone();
    let package = publish(&f, &mut user, true).await?;
    let artifact = rss_mdm_resource::SoftwareArtifact {
        reference: "installer".into(),
        origin: None,
        length: package.length,
        sha256: package.installer_sha256,
    }
    .artifact()?;
    let mut bounded = f.content.as_ref().unwrap().as_ref().clone();
    bounded.config.transfer_seconds = 1;
    let bounded = Arc::new(bounded);
    let file = bounded.verify(&artifact).await?;
    let mut body = file.stream(0, artifact.length()).await?;
    ensure!(body.next().await.transpose()?.is_some());
    ensure!(matches!(
        bounded.verify(&artifact).await,
        Err(rss_mdm_content_service::Error::Conflict)
    ));
    // Leave the response stream alive but do not poll it, as with a stalled HTTP writer.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let next = bounded.verify(&artifact).await?;
    ensure!(next.matches(&artifact));
    ensure!(
        body.next().await.transpose().is_err(),
        "expired body resumed reading"
    );
    drop(next);
    Ok(())
}

#[tokio::test]
#[ignore = "MODULE=agent.configurations: long-lived scope admits new candidates and rejects withdrawn releases"]
async fn configuration_scope_follows_current_candidate_admission() -> Result<()> {
    let f = fixture().await?;
    let mut user = f.user.clone();
    let old = publish(&f, &mut user, true).await?;
    let file = configuration(
        &f,
        &mut user,
        json!({"kind":"finite","count":2}),
        Some(31536000),
    )
    .await?;
    let first = exchange(&file, &old, 0)?;
    let original = machine(&f, "/api/v1/agent/enroll/configurations/exchange", &first).await?;
    ensure!(original.0 == StatusCode::OK);
    let current = publish_version(&f, &mut user, true, "2+enterprise").await?;
    ensure!(current.version != old.version && current.candidate_sha256 != old.candidate_sha256);
    let withdrawn = user
        .call(
            &f.router,
            Method::POST,
            &format!("/api/v1/agent-packages/{}/withdraw", old.release_id),
            Some(json!({"operationId":Uuid::new_v4()})),
        )
        .await?;
    ensure!(withdrawn.0 == StatusCode::NO_CONTENT);
    let anonymous = f
        .client
        .get(format!(
            "{}/api/v1/agent/enroll/packages/{}/content",
            f.origin, old.release_id
        ))
        .header("host", "mdm.example.test:9445")
        .send()
        .await?;
    ensure!(!anonymous.status().is_success());
    ensure!(
        machine(&f, "/api/v1/agent/enroll/configurations/exchange", &first)
            .await?
            .1
            == original.1
    );
    ensure!(
        machine(
            &f,
            "/api/v1/agent/enroll/configurations/exchange",
            &exchange(&file, &old, 1)?
        )
        .await?
        .0 == StatusCode::FORBIDDEN
    );
    ensure!(
        machine(
            &f,
            "/api/v1/agent/enroll/configurations/exchange",
            &exchange(&file, &current, 1)?
        )
        .await?
        .0 == StatusCode::OK
    );
    let state = read(&f, &mut user, file.configuration.configuration_id).await?;
    ensure!(state["reserved"] == 2 && state["consumed"] == 0);
    Ok(())
}
