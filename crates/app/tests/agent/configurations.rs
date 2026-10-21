//! Real HTTP/Postgres publication, signed files and independent mTLS activation.
#![allow(
    clippy::cognitive_complexity,
    reason = "integration matrices preserve independent authority and recovery assertions"
)]
use crate::test_support::*;
use anyhow::Context;
use base64::{Engine, engine::general_purpose::STANDARD};
use rss_mdm_agent_wire::{enroll as w, runtime as r};
use software::Fixture;
use uuid::Uuid;
fn root() -> std::path::PathBuf {
    std::env::var("MDM_AGENT_PKI_FIXTURES").unwrap().into()
}
fn profile(windows: bool) -> Value {
    json!({"capabilities":["inventory.collect.v1"],"platform":if windows{"windows"}else{"macos"},"architecture":if windows{"x86_64"}else{"aarch64"},"executionContext":software_execution::context(if windows{software_execution::Platform::Windows}else{software_execution::Platform::MacOs})})
}
async fn fixture() -> Result<Fixture> {
    fixture_with(&[]).await
}
async fn fixture_with(extra: &[&str]) -> Result<Fixture> {
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
        .chain(extra.iter().copied())
        .map(|name| {
            Ok(crate::authorization::Grant {
                operation: serde_json::from_value(json!(name))?,
                scope: crate::authorization::Scope::Tenant,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    for name in [
        "enrollment",
        "credentials",
        "software_deploy",
        "inventory_read",
    ] {
        grants.push(crate::authorization::Grant {
            operation: serde_json::from_value(json!(name))?,
            scope: crate::authorization::Scope::AllDevices,
        });
    }
    identity::set_grants(case_tenant(), &f.subject, grants).await?;
    Ok(f)
}
async fn publish(
    f: &Fixture,
    user: &mut Browser,
    windows: bool,
) -> Result<w::configuration::Package> {
    publish_version(f, user, windows, "1+enterprise")
        .await
        .map(|(package, _)| package)
}
async fn publish_version(
    f: &Fixture,
    user: &mut Browser,
    windows: bool,
    version: &str,
) -> Result<(w::configuration::Package, Value)> {
    let (platform, architecture, suffix, bytes) = if windows {
        ("windows", "x86_64", "exe", installer_fixtures::exe(version))
    } else {
        ("macos", "aarch64", "pkg", installer_fixtures::pkg(version))
    };
    publish_bytes(
        f,
        user,
        platform,
        architecture,
        suffix,
        Some(version),
        &bytes,
    )
    .await
}
async fn publish_bytes(
    f: &Fixture,
    user: &mut Browser,
    platform: &str,
    architecture: &str,
    suffix: &str,
    version: Option<&str>,
    bytes: &[u8],
) -> Result<(w::configuration::Package, Value)> {
    let id = stage_upload(f, user, suffix, bytes).await?;
    let inspected = user
        .call(
            &f.router,
            Method::GET,
            &format!("/api/v1/agent-packages/uploads/{id}"),
            None,
        )
        .await?;
    ensure!(inspected.0 == StatusCode::OK && inspected.1["facts"]["format"] == suffix);
    if suffix == "exe" {
        ensure!(inspected.1["facts"]["version"].is_null());
    }
    let invalid = json!({"operationId":Uuid::new_v4(),"packageId":id,"version":if suffix == "exe" {Value::Null}else{json!("mismatch")},"target":{"platform":platform,"architecture":architecture}});
    ensure!(
        user.call(
            &f.router,
            Method::POST,
            "/api/v1/agent-packages/save",
            Some(invalid)
        )
        .await?
        .0 == StatusCode::BAD_REQUEST
    );
    let wrong_target = json!({"operationId":Uuid::new_v4(),"packageId":id,"version":version,"target":{"platform":if platform == "windows" {"macos"} else {"windows"},"architecture":architecture}});
    ensure!(
        user.call(
            &f.router,
            Method::POST,
            "/api/v1/agent-packages/save",
            Some(wrong_target)
        )
        .await?
        .0 == StatusCode::BAD_REQUEST
    );
    let input = json!({"operationId":Uuid::new_v4(),"packageId":id,"version":version,"target":{"platform":platform,"architecture":architecture}});
    let saved = user
        .call(
            &f.router,
            Method::POST,
            "/api/v1/agent-packages/save",
            Some(input.clone()),
        )
        .await?;
    ensure!(saved.0 == StatusCode::OK, "save {saved:?}");
    if suffix == "exe" {
        let replay = user
            .call(
                &f.router,
                Method::POST,
                "/api/v1/agent-packages/save",
                Some(input.clone()),
            )
            .await?;
        ensure!(replay == saved, "save replay changed result");
        let receipt = user
            .call(
                &f.router,
                Method::GET,
                &format!(
                    "/api/v1/agent-packages/operations/{}",
                    input["operationId"].as_str().unwrap()
                ),
                None,
            )
            .await?;
        ensure!(receipt == saved, "original save receipt");
        let mut conflict = input;
        conflict["version"] = json!("changed");
        ensure!(
            user.call(
                &f.router,
                Method::POST,
                "/api/v1/agent-packages/save",
                Some(conflict)
            )
            .await?
            .0 == StatusCode::CONFLICT
        );
    }
    let publication = json!({"operationId":Uuid::new_v4(),"packageId":id});
    let response = user
        .call(
            &f.router,
            Method::POST,
            "/api/v1/agent-packages",
            Some(publication.clone()),
        )
        .await?;
    ensure!(response.0 == StatusCode::OK, "publish {response:?}");
    let receipt = user
        .call(
            &f.router,
            Method::GET,
            &format!(
                "/api/v1/agent-packages/operations/{}",
                publication["operationId"].as_str().unwrap()
            ),
            None,
        )
        .await?;
    ensure!(receipt == response, "publication operation recovery");
    let package: w::configuration::Package = serde_json::from_value(response.1)?;
    ensure!(package.installer_sha256 == rss_mdm_resource::Digest::of(bytes).bytes());
    Ok((package, publication))
}
async fn stage_upload(f: &Fixture, user: &mut Browser, suffix: &str, bytes: &[u8]) -> Result<Uuid> {
    let id = Uuid::new_v4();
    let begin = json!({"operationId":id,"filename":format!("agent.{suffix}"),"length":bytes.len(),"sha256":rss_mdm_resource::Digest::of(bytes).bytes()});
    let response = user
        .call(
            &f.router,
            Method::POST,
            "/api/v1/agent-packages/uploads",
            Some(begin.clone()),
        )
        .await?;
    ensure!(response.0 == StatusCode::OK, "prepare {response:?}");
    let id: Uuid = serde_json::from_value(response.1["packageId"].clone())?;
    let upload_href = response.1["href"].as_str().context("upload href")?;
    if suffix == "exe" {
        ensure!(
            user.call(
                &f.router,
                Method::POST,
                "/api/v1/agent-packages/uploads",
                Some(begin.clone())
            )
            .await?
                == response
        );
        let mut conflict = begin;
        conflict["length"] = json!(bytes.len() + 1);
        ensure!(
            user.call(
                &f.router,
                Method::POST,
                "/api/v1/agent-packages/uploads",
                Some(conflict)
            )
            .await?
            .0 == StatusCode::CONFLICT
        );
    }
    let cookie = user
        .cookies
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("; ");
    let session = format!("{}{upload_href}", f.origin);
    let request = |method, url: &str| {
        f.client
            .request(method, url)
            .header("host", "mdm.example.test")
            .header("origin", "https://mdm.example.test")
            .header("x-identity-request", "1")
            .header("x-csrf-token", user.csrf.as_ref().unwrap())
            .header("cookie", &cookie)
            .header("content-type", "application/octet-stream")
    };
    let half = if suffix == "exe" { bytes.len() / 2 } else { 0 };
    if half > 0 {
        let first = request(Method::PATCH, &format!("{session}?offset=0"))
            .body(bytes[..half].to_vec())
            .send()
            .await?;
        ensure!(
            first.status() == StatusCode::OK,
            "first chunk {}",
            first.text().await?
        );
        let resumed: Value = request(Method::GET, &session).send().await?.json().await?;
        ensure!(resumed["offset"] == half);
        let stale = request(Method::PATCH, &format!("{session}?offset=0"))
            .body(vec![0])
            .send()
            .await?;
        ensure!(stale.status() == StatusCode::CONFLICT);
    }
    let uploaded = request(Method::PATCH, &format!("{session}?offset={half}"))
        .body(bytes[half..].to_vec())
        .send()
        .await?;
    ensure!(
        uploaded.status() == StatusCode::OK,
        "upload {}",
        uploaded.text().await?
    );
    let completed = request(Method::POST, &format!("{session}/complete"))
        .send()
        .await?;
    ensure!(
        completed.status() == StatusCode::CREATED,
        "complete {}",
        completed.text().await?
    );
    Ok(id)
}
async fn configuration(
    f: &Fixture,
    user: &mut Browser,
    quantity: Value,
    lifetime: Option<u32>,
) -> Result<(w::configuration::ConfigurationFile, Value)> {
    let mut input = json!({"operationId":Uuid::new_v4(),"secret":credential(&Uuid::new_v4().to_string()),"quantity":quantity,"targets":[{"platform":"windows","architecture":"x86_64"},{"platform":"macos","architecture":"aarch64"}]});
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
    let file = serde_json::from_value(response.1)?;
    Ok((file, input))
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
#[tokio::test]
#[ignore = "MODULE=agent.configurations: four independent peers, explicit quota and representative mTLS HTTP"]
async fn fixed_packages_and_configurations_activate_beyond_self_quota() -> Result<()> {
    let f = fixture_with(&[
        "registration_configuration_read",
        "registration_configuration_write",
        "policy_read",
        "policy_write",
        "scope_read",
        "scope_write",
    ])
    .await?;
    let mut user = f.user.clone();
    let windows = publish(&f, &mut user, true).await?;
    let settings = user
        .call(&f.router, Method::GET, "/api/v1/settings/catalog", None)
        .await?;
    ensure!(settings.0 == StatusCode::OK);
    let capability = settings.1["items"]
        .as_array()
        .context("settings items")?
        .iter()
        .find(|item| item["id"] == "agent-package")
        .context("package capability")?;
    ensure!(
        capability["status"] == "configured"
            && capability["configuredCount"] == 1
            && capability["lifecycle"] == "business_configuration",
        "single package projection {capability:?}"
    );
    let path = "/api/v1/settings/first-use";
    let initial = user.call(&f.router, Method::GET, path, None).await?;
    ensure!(initial.0 == StatusCode::OK);
    let previous = user.operation.replace(Uuid::new_v4());
    let selected = user.call(&f.router, Method::PUT, path, Some(json!({"expectedRevision":initial.1["saved"]["revision"],"intent":{"channels":["agent"],"capabilities":{"agent_package":{"kind":"configure"}},"completionRequested":false}}))).await?;
    user.operation = previous;
    ensure!(
        selected.0 == StatusCode::OK,
        "first use selection {selected:?}"
    );
    let progress = user.call(&f.router, Method::GET, path, None).await?;
    ensure!(progress.0 == StatusCode::OK);
    let step = progress.1["steps"]
        .as_array()
        .context("first use steps")?
        .iter()
        .find(|step| step["id"] == "agent_package")
        .context("package readiness")?;
    ensure!(
        step["status"] == "ready",
        "single package first use {step:?}"
    );

    let macos = publish(&f, &mut user, false).await?;
    let mut authority = authority::Authority::open().await?;
    let authority_resources = std::mem::take(&mut authority.resources);
    authority_resources.finish(async {
    let quota_router = authority.router(authority.enrollment())?;
    let mut quota_admin = authority.browser("admin")?;
    let defaults = quota_admin.call(&quota_router, Method::GET, "/api/v1/registration-quotas/defaults", None).await?;
    ensure!(defaults.0 == StatusCode::OK);
    quota_admin.operation = Some(Uuid::new_v4());
    let updated = quota_admin.call(&quota_router, Method::PUT, "/api/v1/registration-quotas/defaults", Some(json!({"expectedRevision":defaults.1["revision"],"limits":{"agent":1,"windows_mdm":20,"macos_mdm":20}}))).await?;
    ensure!(updated.0 == StatusCode::OK && updated.1["limits"]["agent"] == 1);
    let (file, _) = configuration(&f, &mut user, json!({"kind":"finite","count":2}), None).await?;
    let (unlimited, _) = configuration(&f, &mut user, json!({"kind":"unlimited"}), None).await?;
    let tls = Tls::start(&authority).await?;
    let mut devices = std::collections::BTreeSet::new();
    for (index, config) in [&file, &unlimited].into_iter().enumerate() {
        for (offset, package) in [&windows, &macos].into_iter().enumerate() {
            ensure!(devices.insert(enroll(&f, &tls, config, package, index * 2 + offset).await?));
        }
        let state = read(&f, &mut user, config.configuration.configuration_id).await?;
        ensure!(state["reserved"] == 0 && state["consumed"] == 2);
    }
    ensure!(devices.len() == 4);
    // A published material-only release cannot freeze an installation operation.
    let scope = Uuid::new_v4();
    software::write(&mut user, &f.router, &format!("/api/v1/scopes/{scope}"), 0, json!({"action":"put","definition":{"targets":[{"kind":"device","id":devices.first().unwrap()}],"limitations":null,"exclusions":[]}})).await?;
    let policy = user.call(&f.router, Method::POST, &format!("/api/v1/policies/{}",Uuid::new_v4()), Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":{"scope":scope,"action":{"kind":"ensure_agent_installed","packages":{"windows_x86_64":windows.release_id},"runLifetimeSeconds":3600}}}}))).await?;
    ensure!(
        policy.0 == StatusCode::NOT_IMPLEMENTED && policy.1["code"] == "action_not_supported",
        "material-only task: {policy:?}"
    );

    ensure!(machine(&f, "/api/v1/agent/enroll/configurations/exchange", &exchange(&file, &macos, 2)?).await?.0 == StatusCode::TOO_MANY_REQUESTS);
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
        live == 4,
        "configuration revoke deactivated existing devices"
    );
    ensure!(tls.owner.shutdown().join().await?.is_clean());
    Ok(())

    }).await
}
#[tokio::test]
#[ignore = "MODULE=agent.configurations: concurrent finite allocation, cancellation, revoke and frozen TTL"]
async fn finite_reservations_and_frozen_authority_survive_revoke() -> Result<()> {
    let f = fixture().await?;
    let mut user = f.user.clone();
    let package = publish(&f, &mut user, false).await?;
    let (file, _) = configuration(&f, &mut user, json!({"kind":"finite","count":2}), None).await?;
    let mut other = authority::Authority::prepared_browser("other").await?;
    ensure!(other.call(&f.router,Method::POST,"/api/v1/agent-configurations",Some(json!({"operationId":Uuid::new_v4(),"secret":credential("forbidden"),"quantity":{"kind":"unlimited"},"targets":[{"platform":"macos","architecture":"aarch64"}]}))).await?.0==StatusCode::FORBIDDEN);
    for quantity in [
        json!({"kind":"finite","count":0}),
        json!({"kind":"finite","count":-1}),
    ] {
        ensure!(user.call(&f.router,Method::POST,"/api/v1/agent-configurations",Some(json!({"operationId":Uuid::new_v4(),"secret":credential("invalid-count"),"quantity":quantity,"targets":[{"platform":"macos","architecture":"aarch64"}]}))).await?.0==StatusCode::BAD_REQUEST);
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
    bad.installation.release_id = Uuid::new_v4();
    ensure!(
        machine(&f, "/api/v1/agent/enroll/configurations/exchange", &bad)
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    let inputs = (0..4)
        .map(|n| exchange(&file, &package, n))
        .collect::<Result<Vec<_>>>()?;
    use sqlx::Connection;
    let mut owner =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    let mut hold = owner.begin().await?;
    sqlx::query("SELECT id FROM mdm_access.agent_configurations WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE").bind(case_tenant()).bind(file.configuration.configuration_id).fetch_one(&mut *hold).await?;
    let release = async {
        let observed = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let blocked: i64 = sqlx::query_scalar("WITH RECURSIVE blocked(pid) AS (SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND pg_backend_pid()=ANY(pg_blocking_pids(pid)) UNION SELECT a.pid FROM pg_stat_activity a JOIN blocked b ON b.pid=ANY(pg_blocking_pids(a.pid)) WHERE a.datname=current_database()) SELECT count(*) FROM blocked").fetch_one(&mut *hold).await?;
                if blocked >= 4 { return Ok::<_, sqlx::Error>(()); }
                sqlx::query("SELECT pg_stat_clear_snapshot()").execute(&mut *hold).await?;
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }).await;
        hold.rollback().await?;
        observed??;
        Ok::<_, anyhow::Error>(())
    };
    let (replies, released) = tokio::join!(
        futures::future::join_all(inputs.iter().map(|input| machine(
            &f,
            "/api/v1/agent/enroll/configurations/exchange",
            input
        ))),
        release
    );
    released?;
    owner.close().await?;
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
    let mut authority = authority::Authority::open().await?;
    let authority_resources = std::mem::take(&mut authority.resources);
    authority_resources
        .finish(async {
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
        })
        .await
}
#[tokio::test]
#[ignore = "MODULE=agent.configurations: HTTP lost commits, permanent issuance accounting and lookup"]
async fn unknown_exchange_and_issuance_do_not_reset_quantity() -> Result<()> {
    let f = fixture().await?;
    let mut user = f.user.clone();
    let package = publish(&f, &mut user, false).await?;
    let (file, _) = configuration(&f, &mut user, json!({"kind":"finite","count":1}), None).await?;
    let mut authority = authority::Authority::open().await?;
    let authority_resources = std::mem::take(&mut authority.resources);
    authority_resources.finish(async {
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
    ensure!(pg(&format!("SELECT count(*) FROM mdm_access.agent_issuances WHERE tenant_id='{}' AND grant_id='{}'", case_tenant(), status.1["grantId"].as_str().unwrap()))?.trim() == "1");

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

    }).await
}
#[tokio::test]
#[ignore = "MODULE=agent.configurations: first claim waits across grant expiry before a slot is reused"]
async fn expired_reservation_cannot_be_consumed_after_configuration_lock_wait() -> Result<()> {
    use sqlx::Connection;
    let f = fixture().await?;
    let mut user = f.user.clone();
    let package = publish(&f, &mut user, false).await?;
    let (file, _) = configuration(&f, &mut user, json!({"kind":"finite","count":1}), None).await?;
    let input = exchange(&file, &package, 0)?;
    let (status, grant) =
        machine(&f, "/api/v1/agent/enroll/configurations/exchange", &input).await?;
    ensure!(status == StatusCode::OK);
    let mut owner =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    sqlx::query("UPDATE mdm_access.agent_grants SET created_at=clock_timestamp()-interval '1 hour',expires_at=clock_timestamp()+interval '2 seconds' WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(case_tenant()).bind(grant["grantId"].as_str().unwrap()).execute(&mut owner).await?;
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
    let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await?;
    let observed = tokio::time::timeout(Duration::from_secs(3),async {
  loop {let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND usename='mdm_access' AND wait_event_type='Lock' AND query LIKE '%agent_configurations%' AND $1=ANY(pg_blocking_pids(pid)))").bind(blocker_pid).fetch_one(&observer).await?;if waiting{break;}tokio::time::sleep(Duration::from_millis(10)).await;}
  Ok::<_,sqlx::Error>(())
 }).await;
    if observed.is_err() || observed.as_ref().is_ok_and(|result| result.is_err()) {
        blocker.rollback().await?;
        issue.await??;
        observed??;
        unreachable!();
    }
    let next = exchange(&file, &package, 1)?;
    let allocation = machine(&f, "/api/v1/agent/enroll/configurations/exchange", &next);
    tokio::pin!(allocation);
    let delayed = async {
        let expired = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let expired: bool = sqlx::query_scalar("SELECT expires_at<=clock_timestamp() FROM mdm_access.agent_grants WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(case_tenant()).bind(grant["grantId"].as_str().unwrap()).fetch_one(&observer).await?;
                if expired { return Ok::<_, sqlx::Error>(()); }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }).await;
        blocker.commit().await?;
        expired??;
        Ok::<_, anyhow::Error>(())
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
    for seconds in [0] {
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
    let (file, _) =
        configuration(&f, &mut user, json!({"kind":"finite","count":2}), Some(5)).await?;
    let operation = pg(&format!(
        "SELECT operation_id::text FROM mdm_access.agent_configurations WHERE tenant_id='{}' AND id='{}'",
        case_tenant(),
        file.configuration.configuration_id
    ))?;
    let path = format!(
        "/api/v1/agent-configuration-operations/{}",
        operation.trim()
    );
    let found = user.call(&f.router, Method::GET, &path, None).await?;
    ensure!(
        found.0 == StatusCode::OK
            && found.1["configuration"] == serde_json::to_value(&file.configuration)?
            && found.1["remaining"] == 2
    );
    ensure!(found.1.get("secret").is_none() && found.1.get("signature").is_none());
    let mut other = authority::Authority::prepared_browser("other").await?;
    ensure!(other.call(&f.router, Method::GET, &path, None).await?.0 == StatusCode::FORBIDDEN);
    ensure!(
        user.call(
            &f.router,
            Method::GET,
            &format!("/api/v1/agent-configuration-operations/{}", Uuid::new_v4()),
            None
        )
        .await?
            == (StatusCode::OK, Value::Null)
    );
    let input = exchange(&file, &package, 0)?;
    let assigned = machine(&f, "/api/v1/agent/enroll/configurations/exchange", &input).await?;
    ensure!(
        assigned.0 == StatusCode::OK,
        "seven day grant insert {assigned:?}"
    );
    let grant_times = pg(&format!(
        "SELECT jsonb_build_array(extract(epoch FROM expires_at-created_at),floor(extract(epoch FROM expires_at))::bigint)::text FROM mdm_access.agent_grants WHERE tenant_id='{}' AND id='{}'",
        case_tenant(),
        assigned.1["grantId"].as_str().unwrap()
    ))?;
    let grant_times: Value = serde_json::from_str(&grant_times)?;
    ensure!((grant_times[0].as_f64().unwrap() - 604800.0).abs() < 1.0);
    ensure!(
        assigned.1["expiresAt"] == grant_times[1]
            && assigned.1["expiresAt"] != json!(file.configuration.expires_at)
    );
    let mut authority = authority::Authority::open().await?;
    let authority_resources = std::mem::take(&mut authority.resources);
    authority_resources.finish(async {
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

    }).await
}

#[tokio::test]
#[ignore = "MODULE=agent.configurations: long-lived scope admits new candidates and rejects withdrawn releases"]
async fn configuration_scope_follows_current_candidate_admission() -> Result<()> {
    let f = fixture().await?;
    let mut user = f.user.clone();
    let bad = stage_upload(&f, &mut user, "msi", b"broken").await?;
    ensure!(
        user.call(
            &f.router,
            Method::GET,
            &format!("/api/v1/agent-packages/uploads/{bad}"),
            None
        )
        .await?
        .0 == StatusCode::BAD_REQUEST
    );
    ensure!(user.call(&f.router, Method::POST, "/api/v1/agent-packages/save", Some(json!({"operationId":Uuid::new_v4(),"packageId":bad,"version":"1","target":{"platform":"windows","architecture":"x86_64"}}))).await?.0 == StatusCode::BAD_REQUEST);
    let unknown = user
        .call(
            &f.router,
            Method::GET,
            &format!("/api/v1/agent-packages/operations/{}", Uuid::new_v4()),
            None,
        )
        .await?;
    ensure!(unknown == (StatusCode::OK, Value::Null));
    let old = publish(&f, &mut user, true).await?;
    let (file, configuration_input) = configuration(
        &f,
        &mut user,
        json!({"kind":"finite","count":2}),
        Some(31536000),
    )
    .await?;
    let first = exchange(&file, &old, 0)?;
    let original = machine(&f, "/api/v1/agent/enroll/configurations/exchange", &first).await?;
    ensure!(original.0 == StatusCode::OK);
    let (current, publication_input) = publish_version(&f, &mut user, true, "2+enterprise").await?;
    ensure!(current.version != old.version && current.installer_sha256 != old.installer_sha256);
    let mut anonymous = Browser::default();
    let catalogue = anonymous
        .call(
            &f.router,
            Method::GET,
            "/api/v1/public-agent/packages",
            None,
        )
        .await?;
    ensure!(
        catalogue.0 == StatusCode::OK
            && catalogue.1.as_array().is_some_and(|items| items
                .iter()
                .any(|item| item["releaseId"] == current.release_id.to_string()))
    );
    ensure!(
        anonymous
            .call(
                &f.router,
                Method::POST,
                "/api/v1/public-agent/packages",
                Some(json!({}))
            )
            .await?
            .0
            == StatusCode::METHOD_NOT_ALLOWED
    );
    // These are the representative creation-replay checks; ordinary preparation
    // only creates the material required by each scenario.
    let count_sql = format!(
        "SELECT jsonb_build_array((SELECT count(*) FROM mdm_agent_packages.releases WHERE tenant_id='{tenant}'),(SELECT count(*) FROM mdm_access.agent_configurations WHERE tenant_id='{tenant}'))::text",
        tenant = case_tenant()
    );
    let counts = pg(&count_sql)?;
    ensure!(serde_json::from_str::<Value>(&counts)? == json!([2, 1]));
    let replay = user
        .call(
            &f.router,
            Method::POST,
            "/api/v1/agent-packages",
            Some(publication_input),
        )
        .await?;
    ensure!(replay == (StatusCode::OK, serde_json::to_value(&current)?));
    let replay = user
        .call(
            &f.router,
            Method::POST,
            "/api/v1/agent-configurations",
            Some(configuration_input),
        )
        .await?;
    ensure!(replay == (StatusCode::OK, serde_json::to_value(&file)?));
    ensure!(
        pg(&count_sql)? == counts,
        "creation replay inserted another record"
    );
    let download = f
        .client
        .get(format!(
            "{}/api/v1/agent/enroll/packages/{}/content",
            f.origin, old.release_id
        ))
        .header("host", "mdm.example.test:9445")
        .header("range", "bytes=0-4")
        .send()
        .await?;
    ensure!(download.status() == StatusCode::PARTIAL_CONTENT);
    ensure!(download.bytes().await?.as_ref() == &installer_fixtures::exe("1+enterprise")[..5]);

    let withdrawal_operation = Uuid::new_v4();
    let withdrawn = user
        .call(
            &f.router,
            Method::POST,
            &format!("/api/v1/agent-packages/{}/withdraw", old.release_id),
            Some(json!({"operationId":withdrawal_operation})),
        )
        .await?;
    ensure!(withdrawn.0 == StatusCode::NO_CONTENT);
    let receipt = user
        .call(
            &f.router,
            Method::GET,
            &format!("/api/v1/agent-packages/operations/{withdrawal_operation}"),
            None,
        )
        .await?;
    ensure!(receipt == (StatusCode::OK, json!({"withdrawn":old.release_id})));
    let anonymous = f
        .client
        .get(format!(
            "{}/api/v1/agent/enroll/packages/{}/content",
            f.origin, old.release_id
        ))
        .header("host", "mdm.example.test:9445")
        .send()
        .await?;
    ensure!(anonymous.status() == StatusCode::NOT_FOUND);
    ensure!(anonymous.json::<Value>().await? == json!({"code":"resource_not_found"}));
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
    // The publication owner proves native format acceptance once; OS execution belongs elsewhere.
    for (platform, arch, suffix, version, bytes) in [
        (
            "windows",
            "aarch64",
            "msi",
            "1.2.3",
            installer_fixtures::msi(Some("1.2.3"), true),
        ),
        (
            "windows",
            "x86_64",
            "msix",
            "1.2.3.0",
            installer_fixtures::msix("1.2.3.0", false),
        ),
        (
            "macos",
            "x86_64",
            "pkg",
            "1.2.3",
            installer_fixtures::pkg("1.2.3"),
        ),
        (
            "macos",
            "aarch64",
            "pkg",
            "1.2.4",
            installer_fixtures::pkg("1.2.4"),
        ),
    ] {
        let (package, _) =
            publish_bytes(&f, &mut user, platform, arch, suffix, None, &bytes).await?;
        ensure!(package.version == version);
        let download = f
            .client
            .get(format!(
                "{}/api/v1/agent/enroll/packages/{}/content",
                f.origin, package.release_id
            ))
            .header("host", "mdm.example.test:9445")
            .send()
            .await?;
        ensure!(download.status() == StatusCode::OK);
        ensure!(download.bytes().await?.as_ref() == bytes.as_slice());
    }
    Ok(())
}
