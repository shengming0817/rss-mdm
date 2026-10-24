//! Real HTTP/Postgres publication, signed files and independent mTLS activation.
#![allow(
    clippy::cognitive_complexity,
    reason = "integration matrices preserve independent authority and recovery assertions"
)]
use crate::test_support::{http::*, process::*, runtime::*, *};
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
    // Installer consumers need a current signed configuration; deployment/publication is a separate journey.
    let base: Value = serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
    let access = database(&base).await?;
    let mut tx = access.archive_pool().begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(case_tenant())
        .execute(&mut *tx)
        .await?;
    rss_mdm_registration_service::agent::connections::fixture_configuration_on(
        &mut tx,
        Uuid::parse_str(case_tenant())?,
        crate::test_support::identity::config(case_tenant())?
            .native_protector()?
            .as_ref(),
        "https://mdm.example.test:9445",
    )
    .await?;
    tx.commit().await?;
    access.close().await;

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
async fn save_bytes(
    f: &Fixture,
    user: &mut Browser,
    platform: &str,
    architecture: &str,
    suffix: &str,
    version: Option<&str>,
    bytes: &[u8],
) -> Result<Uuid> {
    let id = stage_upload(f, user, suffix, bytes).await?;
    let inspected = user
        .call(
            &f.router,
            Method::GET,
            &format!("/api/v1/agent-packages/uploads/{id}"),
            None,
        )
        .await?;
    ensure!(
        inspected.0 == StatusCode::OK
            && inspected.1["format"] == suffix
            && inspected.1["inspection"]["status"] == "parsed"
    );
    if suffix == "exe" {
        ensure!(inspected.1["inspection"]["facts"]["version"].is_null());
    }
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
    Ok(id)
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
    let id = save_bytes(f, user, platform, architecture, suffix, version, bytes).await?;
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
async fn assert_configuration_metadata(f: &Fixture, user: &mut Browser, id: Uuid) -> Result<()> {
    let detail = read(f, user, id).await?;
    let (status, page) = user
        .call(
            &f.router,
            Method::GET,
            &format!("/api/v1/agent-configurations?filter=configurationId=={id}"),
            None,
        )
        .await?;
    ensure!(status == StatusCode::OK, "configuration metadata: {page}");
    let rows = page["items"].as_array().unwrap();
    ensure!(rows.len() == 1);
    let row = &rows[0];
    ensure!(
        row["configurationId"] == id.to_string()
            && row["state"] == detail["state"]
            && row["remaining"] == detail["remaining"]
            && row["reserved"] == detail["reserved"]
            && row["consumed"] == detail["consumed"]
    );
    for forbidden in [
        "secret",
        "secretDigest",
        "signature",
        "document",
        "configuration",
        "connections",
        "requestDigest",
    ] {
        ensure!(row.get(forbidden).is_none(), "metadata exposed {forbidden}");
    }
    Ok(())
}
struct Tls {
    address: std::net::SocketAddr,
    owner: rss_runtime::ShutdownStack,
}
impl Tls {
    async fn start(authority: &authority::Authority) -> Result<Self> {
        Self::at_origin(
            authority,
            authority.base["agent_pki"]["endpoint"]["origin"]
                .as_str()
                .context("fixture Agent origin")?,
        )
        .await
    }
    async fn at_origin(authority: &authority::Authority, origin: &str) -> Result<Self> {
        let service = agent::service(authority).await?;
        let envelope = rss_mdm_agent_channel::boundary::Envelope {
            admission: Arc::new(tokio::sync::Semaphore::new(32)),
            host: origin.trim_start_matches("https://").into(),
            clock: monotonic(),
            audit_store: authority.audit.clone(),
            requests: Arc::new(tokio::sync::Semaphore::new(4)),
            tenant: case_tenant().into(),
        };
        let router = Router::new().nest(
            "/api/v1/agent/enroll",
            crate::agent::enroll::router(service.clone(), envelope).into_axum(),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let tls = crate::native::ChannelRouter {
            origins: vec![origin.into()],
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
        let internal = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let internal_address = internal.local_addr()?;
        let router = crate::native::gateway::router(
            Router::new(),
            vec![(crate::native::ChannelKind::Agent, tls)],
            "https://mdm.example.test".into(),
            Some(service),
        );
        {
            let mut startup = owner.startup()?;
            startup.stage_task_with_token(rss_axum::serve_http1_registration(
                internal,
                router,
                crate::native::gateway::Transport {
                    gateway: "127.0.0.1".parse()?,
                },
                "configuration-internal-http",
                crate::lifecycle::http_policy(),
            ));
            startup.stage_task_with_token(crate::test_support::gateway::proxy(
                listener,
                internal_address,
                root(),
                origin.into(),
                "agent-tls.pk8",
            )?);
        }
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
    let package_query = "/api/v1/agent-packages?sort=version&fields=releaseId&limit=1";
    let first = user
        .call(&f.router, Method::GET, package_query, None)
        .await?;
    ensure!(first.0 == StatusCode::OK, "package page: {first:?}");
    let next = first.1["nextCursor"].as_str().unwrap();
    let last = user
        .call(
            &f.router,
            Method::GET,
            &format!("{package_query}&cursor={next}"),
            None,
        )
        .await?;
    ensure!(last.0 == StatusCode::OK && last.1["nextCursor"].is_null());
    let found = std::collections::BTreeSet::from([
        first.1["items"][0]["releaseId"].as_str().unwrap(),
        last.1["items"][0]["releaseId"].as_str().unwrap(),
    ]);
    let expected = [windows.release_id.to_string(), macos.release_id.to_string()];
    ensure!(found == expected.iter().map(String::as_str).collect());

    let (msix, _) = publish_bytes(
        &f,
        &mut user,
        "windows",
        "x86_64",
        "msix",
        Some("2.3.4.5"),
        &installer_fixtures::msix("2.3.4.5", false),
    )
    .await?;
    let filtered = user
        .call(
            &f.router,
            Method::GET,
            "/api/v1/agent-packages?filter=format==windows_msix&fields=releaseId,format",
            None,
        )
        .await?;
    ensure!(
        filtered.0 == StatusCode::OK
            && filtered.1["items"]
                == json!([{"releaseId":msix.release_id,"format":"windows_msix"}])
    );
    let base = "/api/v1/agent-packages?sort=-format&fields=releaseId,format&limit=1";
    let first = user.call(&f.router, Method::GET, base, None).await?;
    ensure!(
        first.0 == StatusCode::OK
            && first.1["items"][0]["releaseId"] == msix.release_id.to_string(),
        "MSIX order: {first:?}"
    );
    let cursor = first.1["nextCursor"]
        .as_str()
        .context("MSIX continuation")?;
    let second = user
        .call(
            &f.router,
            Method::GET,
            &format!("{base}&cursor={cursor}"),
            None,
        )
        .await?;
    ensure!(second.0 == StatusCode::OK && second.1["items"][0]["format"] == "windows_exe");
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
    assert_configuration_metadata(&f,&mut user,file.configuration.configuration_id).await?;
    let query="/api/v1/agent-configurations?filter=platform==windows&sort=createdAt&fields=configurationId,state&limit=1";
    let first=user.call(&f.router,Method::GET,query,None).await?;ensure!(first.0==StatusCode::OK,"first configurations: {first:?}");
    let cursor=first.1["nextCursor"].as_str().context("configuration next cursor")?;
    let last=user.call(&f.router,Method::GET,&format!("{query}&cursor={cursor}"),None).await?;ensure!(last.0==StatusCode::OK,"last configurations: {last:?}");
    let found=std::collections::BTreeSet::from([first.1["items"][0]["configurationId"].as_str().unwrap(),last.1["items"][0]["configurationId"].as_str().unwrap()]);
    let expected=[file.configuration.configuration_id.to_string(),unlimited.configuration.configuration_id.to_string()];
    ensure!(found==expected.iter().map(String::as_str).collect()&&last.1["nextCursor"].is_null());
    ensure!(first.1["items"][0].get("createdAt").is_none());
    for invalid in ["fields=secret","filter=signature==x","sort=platform","after=1"]{ensure!(user.call(&f.router,Method::GET,&format!("/api/v1/agent-configurations?{invalid}"),None).await?.0==StatusCode::BAD_REQUEST);}
    ensure!(user.call(&f.router,Method::GET,&format!("{}&cursor={cursor}",query.replace("platform==windows","platform==macos")),None).await?.0==StatusCode::CONFLICT);

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
    let live:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND channel='agent' AND state='active'").bind(case_tenant()).fetch_one(&mut *{let mut tx = authority.pool.begin().await?; crate::Database::configure_transaction(&mut tx, case_tenant()).await?; tx}).await?;
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
    let mut other = authority::Authority::prepared_browser("other")?;
    ensure!(
        other
            .call(&f.router, Method::GET, "/api/v1/agent-configurations", None)
            .await?
            .0
            == StatusCode::FORBIDDEN
    );

    ensure!(other.call(&f.router,Method::POST,"/api/v1/agent-configurations",Some(json!({"operationId":Uuid::new_v4(),"secret":credential("forbidden"),"quantity":{"kind":"unlimited"},"targets":[{"platform":"macos","architecture":"aarch64"}]}))).await?.0==StatusCode::FORBIDDEN);
    for quantity in [
        json!({"kind":"finite","count":0}),
        json!({"kind":"finite","count":-1}),
    ] {
        ensure!(user.call(&f.router,Method::POST,"/api/v1/agent-configurations",Some(json!({"operationId":Uuid::new_v4(),"secret":credential("invalid-count"),"quantity":quantity,"targets":[{"platform":"macos","architecture":"aarch64"}]}))).await?.0==StatusCode::BAD_REQUEST);
    }
    let mut bad = exchange(&file, &package, 0)?;
    bad.file
        .configuration
        .connections
        .configuration
        .preferred_origin = "https://untrusted.example".into();
    bad.file.configuration.connections.configuration.origins =
        vec!["https://untrusted.example".into()];
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
        .inject_next_fault(rss_transactional_messaging_postgres::PgTransactionFault::CommitPending);
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
        .inject_next_fault(rss_transactional_messaging_postgres::PgTransactionFault::CommitUnknownAfterAck);
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
        .inject_next_fault(rss_transactional_messaging_postgres::PgTransactionFault::CommitUnknownAfterAck);
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
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(case_tenant())
        .execute(&mut owner)
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
    let mut other = authority::Authority::prepared_browser("other")?;
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
    ensure!(grant_times[0].as_f64() == Some(604800.0));
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
            "/api/v1/agent/enroll/packages",
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
                "/api/v1/agent/enroll/packages",
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
    let managed = user
        .call(
            &f.router,
            Method::GET,
            &format!("/api/v1/agent-packages/{}", old.release_id),
            None,
        )
        .await?;
    ensure!(managed.0 == StatusCode::OK && managed.1["state"] == "withdrawn");
    let withdrawn_page=user.call(&f.router,Method::GET,"/api/v1/agent-packages?filter=state==withdrawn&sort=version&fields=releaseId,state&limit=1",None).await?;
    ensure!(
        withdrawn_page.0 == StatusCode::OK
            && withdrawn_page.1["items"]
                == json!([{"releaseId":old.release_id,"state":"withdrawn"}])
    );

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
            installer_fixtures::pkgbuild(),
        ),
        (
            "macos",
            "aarch64",
            "pkg",
            "1.2.3",
            installer_fixtures::productbuild(),
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

#[tokio::test]
#[ignore = "MODULE=agent.configurations: native ARM64 EXE explicit enable, publish, replay and immutable download"]
async fn arm64_exe_explicit_enable_preserves_publication_binding() -> Result<()> {
    let f = fixture().await?;
    let mut user = f.user.clone();
    let bytes = installer_fixtures::exe_machine("8+enterprise", 0xaa64);
    let id = save_bytes(
        &f,
        &mut user,
        "windows",
        "aarch64",
        "exe",
        Some("8+enterprise"),
        &bytes,
    )
    .await?;
    let enabled=user.call(&f.router,Method::POST,&format!("/api/v1/software/resources/{id}/versions/v1"),
        Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"enable"}}))).await?;
    ensure!(enabled.0 == StatusCode::OK, "explicit enable {enabled:?}");
    let input = json!({"operationId":Uuid::new_v4(),"packageId":id});
    let result = user
        .call(
            &f.router,
            Method::POST,
            "/api/v1/agent-packages",
            Some(input.clone()),
        )
        .await?;
    ensure!(result.0 == StatusCode::OK, "ARM64 publication {result:?}");
    ensure!(
        user.call(
            &f.router,
            Method::POST,
            "/api/v1/agent-packages",
            Some(input.clone())
        )
        .await?
            == result
    );
    let package: w::configuration::Package = serde_json::from_value(result.1)?;
    ensure!(
        package.target.architecture == r::TaskArchitecture::Aarch64
            && package.format == w::configuration::InstallerFormat::WindowsExe
    );
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
    Ok(())
}

#[tokio::test]
#[ignore = "MODULE=agent.configurations: publication business identity survives concurrency, reupload and withdrawal"]
async fn agent_publication_business_identity_is_unique() -> Result<()> {
    let f = fixture().await?;
    let mut author = f.user.clone();
    let bytes = installer_fixtures::exe("7+enterprise");
    let first = save_bytes(
        &f,
        &mut author,
        "windows",
        "x86_64",
        "exe",
        Some("7+enterprise"),
        &bytes,
    )
    .await?;
    let second = save_bytes(
        &f,
        &mut author,
        "windows",
        "x86_64",
        "exe",
        Some("7+enterprise"),
        &bytes,
    )
    .await?;
    let left = json!({"operationId":Uuid::new_v4(),"packageId":first});
    let right = json!({"operationId":Uuid::new_v4(),"packageId":second});
    let mut a = author.clone();
    let mut b = author.clone();
    let (a, b) = tokio::join!(
        a.call(
            &f.router,
            Method::POST,
            "/api/v1/agent-packages",
            Some(left.clone())
        ),
        b.call(
            &f.router,
            Method::POST,
            "/api/v1/agent-packages",
            Some(right.clone())
        )
    );
    let a = a?;
    let b = b?;
    ensure!(
        a.0 == StatusCode::OK && a == b,
        "competing publications: {a:?}, {b:?}"
    );
    let package: w::configuration::Package = serde_json::from_value(a.1.clone())?;
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_agent_packages.releases WHERE tenant_id='{}'",
            case_tenant()
        ))?
        .trim()
            == "1"
    );
    let mut different = bytes.clone();
    different.push(1);
    let changed = save_bytes(
        &f,
        &mut author,
        "windows",
        "x86_64",
        "exe",
        Some("7+enterprise"),
        &different,
    )
    .await?;
    ensure!(
        author
            .call(
                &f.router,
                Method::POST,
                "/api/v1/agent-packages",
                Some(json!({"operationId":Uuid::new_v4(),"packageId":changed}))
            )
            .await?
            .0
            == StatusCode::CONFLICT
    );
    let withdrawn = author
        .call(
            &f.router,
            Method::POST,
            &format!("/api/v1/agent-packages/{}/withdraw", package.release_id),
            Some(json!({"operationId":Uuid::new_v4()})),
        )
        .await?;
    ensure!(withdrawn.0 == StatusCode::NO_CONTENT);
    ensure!(
        author
            .call(
                &f.router,
                Method::POST,
                "/api/v1/agent-packages",
                Some(left)
            )
            .await?
            == a
    );
    ensure!(
        author
            .call(
                &f.router,
                Method::POST,
                "/api/v1/agent-packages",
                Some(right)
            )
            .await?
            == a
    );
    ensure!(
        author
            .call(
                &f.router,
                Method::POST,
                "/api/v1/agent-packages",
                Some(json!({"operationId":Uuid::new_v4(),"packageId":second}))
            )
            .await?
            .0
            == StatusCode::CONFLICT
    );
    ensure!(
        pg(&format!(
            "SELECT state FROM mdm_agent_packages.releases WHERE tenant_id='{}' AND id='{}'",
            case_tenant(),
            package.release_id
        ))?
        .trim()
            == "withdrawn"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "MODULE=agent.configurations: connection draft, observation gate and original publication receipts"]
async fn connection_publication_requires_deployment_and_preserves_operations() -> Result<()> {
    use sqlx::Connection;
    let f = fixture_with(&[
        "registration_configuration_read",
        "registration_configuration_write",
    ])
    .await?;
    let mut user = f.user.clone();
    let first = user
        .call(&f.router, Method::GET, "/api/v1/agent-connections", None)
        .await?;
    ensure!(
        first.0 == StatusCode::OK && first.1["published"]["configuration"]["revision"] == 1,
        "initial signed fixture {first:?}"
    );
    let (old_material, _) =
        configuration(&f, &mut user, json!({"kind":"unlimited"}), Some(3600)).await?;
    let package = publish(&f, &mut user, false).await?;
    let pending = exchange(&old_material, &package, 0)?;
    let grant = machine(&f, "/api/v1/agent/enroll/configurations/exchange", &pending).await?;
    ensure!(grant.0 == StatusCode::OK);
    let candidate = machine(&f, "/api/v1/agent/enroll/certificates", &json!({"wireVersion":1,"operationId":Uuid::new_v4(),"grantId":grant.1["grantId"],"secret":pending.secret,"csr":pending.csr,"runtime":pending.runtime})).await?;
    ensure!(
        candidate.0 == StatusCode::OK,
        "pending certificate {candidate:?}"
    );
    let a = "https://mdm.example.test:9445";
    let b = "https://mdm.example.test:10443";
    let mut origins = vec![a, b];
    origins.sort();
    let save = json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"preferredOrigin":b,"origins":origins});
    let saved = user
        .call(
            &f.router,
            Method::PUT,
            "/api/v1/agent-connections",
            Some(save.clone()),
        )
        .await?;
    ensure!(saved.0 == StatusCode::OK, "save desired {saved:?}");
    ensure!(
        user.call(
            &f.router,
            Method::PUT,
            "/api/v1/agent-connections",
            Some(save.clone())
        )
        .await?
            == saved
    );
    let base: Value = serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
    let runtime = agent::seed_profile(
        &base,
        f.execution.clone(),
        "connection-peer",
        crate::test_support::case::name("connection-peer"),
        profile(false),
    )
    .await?;
    let peer = agent::evidence("connection-peer").context("real connection peer")?;
    let publish = json!({"operationId":Uuid::new_v4(),"expectedRevision":2});
    let refused = user
        .call(
            &f.router,
            Method::POST,
            "/api/v1/agent-connections/publish",
            Some(publish.clone()),
        )
        .await?;
    ensure!(
        refused.0 == StatusCode::CONFLICT
            && refused.1["code"] == "connection_deployment_unobserved",
        "deployment refusal {refused:?}"
    );
    // A successful deployment observation is a minimal fixture prerequisite here.
    // Actual HTTPS observation and Nginx evidence have their own transport acceptance owner.
    let mut c =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    let mut tx = c.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(case_tenant())
        .execute(&mut *tx)
        .await?;
    for origin in [a, b] {
        rss_mdm_registration_service::agent::connections::record_deployment_on(
            &mut tx,
            Uuid::parse_str(case_tenant())?,
            origin,
            Uuid::parse_str(crate::test_support::identity::INSTANCE)?,
            Uuid::new_v4(),
            1,
        )
        .await?;
    }
    tx.commit().await?;
    let published = user
        .call(
            &f.router,
            Method::POST,
            "/api/v1/agent-connections/publish",
            Some(publish.clone()),
        )
        .await?;
    ensure!(
        published.0 == StatusCode::OK,
        "publish observed {published:?}"
    );
    ensure!(
        user.call(
            &f.router,
            Method::POST,
            "/api/v1/agent-connections/publish",
            Some(publish.clone())
        )
        .await?
            == published
    );
    let receipt = user
        .call(
            &f.router,
            Method::GET,
            &format!(
                "/api/v1/agent-connection-operations/{}",
                publish["operationId"].as_str().unwrap()
            ),
            None,
        )
        .await?;
    ensure!(
        receipt.0 == StatusCode::OK
            && receipt.1["action"] == "published"
            && receipt.1["configuration"] == published.1,
        "original publication {receipt:?}"
    );
    let missing = user
        .call(
            &f.router,
            Method::GET,
            &format!("/api/v1/agent-connection-operations/{}", Uuid::new_v4()),
            None,
        )
        .await?;
    ensure!(
        missing == (StatusCode::OK, Value::Null),
        "unknown operation must stay unknown"
    );
    let mut changed = publish.clone();
    changed["expectedRevision"] = json!(3);
    ensure!(
        user.call(
            &f.router,
            Method::POST,
            "/api/v1/agent-connections/publish",
            Some(changed)
        )
        .await?
        .0 == StatusCode::CONFLICT
    );
    let records = crate::audit_test_support::read(&mut c).await?;
    ensure!(
        records
            .iter()
            .filter(|r| r.source() == "mdm.business"
                && r.operation() == publish["operationId"].as_str())
            .count()
            == 1,
        "replay duplicated publication audit fact"
    );
    let signed: rss_mdm_agent_wire::connections::SignedConfiguration =
        serde_json::from_value(published.1)?;
    let keys = first.1["verificationKeys"].as_object().unwrap();
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let key = URL_SAFE_NO_PAD.decode(keys[&signed.configuration.key_id].as_str().unwrap())?;
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, key)
        .verify(
            &signed.configuration.signing_bytes()?,
            &URL_SAFE_NO_PAD.decode(&signed.signature)?,
        )
        .map_err(|_| anyhow::anyhow!("connection signature"))?;
    let mut authority = authority::Authority::open().await?;
    let resources = std::mem::take(&mut authority.resources);
    resources.finish(async {
        let tls_a=Tls::at_origin(&authority,a).await?;
        let tls_b=Tls::at_origin(&authority,b).await?;
        let mut identity=Vec::new();
        for der in peer.chain(){identity.extend(openssl::x509::X509::from_der(der.as_ref())?.to_pem()?);}
        identity.extend(openssl::pkey::PKey::private_key_from_der(&std::fs::read(root().join("agent.pk8"))?)?.private_key_to_pem_pkcs8()?);
        let identity=reqwest::Identity::from_pem(&identity)?;
        let ca=reqwest::Certificate::from_pem(&std::fs::read(root().join("ca.crt"))?)?;
        let client=|address,identity: reqwest::Identity|reqwest::Client::builder().no_proxy().https_only(true).redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_secs(5))
            .identity(identity).add_root_certificate(ca.clone()).resolve("mdm.example.test",address).build();
        let client_a=client(tls_a.address,identity.clone())?;let client_b=client(tls_b.address,identity)?;
        let url=|address:std::net::SocketAddr,path:&str|format!("https://mdm.example.test:{}{path}",address.port());
        let mut ack=json!({"operationId":Uuid::new_v4(),"revision":2,"digest":signed.configuration.digest()?,"origin":b});
        let rejected=client_a.post(url(tls_a.address,"/api/v1/agent/enroll/connections/acknowledgements")).header("host",a.trim_start_matches("https://")).json(&ack).send().await?;
        ensure!(rejected.status()==StatusCode::FORBIDDEN,"a device supplied origin replaced gateway evidence");
        ack["origin"]=json!(a);
        ensure!(client_a.post(url(tls_a.address,"/api/v1/agent/enroll/connections/acknowledgements")).header("host",a.trim_start_matches("https://")).json(&ack).send().await?.status()==StatusCode::NO_CONTENT);
        let save=json!({"operationId":Uuid::new_v4(),"expectedRevision":2,"preferredOrigin":b,"origins":[b]});
        ensure!(user.call(&f.router,Method::PUT,"/api/v1/agent-connections",Some(save)).await?.0==StatusCode::OK);
        let retire=json!({"operationId":Uuid::new_v4(),"expectedRevision":3});
        let blocked=user.call(&f.router,Method::POST,"/api/v1/agent-connections/publish",Some(retire.clone())).await?;
        ensure!(blocked.0==StatusCode::CONFLICT && blocked.1["code"]=="connection_retirement_blocked","retirement stranded an active peer: {blocked:?}");
        let failed=json!({"operationId":Uuid::new_v4(),"revision":2,"reason":"persistence_failed"});
        ensure!(client_a.post(url(tls_a.address,"/api/v1/agent/enroll/connections/failures")).header("host",a.trim_start_matches("https://")).json(&failed).send().await?.status()==StatusCode::NO_CONTENT);
        let device=url::form_urlencoded::byte_serialize(runtime["deviceId"].as_str().unwrap().as_bytes()).collect::<String>();
        let observed=user.call(&f.router,Method::GET,&format!("/api/v1/agent-connections/devices/{device}/observation"),None).await?;
        ensure!(observed.0==StatusCode::OK && observed.1["acknowledgement"]["revision"]==2 && observed.1["failure"]["report"]["reason"]=="persistence_failed","separate installed/failure facts {observed:?}");
        ack["operationId"]=json!(Uuid::new_v4());ack["origin"]=json!(b);
        for _ in 0..2 {ensure!(client_b.post(url(tls_b.address,"/api/v1/agent/enroll/connections/acknowledgements")).header("host",b.trim_start_matches("https://")).json(&ack).send().await?.status()==StatusCode::NO_CONTENT);}
        let state=user.call(&f.router,Method::GET,"/api/v1/agent-connections",None).await?;
        ensure!(state.1["retirementBlockers"]["configurations"]==1,"old install material was omitted: {state:?}");
        let blocked=user.call(&f.router,Method::POST,"/api/v1/agent-connections/publish",Some(retire.clone())).await?;
        ensure!(blocked.0==StatusCode::CONFLICT && blocked.1["code"]=="connection_retirement_blocked","old live material stranded: {blocked:?}");
        let revoked=user.call(&f.router,Method::POST,&format!("/api/v1/agent-configurations/{}/revoke",old_material.configuration.configuration_id),Some(json!({"operationId":Uuid::new_v4()}))).await?;
        ensure!(revoked.0==StatusCode::NO_CONTENT);
        let state=user.call(&f.router,Method::GET,"/api/v1/agent-connections",None).await?;
        ensure!(state.1["retirementBlockers"]["configurations"]==1,"issued but unactivated grant lost its last origin: {state:?}");
        let blocked=user.call(&f.router,Method::POST,"/api/v1/agent-connections/publish",Some(retire.clone())).await?;
        ensure!(blocked.0==StatusCode::CONFLICT && blocked.1["code"]=="connection_retirement_blocked","consumed grant was mistaken for completed registration: {blocked:?}");
        tls_a.activate(&candidate.1,0).await?;
        let mut pending_identity=Vec::new();
        for der in candidate.1["certificateChain"].as_array().unwrap(){pending_identity.extend(openssl::x509::X509::from_der(&STANDARD.decode(der.as_str().unwrap())?)?.to_pem()?);}
        pending_identity.extend(openssl::pkey::PKey::private_key_from_der(&std::fs::read(root().join("configuration-0.pk8"))?)?.private_key_to_pem_pkcs8()?);
        let pending_identity=reqwest::Identity::from_pem(&pending_identity)?;
        let pending_a=client(tls_a.address,pending_identity.clone())?;
        let pending_b=client(tls_b.address,pending_identity)?;
        let learned=pending_a.get(url(tls_a.address,"/api/v1/agent/enroll/connections")).header("host",a.trim_start_matches("https://")).send().await?;
        ensure!(learned.status()==StatusCode::OK && learned.json::<Value>().await?==serde_json::to_value(&signed)?);
        let mut pending_ack=ack.clone();pending_ack["operationId"]=json!(Uuid::new_v4());
        ensure!(pending_b.post(url(tls_b.address,"/api/v1/agent/enroll/connections/acknowledgements")).header("host",b.trim_start_matches("https://")).json(&pending_ack).send().await?.status()==StatusCode::NO_CONTENT);
        let state=user.call(&f.router,Method::GET,"/api/v1/agent-connections",None).await?;
        ensure!(state.1["retirementBlockers"]["configurations"]==0,"completed registration retained an installation blocker: {state:?}");
        let mut tx=c.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)").bind(case_tenant()).execute(&mut *tx).await?;
        rss_mdm_registration_service::agent::connections::record_deployment_on(&mut tx,Uuid::parse_str(case_tenant())?,b,Uuid::parse_str(crate::test_support::identity::INSTANCE)?,Uuid::new_v4(),1).await?;
        tx.commit().await?;
        let retired=user.call(&f.router,Method::POST,"/api/v1/agent-connections/publish",Some(retire)).await?;
        ensure!(retired.0==StatusCode::OK && retired.1["configuration"]["origins"]==json!([b]),"confirmed B retirement {retired:?}");
        let removed=client_a.get(url(tls_a.address,"/api/v1/agent/enroll/connections")).header("host",a.trim_start_matches("https://")).send().await?;
        ensure!(removed.status()==StatusCode::FORBIDDEN,"retired Agent origin remained admitted");
        let current=client_b.get(url(tls_b.address,"/api/v1/agent/enroll/connections")).header("host",b.trim_start_matches("https://")).send().await?;
        ensure!(current.status()==StatusCode::OK && current.json::<Value>().await?==retired.1);
        let failed_new=json!({"operationId":Uuid::new_v4(),"revision":3,"reason":"persistence_failed"});
        ensure!(client_b.post(url(tls_b.address,"/api/v1/agent/enroll/connections/failures")).header("host",b.trim_start_matches("https://")).json(&failed_new).send().await?.status()==StatusCode::NO_CONTENT);
        ack["operationId"]=json!(Uuid::new_v4());
        ensure!(client_b.post(url(tls_b.address,"/api/v1/agent/enroll/connections/acknowledgements")).header("host",b.trim_start_matches("https://")).json(&ack).send().await?.status()==StatusCode::NO_CONTENT);
        let observed=user.call(&f.router,Method::GET,&format!("/api/v1/agent-connections/devices/{device}/observation"),None).await?;
        ensure!(observed.0==StatusCode::OK && observed.1["targetRevision"]==3 && observed.1["acknowledgement"]["revision"]==2 && observed.1["failure"]["report"]["revision"]==3,"late old ACK hid new failure: {observed:?}");
        ack["operationId"]=json!(Uuid::new_v4());ack["revision"]=json!(3);ack["digest"]=json!(serde_json::from_value::<rss_mdm_agent_wire::connections::SignedConfiguration>(retired.1)?.configuration.digest()?);
        ensure!(client_b.post(url(tls_b.address,"/api/v1/agent/enroll/connections/acknowledgements")).header("host",b.trim_start_matches("https://")).json(&ack).send().await?.status()==StatusCode::NO_CONTENT);
        pending_ack=ack.clone();pending_ack["operationId"]=json!(Uuid::new_v4());
        ensure!(pending_b.post(url(tls_b.address,"/api/v1/agent/enroll/connections/acknowledgements")).header("host",b.trim_start_matches("https://")).json(&pending_ack).send().await?.status()==StatusCode::NO_CONTENT);
        let converged=user.call(&f.router,Method::GET,"/api/v1/agent-connections",None).await?;
        ensure!(converged.1["convergence"]["activeDevices"]==2 && converged.1["convergence"]["confirmedDevices"]==2,"actual convergence {converged:?}");
        let missing=user.call(&f.router,Method::GET,"/api/v1/agent-connections/devices?revision=3",None).await?;
        ensure!(missing.0==StatusCode::OK && missing.1["items"]==json!([]));
        let mut inventory_user=authority::Authority::prepared_browser("other")?;
        let subject=browser_subject(&inventory_user, &f.router).await?;
        identity::set_grants(case_tenant(), &subject, vec![crate::authorization::Grant {operation:serde_json::from_value(json!("inventory_read"))?,scope:crate::authorization::Scope::AllDevices}]).await?;
        let observed=inventory_user.call(&f.router,Method::GET,&format!("/api/v1/agent-connections/devices/{device}/observation"),None).await?;
        ensure!(observed.0==StatusCode::OK && observed.1["targetRevision"]==3 && observed.1["acknowledgement"]["revision"]==3 && observed.1["failure"].is_null(),"inventory reader could not see target and installed facts: {observed:?}");
        ensure!(inventory_user.call(&f.router,Method::GET,"/api/v1/agent-connections",None).await?.0==StatusCode::FORBIDDEN);
        ensure!(tls_a.owner.shutdown().join().await?.is_clean());ensure!(tls_b.owner.shutdown().join().await?.is_clean());
        Ok(())
    }).await?;
    c.close().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "MODULE=agent.configurations: persisted observations and administrator declarations do not reread installer bytes"]
async fn installer_observations_are_optional_and_reused_without_payload_reads() -> Result<()> {
    let f = fixture().await?;
    let mut user = f.user.clone();
    let bytes = installer_fixtures::exe("1");
    let id = stage_upload(&f, &mut user, "exe", &bytes).await?;
    let path = format!("/api/v1/agent-packages/uploads/{id}");
    let observed = user.call(&f.router, Method::GET, &path, None).await?;
    ensure!(observed.0 == StatusCode::OK && observed.1["inspection"]["status"] == "parsed");
    let digest = rss_mdm_resource::Digest::of(&bytes)
        .bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let object = pg(&format!(
        "SELECT document->'value'->'pieces'->0->'coordinate'->>'id' FROM mdm_content.manifests WHERE tenant_id='{}' AND sha256=decode('{digest}','hex') AND length={}",
        case_tenant(),
        bytes.len()
    ))?;
    let original = f.directory.join(case_tenant()).join(object.trim());
    let moved = original.with_extension("inspection-reuse");
    std::fs::rename(&original, &moved)?;
    let result: Result<w::configuration::Package> = async {
        ensure!(user.call(&f.router, Method::GET, &path, None).await? == observed);
        ensure!(user.call(&f.router, Method::POST, &path, None).await? == observed);
        let saved = user.call(&f.router, Method::POST, "/api/v1/agent-packages/save",
            Some(json!({"operationId":Uuid::new_v4(),"packageId":id,"version":"admin-declared","target":{"platform":"windows","architecture":"x86_64"}}))).await?;
        ensure!(saved.0 == StatusCode::OK, "save must use completed integrity and explicit declaration: {saved:?}");
        let published = user.call(&f.router, Method::POST, "/api/v1/agent-packages",
            Some(json!({"operationId":Uuid::new_v4(),"packageId":id}))).await?;
        ensure!(published.0 == StatusCode::OK, "publication must not reread bytes: {published:?}");
        let package: w::configuration::Package = serde_json::from_value(published.1)?;
        let download = f.client.get(format!("{}/api/v1/agent/enroll/packages/{}/content",f.origin,package.release_id))
            .header("host","mdm.example.test:9445").send().await?;
        ensure!(!download.status().is_success(), "real download must still reject missing bytes");
        Ok(package)
    }.await;
    std::fs::rename(&moved, &original)?;
    let package = result?;
    let download = f
        .client
        .get(format!(
            "{}/api/v1/agent/enroll/packages/{}/content",
            f.origin, package.release_id
        ))
        .header("host", "mdm.example.test:9445")
        .send()
        .await?;
    ensure!(
        download.status() == StatusCode::OK && download.bytes().await?.as_ref() == bytes.as_slice()
    );

    let rejected = stage_upload(
        &f,
        &mut user,
        "pkg",
        b"not a package; intact distribution material",
    )
    .await?;
    let inspected = user
        .call(
            &f.router,
            Method::GET,
            &format!("/api/v1/agent-packages/uploads/{rejected}"),
            None,
        )
        .await?;
    ensure!(inspected.0 == StatusCode::OK && inspected.1["inspection"]["status"] == "rejected");
    let saved = user.call(&f.router, Method::POST, "/api/v1/agent-packages/save",
        Some(json!({"operationId":Uuid::new_v4(),"packageId":rejected,"version":"manual","target":{"platform":"macos","architecture":"aarch64"}}))).await?;
    ensure!(
        saved.0 == StatusCode::OK,
        "failed auxiliary inspection must not block declarations: {saved:?}"
    );
    let published = user
        .call(
            &f.router,
            Method::POST,
            "/api/v1/agent-packages",
            Some(json!({"operationId":Uuid::new_v4(),"packageId":rejected})),
        )
        .await?;
    ensure!(
        published.0 == StatusCode::OK,
        "rejected auxiliary metadata does not reject intact bytes: {published:?}"
    );
    Ok(())
}
