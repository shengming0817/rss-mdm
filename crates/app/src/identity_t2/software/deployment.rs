//! Real enterprise software Policy through Agent Offer, content, Start and detection.
use super::*;
use base64::Engine;
use ring::signature::KeyPair;
use sha2::{Digest, Sha256};
use sqlx::Connection;

const DEVICE: &str = "software-deployment-device";
const CREDENTIAL: &str = "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ";

async fn agent(router: &Router, path: &str, body: Option<Value>) -> Result<(StatusCode, Value)> {
    agent_call(router, Method::POST, path, Some(CREDENTIAL), body).await
}
async fn event(router: &Router, task: &Value, mut event: Value) -> Result<(StatusCode, Value)> {
    if event["kind"] == "software_result" {
        event["definitionDigest"] = task["payload"]["definitionDigest"].clone();
        event["evidenceDigest"] = json!(Sha256::digest(b"controlled detector evidence").to_vec());
        event["observedVersion"] = if event["detection"] == "present" {
            task["payload"]["steps"]
                .as_array()
                .and_then(|steps| steps.last())
                .ok_or_else(|| anyhow::anyhow!("missing executable step"))?["action"]["version"]
                .clone()
        } else {
            Value::Null
        };
    }
    agent(router, &format!("/api/agent/v3/tasks/{}/events", task["payload"]["taskId"].as_str().unwrap()),
        Some(json!({"wireVersion":3,"operationId":Uuid::new_v4(),"attemptId":task["payload"]["attemptId"],"event":event}))).await
}
async fn claim(router: &Router) -> Result<Value> {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let response = agent(
                router,
                "/api/agent/v3/tasks/claim",
                Some(json!({"wireVersion":3,"operationId":Uuid::new_v4()})),
            )
            .await?;
            ensure!(response.0 == StatusCode::OK, "claim: {response:?}");
            if !response.1["task"].is_null() {
                return Ok::<_, anyhow::Error>(response.1["task"].clone());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 SUITE=software: real Router, TLS PostgreSQL and software bytes"]
async fn enterprise_assignment_authorization_rollout_and_results() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir()?;
    let keyfile = temp.path().join("signing.pk8");
    let pkcs8 =
        ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
    std::fs::write(&keyfile, pkcs8.as_ref())?;
    std::fs::set_permissions(&keyfile, std::fs::Permissions::from_mode(0o600))?;
    let key = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let mut base: Value =
        serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
    base["content"] = json!({"directory":temp.path(),"imports":{},"max_artifact_bytes":33554432,"max_temporary_bytes":67108864,"max_uploads":4,"transfer_seconds":60,"retention_seconds":3600,"max_bundle_bytes":67108864,"max_bundle_entries":100,"max_expansion_ratio":100});
    base["task_signing"] = json!({"private_key_file":keyfile,"key_id":"fixture","trusted_keys":{"fixture":base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.public_key().as_ref())}});
    let (router, _, _) = crate::api::application_fixture(
        serde_json::from_value(base.clone())?,
        Arc::new(crate::clock::SystemClock),
        monotonic(),
        database(&base).await?,
        None,
        database(&base)
            .await?
            .audit_store(&crate::config::AuditConfig::Plain)
            .await?,
    )
    .await?;
    let router = router.layer(axum::Extension(rss_identity_http_axum::ClientAddress(
        "127.0.0.1".parse()?,
    )));
    let mut author = Browser::default();
    ensure!(author.login(&router, "other").await? == StatusCode::OK);
    let subject = browser_subject(&author, &router).await?;
    let mut grants = crate::identity_fixture::device_grants(
        None,
        &[
            "enrollment",
            "inventory_read",
            "software_deploy",
            "operation_read",
        ],
    )?;
    for name in [
        "resource_read",
        "resource_write",
        "software_read",
        "software_write",
        "software_approve",
        "software_withdraw",
        "policy_read",
        "policy_write",
        "scope_read",
        "scope_write",
    ] {
        grants.push(crate::authorization::Grant {
            operation: serde_json::from_value(json!(name))?,
            scope: crate::authorization::Scope::Tenant,
        });
    }
    crate::identity_fixture::set_grants(TENANT, &subject, grants).await?;
    author.operation = Some(Uuid::new_v4());
    let password = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let enrollment = author
        .call(
            &router,
            Method::POST,
            "/api/v3/enrollments",
            Some(json!({"deviceId":DEVICE,"password":password,"source":"agent.builtin"})),
        )
        .await?;
    ensure!(enrollment.0.is_success(), "enrollment: {enrollment:?}");
    author.operation = None;
    let registration=agent_call(&router,Method::POST,"/api/agent/v3/registrations",None,Some(json!({"wireVersion":3,"operationId":Uuid::new_v4(),"enrollmentId":enrollment.1["enrollmentId"],"password":password,"credential":CREDENTIAL,"platform":"macos","architecture":"aarch64","capabilities":["inventory.basic.v3","software.execute.v3"]}))).await?;
    ensure!(
        registration.0 == StatusCode::CREATED,
        "registration: {registration:?}"
    );
    let scope = Uuid::new_v4();
    let automation = start_automation(&base).await?;
    let created=write(&mut author,&router,&format!("/api/v2/scopes/{scope}"),0,json!({"action":"put","definition":{"targets":[{"kind":"device","id":DEVICE}],"limitations":null,"exclusions":[]}})).await?;
    await_task(
        &mut author,
        &router,
        &format!(
            "/api/v2/scopes/{scope}/tasks/{}",
            created["task"].as_str().unwrap()
        ),
    )
    .await?;
    let empty_scope = Uuid::new_v4();
    let empty = write(
        &mut author,
        &router,
        &format!("/api/v2/scopes/{empty_scope}"),
        0,
        json!({"action":"put","definition":{"targets":[],"limitations":null,"exclusions":[]}}),
    )
    .await?;
    await_task(
        &mut author,
        &router,
        &format!(
            "/api/v2/scopes/{empty_scope}/tasks/{}",
            empty["task"].as_str().unwrap()
        ),
    )
    .await?;
    ensure!(automation.shutdown().join().await?.is_clean());
    let source = Uuid::new_v4().to_string();
    let source_path = format!("/api/v3/software/sources/{source}/revisions/1");
    let registered=write(&mut author,&router,&source_path,0,json!({"action":"register","definition":{"id":source,"revision":"1","kind":"private","location":null,"publishers":[]}})).await?;
    write(
        &mut author,
        &router,
        &source_path,
        1,
        json!({"action":"approve","evidence":["enterprise-source"]}),
    )
    .await?;
    let dependency = Uuid::new_v4();
    let dependency_path = format!("/api/v3/resources/{dependency}");
    write(
        &mut author,
        &router,
        &dependency_path,
        0,
        json!({"action":"create","kind":"software"}),
    )
    .await?;
    let dependency_bytes = b"controlled dependency package";
    let dependency_digest: [u8; 32] = Sha256::digest(dependency_bytes).into();
    let dependency_definition = json!({"source":registered["snapshot"],"package":"Private.Dependency","version":"1","format":"pkg","primary":"scripts/install.sh","artifacts":{"scripts/install.sh":{"reference":"dep-installer","length":dependency_bytes.len(),"sha256":dependency_digest}},"install":{"executor":"package_installer","entry":null,"runAs":"system","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096},"uninstall":null,"detect":{"kind":"pkg_receipt","receipt":"com.private.dependency","version":"1"},"reboot":"report","downgrade":"deny","ownership":"managed_only","dependencies":[],"bundle":null});
    write(&mut author,&router,&dependency_path,1,json!({"action":"version","version":"v1","kind":"software","variants":[{"platform":"macos","architecture":"aarch64","key":"default","declaration":{"kind":"software","definition":dependency_definition}}]})).await?;
    let request=Request::builder().method(Method::POST).uri(format!("{dependency_path}/content?version=v1&variant=default&platform=macos&architecture=aarch64&operation={}",Uuid::new_v4()))
        .header("host","mdm.example.test").header("origin","https://mdm.example.test").header("x-identity-request","1")
        .header("x-csrf-token",author.csrf.as_ref().unwrap())
        .header("cookie",author.cookies.iter().map(|(k,v)|format!("{k}={v}")).collect::<Vec<_>>().join("; "))
        .header("content-type","application/octet-stream").body(Body::from(dependency_bytes.to_vec()))?;
    ensure!(router.clone().oneshot(request).await?.status() == StatusCode::CREATED);
    write(
        &mut author,
        &router,
        &dependency_path,
        2,
        json!({"action":"activate","version":"v1"}),
    )
    .await?;
    write(
        &mut author,
        &router,
        &format!("/api/v3/software/resources/{dependency}/versions/v1"),
        0,
        json!({"action":"approve","evidence":["fixed-prerequisite"]}),
    )
    .await?;
    let dependency_version = author
        .call(
            &router,
            Method::GET,
            &format!("/api/v3/software/resources/{dependency}/versions/v1"),
            None,
        )
        .await?;
    ensure!(dependency_version.0 == StatusCode::OK);
    let resource = Uuid::new_v4();
    let path = format!("/api/v3/resources/{resource}");
    write(
        &mut author,
        &router,
        &path,
        0,
        json!({"action":"create","kind":"software"}),
    )
    .await?;
    let bytes = b"controlled software package";
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    let removal = b"#!/bin/sh\nexit 0\n";
    let removal_digest: [u8; 32] = Sha256::digest(removal).into();
    let definition = json!({"source":registered["snapshot"],"package":"Private.Controlled","version":"1","format":"pkg","primary":"package","artifacts":{"package":{"reference":"installer","length":bytes.len(),"sha256":digest},"remove":{"reference":"remover","length":removal.len(),"sha256":removal_digest}},"install":{"executor":"package_installer","entry":null,"runAs":"system","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096},"uninstall":{"executor":"posix_sh","entry":"remove","runAs":"system","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096},"detect":{"kind":"pkg_receipt","receipt":"com.private.controlled","version":"1"},"reboot":"report","downgrade":"deny","ownership":"managed_only","dependencies":[{"resource":dependency,"version":"v1","sha256":dependency_version.1["resourceDigest"]}],"bundle":null});
    write(&mut author,&router,&path,1,json!({"action":"version","version":"v1","kind":"software","variants":[{"platform":"macos","architecture":"aarch64","key":"default","declaration":{"kind":"software","definition":definition}}]})).await?;
    let request=Request::builder().method(Method::POST).uri(format!("{path}/content?version=v1&variant=default&platform=macos&architecture=aarch64&operation={}",Uuid::new_v4()))
        .header("host","mdm.example.test").header("origin","https://mdm.example.test").header("x-identity-request","1")
        .header("x-csrf-token",author.csrf.as_ref().unwrap())
        .header("cookie",author.cookies.iter().map(|(k,v)|format!("{k}={v}")).collect::<Vec<_>>().join("; "))
        .header("content-type","application/octet-stream").body(Body::from(bytes.to_vec()))?;
    ensure!(router.clone().oneshot(request).await?.status() == StatusCode::CREATED);
    let request=Request::builder().method(Method::POST).uri(format!("{path}/content?version=v1&variant=default&platform=macos&architecture=aarch64&artifact=remover&operation={}",Uuid::new_v4()))
        .header("host","mdm.example.test").header("origin","https://mdm.example.test").header("x-identity-request","1")
        .header("x-csrf-token",author.csrf.as_ref().unwrap())
        .header("cookie",author.cookies.iter().map(|(k,v)|format!("{k}={v}")).collect::<Vec<_>>().join("; "))
        .header("content-type","application/octet-stream").body(Body::from(removal.to_vec()))?;
    ensure!(router.clone().oneshot(request).await?.status() == StatusCode::CREATED);
    write(
        &mut author,
        &router,
        &path,
        2,
        json!({"action":"activate","version":"v1"}),
    )
    .await?;
    let first_approval = write(
        &mut author,
        &router,
        &format!("/api/v3/software/resources/{resource}/versions/v1"),
        0,
        json!({"action":"approve","evidence":["enterprise-version"]}),
    )
    .await?;
    let first_operation = first_approval["admission"]["operation"].clone();
    let policy = Uuid::new_v4();
    let policy_path = format!("/api/v2/policies/{policy}");
    let authored = |intent: &str, operation: &Value| json!({"resource":{"kind":"software","id":resource,"version":"v1","variants":{"macos_aarch64":"default"}},"scope":scope,"behavior":{"kind":"software","intent":intent,"admissionOperation":operation,"runLifetimeSeconds":600,"rollout":{"stages":[{"scope":scope,"opensAt":0}]}}});
    let published = write(
        &mut author,
        &router,
        &policy_path,
        0,
        json!({"action":"put","enabled":true,"definition":authored("required_install", &first_operation)}),
    )
    .await?;
    ensure!(published["version"] == 1, "publish: {published}");
    let config: Config = serde_json::from_value(base.clone())?;
    let worker = crate::flow::execution::open(
        &config,
        crate::identity_fixture::audit_store(&config).await?,
    )
    .await?;
    let mut stack = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(15))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let mut startup = stack.startup()?;
    startup.stage_resource(rss_runtime::DynManagedResource::new_box(
        crate::execution::Resource(worker.clone()),
    ));
    let mut launch = startup.commit();
    launch.stage_deferred_task_with_token(worker.registration().critical());
    launch.finish();
    let task = claim(&router).await?;
    ensure!(
        task["payload"]["steps"][0]["action"]["package"] == "Private.Dependency"
            && task["payload"]["steps"][1]["action"]["package"] == "Private.Controlled"
            && task["payload"]["softwareResource"].is_null()
            && task["payload"]["admissionOperation"].is_null()
            && task["payload"]["startMode"] == "automatic",
        "offer: {task}"
    );
    ensure!(task["payload"]["steps"][1]["artifacts"][0]["length"] == bytes.len());
    let mut owner =
        sqlx::PgConnection::connect_with(&crate::device::tests::options("postgres")?).await?;
    sqlx::query("UPDATE mdm_commands.action_attempts SET offer=jsonb_set(offer,'{payload,expiresAt}','0'::jsonb) WHERE id=$1::uuid")
        .bind(task["payload"]["attemptId"].as_str().unwrap()).execute(&mut owner).await?;
    let expired = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "/api/agent/v3/tasks/{}/content?attempt={}&artifact=1%2Fpackage",
            task["payload"]["taskId"].as_str().unwrap(),
            task["payload"]["attemptId"].as_str().unwrap()
        ))
        .header("host", "mdm.example.test")
        .header("authorization", format!("Bearer {CREDENTIAL}"))
        .body(Body::empty())?;
    ensure!(router.clone().oneshot(expired).await?.status() == StatusCode::FORBIDDEN);
    sqlx::query("UPDATE mdm_commands.action_attempts SET offer=jsonb_set(offer,'{payload,expiresAt}',to_jsonb($2::bigint)) WHERE id=$1::uuid")
        .bind(task["payload"]["attemptId"].as_str().unwrap())
        .bind(task["payload"]["expiresAt"].as_i64().unwrap()).execute(&mut owner).await?;
    owner.close().await?;
    let content = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "/api/agent/v3/tasks/{}/content?attempt={}&artifact=1%2Fpackage",
            task["payload"]["taskId"].as_str().unwrap(),
            task["payload"]["attemptId"].as_str().unwrap()
        ))
        .header("host", "mdm.example.test")
        .header("authorization", format!("Bearer {CREDENTIAL}"))
        .body(Body::empty())?;
    let content = router.clone().oneshot(content).await?;
    ensure!(
        content.status() == StatusCode::OK,
        "content: {}",
        content.status()
    );
    ensure!(content.into_body().collect().await?.to_bytes() == bytes.as_slice());
    let prerequisite = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "/api/agent/v3/tasks/{}/content?attempt={}&artifact=0%2Fscripts%2Finstall.sh",
            task["payload"]["taskId"].as_str().unwrap(),
            task["payload"]["attemptId"].as_str().unwrap()
        ))
        .header("host", "mdm.example.test")
        .header("authorization", format!("Bearer {CREDENTIAL}"))
        .body(Body::empty())?;
    let prerequisite = router.clone().oneshot(prerequisite).await?;
    ensure!(prerequisite.status() == StatusCode::OK);
    ensure!(prerequisite.into_body().collect().await?.to_bytes() == dependency_bytes.as_slice());
    ensure!(event(&router, &task, json!({"kind":"received"})).await?.0 == StatusCode::OK);
    let start = event(&router, &task, json!({"kind":"start"})).await?;
    ensure!(
        start.0 == StatusCode::OK && start.1["permit"]["payload"]["permit"] == "start",
        "start: {start:?}"
    );
    let result=event(&router,&task,json!({"kind":"software_result","intent":"install","installerExitCode":0,"detection":"present","rebootRequired":false,"diagnostics":{"stdout":"","stderr":"","durationMs":1,"executedAt":1,"failure":null}})).await?;
    ensure!(result.0 == StatusCode::OK, "result: {result:?}");
    let status = author
        .call(
            &router,
            Method::GET,
            &format!("/api/v2/policies/{policy}/software/rollout"),
            None,
        )
        .await?;
    ensure!(status.0 == StatusCode::OK, "rollout: {status:?}");
    ensure!(
        status.1["stages"][0]["totalTargets"] == 1
            && status.1["stages"][0]["reported"] == 1
            && status.1["stages"][0]["unknown"] == 0
            && status.1["stages"][0]["verifiedSuccess"] == 1,
        "counts: {status:?}"
    );
    let runs = author
        .call(
            &router,
            Method::GET,
            &format!("/api/v2/policies/{policy}/runs"),
            None,
        )
        .await?;
    ensure!(
        runs.1["items"][0]["effect"] == "verified",
        "run list effect: {runs:?}"
    );
    let detail = author
        .call(
            &router,
            Method::GET,
            &format!(
                "/api/v2/policies/{policy}/runs/{}",
                task["payload"]["taskId"].as_str().unwrap()
            ),
            None,
        )
        .await?;
    ensure!(
        detail.1["effect"] == "verified",
        "run detail effect: {detail:?}"
    );
    write(
        &mut author,
        &router,
        &policy_path,
        1,
        json!({"action":"disable"}),
    )
    .await?;
    let available = Uuid::new_v4();
    write(
        &mut author,
        &router,
        &format!("/api/v2/policies/{available}"),
        0,
        json!({"action":"put","enabled":true,"definition":authored("available_install", &first_operation)}),
    )
    .await?;
    let optional = claim(&router).await?;
    ensure!(
        optional["payload"]["intent"] == "install"
            && optional["payload"]["startMode"] == "user_initiated",
        "optional: {optional}"
    );
    let awaiting = author
        .call(
            &router,
            Method::GET,
            &format!("/api/v2/policies/{available}/software/rollout"),
            None,
        )
        .await?;
    ensure!(
        awaiting.1["stages"][0]["reported"] == 0,
        "self-service task auto-reported: {awaiting:?}"
    );
    ensure!(
        event(&router, &optional, json!({"kind":"received"}))
            .await?
            .0
            == StatusCode::OK
    );
    ensure!(event(&router, &optional, json!({"kind":"start"})).await?.0 == StatusCode::OK);
    ensure!(event(&router,&optional,json!({"kind":"software_result","intent":"install","installerExitCode":17,"detection":"present","rebootRequired":false,"diagnostics":{"stdout":"","stderr":"","durationMs":1,"executedAt":1,"failure":null}})).await?.0==StatusCode::OK);
    let optional_status = author
        .call(
            &router,
            Method::GET,
            &format!("/api/v2/policies/{available}/software/rollout"),
            None,
        )
        .await?;
    ensure!(
        optional_status.1["stages"][0]["verifiedSuccess"] == 1,
        "detector must be independent of installer exit: {optional_status:?}"
    );
    write(
        &mut author,
        &router,
        &format!("/api/v2/policies/{available}"),
        1,
        json!({"action":"disable"}),
    )
    .await?;
    let uninstall = Uuid::new_v4();
    write(
        &mut author,
        &router,
        &format!("/api/v2/policies/{uninstall}"),
        0,
        json!({"action":"put","enabled":true,"definition":authored("explicit_uninstall", &first_operation)}),
    )
    .await?;
    let removal_task = claim(&router).await?;
    ensure!(
        removal_task["payload"]["intent"] == "uninstall"
            && removal_task["payload"]["startMode"] == "automatic",
        "uninstall: {removal_task}"
    );
    let content = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "/api/agent/v3/tasks/{}/content?attempt={}&artifact=0%2Fremove",
            removal_task["payload"]["taskId"].as_str().unwrap(),
            removal_task["payload"]["attemptId"].as_str().unwrap()
        ))
        .header("host", "mdm.example.test")
        .header("authorization", format!("Bearer {CREDENTIAL}"))
        .body(Body::empty())?;
    let content = router.clone().oneshot(content).await?;
    ensure!(
        content.status() == StatusCode::OK,
        "remove content: {}",
        content.status()
    );
    ensure!(content.into_body().collect().await?.to_bytes() == removal.as_slice());
    ensure!(
        event(&router, &removal_task, json!({"kind":"received"}))
            .await?
            .0
            == StatusCode::OK
    );
    ensure!(
        event(&router, &removal_task, json!({"kind":"start"}))
            .await?
            .0
            == StatusCode::OK
    );
    ensure!(event(&router,&removal_task,json!({"kind":"software_result","intent":"uninstall","installerExitCode":0,"detection":"absent","rebootRequired":false,"diagnostics":{"stdout":"","stderr":"","durationMs":1,"executedAt":1,"failure":null}})).await?.0==StatusCode::OK);
    let removed = author
        .call(
            &router,
            Method::GET,
            &format!("/api/v2/policies/{uninstall}/software/rollout"),
            None,
        )
        .await?;
    ensure!(
        removed.1["stages"][0]["verifiedSuccess"] == 1,
        "uninstall detection: {removed:?}"
    );
    write(
        &mut author,
        &router,
        &format!("/api/v2/policies/{uninstall}"),
        1,
        json!({"action":"disable"}),
    )
    .await?;
    let revoke_policy = Uuid::new_v4();
    write(
        &mut author,
        &router,
        &format!("/api/v2/policies/{revoke_policy}"),
        0,
        json!({"action":"put","enabled":true,"definition":authored("required_install", &first_operation)}),
    )
    .await?;
    let offered = claim(&router).await?;
    ensure!(
        event(&router, &offered, json!({"kind":"received"}))
            .await?
            .0
            == StatusCode::OK
    );
    write(
        &mut author,
        &router,
        &format!("/api/v3/software/resources/{resource}/versions/v1"),
        1,
        json!({"action":"withdraw","evidence":["deployment-revocation"]}),
    )
    .await?;
    let denied = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "/api/agent/v3/tasks/{}/content?attempt={}&artifact=1%2Fpackage",
            offered["payload"]["taskId"].as_str().unwrap(),
            offered["payload"]["attemptId"].as_str().unwrap()
        ))
        .header("host", "mdm.example.test")
        .header("authorization", format!("Bearer {CREDENTIAL}"))
        .body(Body::empty())?;
    ensure!(router.clone().oneshot(denied).await?.status() == StatusCode::FORBIDDEN);
    ensure!(event(&router, &offered, json!({"kind":"start"})).await?.0 == StatusCode::FORBIDDEN);
    write(
        &mut author,
        &router,
        &format!("/api/v2/policies/{revoke_policy}"),
        1,
        json!({"action":"disable"}),
    )
    .await?;
    let reapproved = write(
        &mut author,
        &router,
        &format!("/api/v3/software/resources/{resource}/versions/v1"),
        2,
        json!({"action":"approve","evidence":["reapproved-for-future-task"]}),
    )
    .await?;
    let second_operation = reapproved["admission"]["operation"].clone();
    let future = Uuid::new_v4();
    let future_path = format!("/api/v2/policies/{future}");
    let now = crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?;
    let future_definition = |opens_at: i64, minimum: Option<u8>| json!({"resource":{"kind":"software","id":resource,"version":"v1","variants":{"macos_aarch64":"default"}},"scope":scope,"behavior":{"kind":"software","intent":"required_install","admissionOperation":second_operation,"runLifetimeSeconds":600,"rollout":{"stages":[{"scope":empty_scope,"opensAt":0},{"scope":scope,"opensAt":opens_at,"minimumVerifiedPercent":minimum}]}}});
    let future_policy = write(
        &mut author,
        &router,
        &future_path,
        0,
        json!({"action":"put","enabled":true,"definition":future_definition(now+3600,None)}),
    )
    .await?;
    let frozen_version = future_policy["versionId"].clone();
    let device_page = author
        .call(
            &router,
            Method::GET,
            &format!("/api/v2/policies/{future}/devices"),
            None,
        )
        .await?;
    ensure!(
        device_page.1["items"][0]["taskAdmission"]["state"] == "scheduled",
        "device page misstates execution eligibility: {device_page:?}"
    );
    let preview=author.call(&router,Method::POST,"/api/v2/policies/previews",Some(json!({"definition":future_definition(now+3600,None),"after":null,"scopeResult":null}))).await?;
    ensure!(
        preview.1["items"][0]["taskAdmission"]["state"] == "scheduled",
        "preview misstates execution eligibility: {preview:?}"
    );
    let waiting = agent(
        &router,
        "/api/agent/v3/tasks/claim",
        Some(json!({"wireVersion":3,"operationId":Uuid::new_v4()})),
    )
    .await?;
    ensure!(
        waiting.0 == StatusCode::OK && waiting.1["task"].is_null(),
        "time gate: {waiting:?}"
    );
    write(
        &mut author,
        &router,
        &future_path,
        1,
        json!({"action":"disable"}),
    )
    .await?;
    let edited = write(
        &mut author,
        &router,
        &future_path,
        2,
        json!({"action":"put","enabled":false,"definition":future_definition(1,Some(80))}),
    )
    .await?;
    ensure!(
        edited["versionId"] == frozen_version,
        "rollout edit changed software execution version: {edited}"
    );
    write(
        &mut author,
        &router,
        &future_path,
        3,
        json!({"action":"enable"}),
    )
    .await?;
    let gated = agent(
        &router,
        "/api/agent/v3/tasks/claim",
        Some(json!({"wireVersion":3,"operationId":Uuid::new_v4()})),
    )
    .await?;
    ensure!(
        gated.0 == StatusCode::OK && gated.1["task"].is_null(),
        "optional success gate: {gated:?}"
    );
    let resumed = write(
        &mut author,
        &router,
        &future_path,
        4,
        json!({"action":"put","enabled":true,"definition":future_definition(1,None)}),
    )
    .await?;
    ensure!(resumed["versionId"] == frozen_version);
    let resumed_task = claim(&router).await?;
    ensure!(
        resumed_task["payload"]["steps"][1]["action"]["package"] == "Private.Controlled",
        "resume: {resumed_task}"
    );
    ensure!(
        event(&router, &resumed_task, json!({"kind":"received"}))
            .await?
            .0
            == StatusCode::OK
    );
    ensure!(
        event(&router, &resumed_task, json!({"kind":"start"}))
            .await?
            .0
            == StatusCode::OK
    );
    let unknown_operation = Uuid::new_v4();
    let unknown_request = json!({"wireVersion":3,"operationId":unknown_operation,"attemptId":resumed_task["payload"]["attemptId"],
        "event":{"kind":"software_result","intent":"install","installerExitCode":0,"detection":"unknown","rebootRequired":false,
            "definitionDigest":resumed_task["payload"]["definitionDigest"],"observedVersion":null,
            "evidenceDigest":Sha256::digest(b"unknown detector evidence").to_vec(),
            "diagnostics":{"stdout":"","stderr":"","durationMs":1,"executedAt":1,"failure":null}}});
    let result = agent(
        &router,
        &format!(
            "/api/agent/v3/tasks/{}/events",
            resumed_task["payload"]["taskId"].as_str().unwrap()
        ),
        Some(unknown_request.clone()),
    )
    .await?;
    ensure!(result.0 == StatusCode::OK, "unknown result: {result:?}");
    let replay = agent(
        &router,
        &format!(
            "/api/agent/v3/tasks/{}/events",
            resumed_task["payload"]["taskId"].as_str().unwrap()
        ),
        Some(unknown_request),
    )
    .await?;
    ensure!(replay == result, "result replay: {replay:?}");
    let uncertainty = author
        .call(
            &router,
            Method::GET,
            &format!("/api/v2/policies/{future}/software/rollout"),
            None,
        )
        .await?;
    ensure!(
        uncertainty.1["stages"][1]["reported"] == 1
            && uncertainty.1["stages"][1]["unknown"] == 1
            && uncertainty.1["stages"][1]["verifiedSuccess"] == 0,
        "unknown denominator: {uncertainty:?}"
    );
    let no_retry = agent(
        &router,
        "/api/agent/v3/tasks/claim",
        Some(json!({"wireVersion":3,"operationId":Uuid::new_v4()})),
    )
    .await?;
    ensure!(
        no_retry.0 == StatusCode::OK && no_retry.1["task"].is_null(),
        "unknown effect was blindly retried: {no_retry:?}"
    );
    let late = event(
        &router,
        &resumed_task,
        json!({"kind":"software_result","intent":"install","installerExitCode":0,"detection":"present","rebootRequired":false,"diagnostics":{"stdout":"","stderr":"","durationMs":1,"executedAt":1,"failure":null}}),
    )
    .await?;
    ensure!(late.0 == StatusCode::OK, "late detection: {late:?}");
    let resolved = author
        .call(
            &router,
            Method::GET,
            &format!("/api/v2/policies/{future}/software/rollout"),
            None,
        )
        .await?;
    ensure!(
        resolved.1["stages"][1]["unknown"] == 0 && resolved.1["stages"][1]["verifiedSuccess"] == 1,
        "late detection did not resolve unknown: {resolved:?}"
    );
    let reordered=write(&mut author,&router,&future_path,5,json!({"action":"put","enabled":true,
        "definition":{"resource":{"kind":"software","id":resource,"version":"v1","variants":{"macos_aarch64":"default"}},"scope":scope,
        "behavior":{"kind":"software","intent":"required_install","admissionOperation":second_operation,"runLifetimeSeconds":600,
        "rollout":{"stages":[{"scope":scope,"opensAt":0},{"scope":empty_scope,"opensAt":1}]}}}})).await?;
    ensure!(reordered["versionId"] == frozen_version);
    let reordered_status = author
        .call(
            &router,
            Method::GET,
            &format!("/api/v2/policies/{future}/software/rollout"),
            None,
        )
        .await?;
    ensure!(
        reordered_status.1["stages"][0]["verifiedSuccess"] == 1
            && reordered_status.1["stages"][1]["verifiedSuccess"] == 0,
        "stage edit reused another scope's evidence: {reordered_status:?}"
    );
    let rebound = write(
        &mut author,
        &router,
        &policy_path,
        2,
        json!({"action":"put","enabled":false,"definition":authored("required_install", &second_operation)}),
    )
    .await?;
    ensure!(
        rebound["versionId"] != published["versionId"],
        "reapproval must create a new execution version: {rebound}"
    );
    write(
        &mut author,
        &router,
        &future_path,
        6,
        json!({"action":"disable"}),
    )
    .await?;
    let failed_policy = Uuid::new_v4();
    let failed_path = format!("/api/v2/policies/{failed_policy}");
    write(&mut author,&router,&failed_path,0,json!({"action":"put","enabled":true,"definition":authored("required_install",&second_operation)})).await?;
    let failed_task = claim(&router).await?;
    ensure!(
        event(&router, &failed_task, json!({"kind":"received"}))
            .await?
            .0
            == StatusCode::OK
    );
    ensure!(
        event(&router, &failed_task, json!({"kind":"start"}))
            .await?
            .0
            == StatusCode::OK
    );
    ensure!(event(&router,&failed_task,json!({"kind":"software_result","intent":"install","installerExitCode":1,"detection":"absent","rebootRequired":false,"diagnostics":{"stdout":"","stderr":"","durationMs":1,"executedAt":1,"failure":null}})).await?.0==StatusCode::OK);
    let failed_detail = author
        .call(
            &router,
            Method::GET,
            &format!(
                "/api/v2/policies/{failed_policy}/runs/{}",
                failed_task["payload"]["taskId"].as_str().unwrap()
            ),
            None,
        )
        .await?;
    ensure!(
        failed_detail.1["effect"] == "failed",
        "known detector failure: {failed_detail:?}"
    );
    write(
        &mut author,
        &router,
        &failed_path,
        1,
        json!({"action":"disable"}),
    )
    .await?;
    let reboot_policy = Uuid::new_v4();
    let reboot_path = format!("/api/v2/policies/{reboot_policy}");
    write(&mut author,&router,&reboot_path,0,json!({"action":"put","enabled":true,"definition":authored("required_install",&second_operation)})).await?;
    let reboot_task = claim(&router).await?;
    ensure!(
        event(&router, &reboot_task, json!({"kind":"received"}))
            .await?
            .0
            == StatusCode::OK
    );
    ensure!(
        event(&router, &reboot_task, json!({"kind":"start"}))
            .await?
            .0
            == StatusCode::OK
    );
    ensure!(event(&router,&reboot_task,json!({"kind":"software_result","intent":"install","installerExitCode":0,"detection":"absent","rebootRequired":true,"diagnostics":{"stdout":"","stderr":"","durationMs":1,"executedAt":1,"failure":null}})).await?.0==StatusCode::OK);
    let reboot_detail = author
        .call(
            &router,
            Method::GET,
            &format!(
                "/api/v2/policies/{reboot_policy}/runs/{}",
                reboot_task["payload"]["taskId"].as_str().unwrap()
            ),
            None,
        )
        .await?;
    ensure!(
        reboot_detail.1["effect"] == "waiting_reboot",
        "pending reboot: {reboot_detail:?}"
    );
    let reboot_retry = agent(
        &router,
        "/api/agent/v3/tasks/claim",
        Some(json!({"wireVersion":3,"operationId":Uuid::new_v4()})),
    )
    .await?;
    ensure!(
        reboot_retry.1["task"].is_null(),
        "reboot caused blind retry: {reboot_retry:?}"
    );
    ensure!(event(&router,&reboot_task,json!({"kind":"software_result","intent":"install","installerExitCode":0,"detection":"present","rebootRequired":false,"diagnostics":{"stdout":"","stderr":"","durationMs":1,"executedAt":1,"failure":null}})).await?.0==StatusCode::OK);
    write(
        &mut author,
        &router,
        &reboot_path,
        1,
        json!({"action":"disable"}),
    )
    .await?;
    let unknown_policy = Uuid::new_v4();
    write(&mut author,&router,&format!("/api/v2/policies/{unknown_policy}"),0,json!({"action":"put","enabled":true,"definition":authored("required_install",&second_operation)})).await?;
    let unknown_task = claim(&router).await?;
    ensure!(
        event(&router, &unknown_task, json!({"kind":"received"}))
            .await?
            .0
            == StatusCode::OK
    );
    ensure!(
        event(&router, &unknown_task, json!({"kind":"start"}))
            .await?
            .0
            == StatusCode::OK
    );
    ensure!(event(&router,&unknown_task,json!({"kind":"software_result","intent":"install","installerExitCode":null,"detection":"unknown","rebootRequired":false,"diagnostics":{"stdout":"","stderr":"","durationMs":1,"executedAt":1,"failure":null}})).await?.0==StatusCode::OK);
    let next_password = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI";
    let next_credential = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM";
    author.operation = Some(Uuid::new_v4());
    let next_enrollment = author
        .call(
            &router,
            Method::POST,
            "/api/v3/enrollments",
            Some(json!({"deviceId":DEVICE,"password":next_password,"source":"agent.builtin"})),
        )
        .await?;
    ensure!(
        next_enrollment.0.is_success(),
        "replacement enrollment: {next_enrollment:?}"
    );
    author.operation = None;
    let next_registration=agent_call(&router,Method::POST,"/api/agent/v3/registrations",None,Some(json!({"wireVersion":3,"operationId":Uuid::new_v4(),"enrollmentId":next_enrollment.1["enrollmentId"],"password":next_password,"credential":next_credential,"platform":"macos","architecture":"aarch64","capabilities":["inventory.basic.v3","software.execute.v3"]}))).await?;
    ensure!(
        next_registration.0 == StatusCode::CREATED,
        "replacement registration: {next_registration:?}"
    );
    let after_reenroll = agent_call(
        &router,
        Method::POST,
        "/api/agent/v3/tasks/claim",
        Some(next_credential),
        Some(json!({"wireVersion":3,"operationId":Uuid::new_v4()})),
    )
    .await?;
    ensure!(
        after_reenroll.0 == StatusCode::OK && after_reenroll.1["task"].is_null(),
        "unknown side effect retried after registration replacement: {after_reenroll:?}"
    );
    ensure!(stack.shutdown().join().await?.is_clean());
    Ok(())
}
