#![allow(
    clippy::cognitive_complexity,
    reason = "quota integration scenarios assert independent persistence and authorization risks"
)]
use crate::test_support::*;
use uuid::Uuid;
const DEFAULTS: &str = "/api/v1/registration-quotas/defaults";
const ME: &str = "/api/v1/registration-quotas/me";
const SELF: &str = "/api/v1/self-enrollments";
fn native() -> Value {
    json!({"password":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","source":"mdm.windows","windowsProfile":"Device"})
}
async fn call(
    browser: &mut Browser,
    router: &Router,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> Result<Value> {
    let (status, value) = browser.call(router, method, path, body).await?;
    ensure!(status == StatusCode::OK, "{path}: {status} {value}");
    Ok(value)
}
async fn write(
    browser: &mut Browser,
    router: &Router,
    method: Method,
    path: &str,
    body: Value,
) -> Result<Value> {
    browser.operation = Some(Uuid::new_v4());
    call(browser, router, method, path, Some(body)).await
}
async fn hosted(
    f: &authority::Authority,
) -> Result<(Router, Browser, Browser, software::HttpServer)> {
    let router = f.router(f.authorization().merge(f.enrollment()))?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let network = (
        Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(12))
            .build()?,
        format!("http://{}", listener.local_addr()?),
    );
    let server = software::HttpServer::start(listener, router.clone());
    let mut admin = f.browser("admin")?;
    let mut other = f.browser("other")?;
    admin.network = Some(network.clone());
    other.network = Some(network);
    let subject = browser_subject(&other, &router).await?;
    identity::set_grants(case_tenant(), &subject, vec![]).await?;
    Ok((router, admin, other, server))
}
fn windows(usage: &Value) -> &Value {
    usage["channels"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["channel"] == "windows_mdm")
        .unwrap()
}
#[tokio::test]
#[ignore = "MODULE=enrollment.quotas: real HTTP concurrency and durable quota admission"]
async fn concurrent_self_enrollment_replays_and_preserves_live_reservations() -> Result<()> {
    let f = authority::Authority::open().await?;
    let (router, mut admin, mut other, _server) = hosted(&f).await?;
    browser_consumer(&admin, &other).await?;
    let defaults = call(&mut admin, &router, Method::GET, DEFAULTS, None).await?;
    ensure!(defaults["limits"] == json!({"agent":20,"windows_mdm":20,"macos_mdm":20}));
    write(
        &mut admin,
        &router,
        Method::PUT,
        DEFAULTS,
        json!({"expectedRevision":0,"limits":{"agent":20,"windows_mdm":1,"macos_mdm":20}}),
    )
    .await?;
    let mut first = other.clone();
    first.operation = Some(Uuid::new_v4());
    let mut second = other.clone();
    second.operation = Some(Uuid::new_v4());
    let (a, b) = tokio::join!(
        first.call(&router, Method::POST, SELF, Some(native())),
        second.call(&router, Method::POST, SELF, Some(native()))
    );
    let (a, b) = (a?, b?);
    ensure!([a.0, b.0].iter().filter(|s| **s == StatusCode::OK).count() == 1);
    let (mut winner, receipt, loser) = if a.0 == StatusCode::OK {
        (first, a.1, b)
    } else {
        (second, b.1, a)
    };
    ensure!(loser.0 == StatusCode::TOO_MANY_REQUESTS && loser.1["code"] == "registration_limit");
    ensure!(call(&mut winner, &router, Method::POST, SELF, Some(native())).await? == receipt);
    let before = call(&mut other, &router, Method::GET, ME, None).await?;
    ensure!(windows(&before)["active"] == 0 && windows(&before)["reserved"] == 1);
    ensure!(
        before["channels"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|c| c["channel"] != "windows_mdm")
            .all(|c| c["used"] == 0)
    );
    write(
        &mut admin,
        &router,
        Method::PUT,
        DEFAULTS,
        json!({"expectedRevision":1,"limits":{"agent":20,"windows_mdm":0,"macos_mdm":20}}),
    )
    .await?;
    let low = call(&mut other, &router, Method::GET, ME, None).await?;
    ensure!(
        windows(&low)["used"] == 1
            && windows(&low)["overLimit"] == 1
            && windows(&low)["canEnroll"] == false
    );
    let id = receipt["enrollmentId"].as_str().unwrap();
    write(
        &mut winner,
        &router,
        Method::POST,
        &format!("/api/v1/enrollments/{id}/resume"),
        json!({"password":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA"}),
    )
    .await?;
    ensure!(windows(&call(&mut other, &router, Method::GET, ME, None).await?)["used"] == 1);
    let mut stranger = f.browser("admin")?;
    ensure!(
        stranger
            .call(
                &router,
                Method::GET,
                &format!("/api/v1/enrollments/{id}"),
                None
            )
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    write(
        &mut winner,
        &router,
        Method::POST,
        &format!("/api/v1/enrollments/{id}/cancel"),
        json!({}),
    )
    .await?;
    ensure!(windows(&call(&mut other, &router, Method::GET, ME, None).await?)["used"] == 0);
    other.operation = Some(Uuid::new_v4());
    ensure!(
        other
            .call(&router, Method::POST, SELF, Some(native()))
            .await?
            .0
            == StatusCode::TOO_MANY_REQUESTS
    );
    // Configuration is durable across service reconstruction and revisioned writes.
    let restarted = authority::Authority::open().await?;
    let rerouter = restarted.router(restarted.enrollment())?;
    let mut reread = restarted.browser("admin")?;
    ensure!(call(&mut reread, &rerouter, Method::GET, DEFAULTS, None).await?["revision"] == 2);
    Ok(())
}
#[tokio::test]
#[ignore = "MODULE=enrollment.quotas: overrides, expiry, organization exemption and responsibility"]
async fn overrides_inherit_and_organization_responsibility_is_optional_and_exempt() -> Result<()> {
    let f = authority::Authority::open().await?;
    let (router, mut admin, mut other, _server) = hosted(&f).await?;
    let me = call(&mut other, &router, Method::GET, ME, None).await?;
    let target = json!({"tenantId":case_tenant(),"instanceId":me["instanceId"],"principalId":me["principalId"]});
    let path = format!(
        "/api/v1/registration-quotas/users/{}/{}",
        me["instanceId"].as_str().unwrap(),
        me["principalId"].as_str().unwrap()
    );
    write(
        &mut admin,
        &router,
        Method::PUT,
        &path,
        json!({"expectedRevision":0,"limits":{"agent":0,"windows_mdm":1,"macos_mdm":null}}),
    )
    .await?;
    let own = call(&mut other, &router, Method::GET, ME, None).await?;
    ensure!(windows(&own)["limit"] == 1);
    ensure!(
        own["channels"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["channel"] == "macos_mdm")
            .unwrap()["limit"]
            == 20
    );
    ensure!(other.call(&router, Method::GET, DEFAULTS, None).await?.0 == StatusCode::FORBIDDEN);
    other.operation = Some(Uuid::new_v4());
    ensure!(other.call(&router,Method::PUT,&path,Some(json!({"expectedRevision":1,"limits":{"agent":20,"windows_mdm":20,"macos_mdm":20}}))).await?.0==StatusCode::FORBIDDEN);
    let receipt = write(&mut other, &router, Method::POST, SELF, native()).await?;
    let self_device = receipt["deviceId"].as_str().unwrap();
    ensure!(self_device.starts_with("self:"));
    let device = case::name("organization");
    let mut org = native();
    org["deviceId"] = json!(device);
    write(
        &mut admin,
        &router,
        Method::POST,
        "/api/v1/enrollments",
        org,
    )
    .await?;
    let responsibility = format!("/api/v1/devices/{device}/registration-user");
    ensure!(call(&mut admin, &router, Method::GET, &responsibility, None).await?["user"].is_null());
    let assigned = write(
        &mut admin,
        &router,
        Method::PUT,
        &responsibility,
        json!({"expectedRevision":0,"user":target}),
    )
    .await?;
    ensure!(assigned["user"] == target);
    ensure!(windows(&call(&mut other, &router, Method::GET, ME, None).await?)["used"] == 1);
    write(
        &mut admin,
        &router,
        Method::PUT,
        &responsibility,
        json!({"expectedRevision":1,"user":null}),
    )
    .await?;
    ensure!(call(&mut admin, &router, Method::GET, &responsibility, None).await?["user"].is_null());
    ensure!(
        other
            .call(&router, Method::GET, &responsibility, None)
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    ensure!(
        admin
            .call(
                &router,
                Method::GET,
                &format!("/api/v1/devices/{self_device}/registration-user"),
                None
            )
            .await?
            .0
            == StatusCode::NOT_FOUND
    );
    write(
        &mut admin,
        &router,
        Method::PUT,
        &path,
        json!({"expectedRevision":1,"limits":{"agent":null,"windows_mdm":null,"macos_mdm":null}}),
    )
    .await?;
    ensure!(windows(&call(&mut other, &router, Method::GET, ME, None).await?)["limit"] == 20);
    let mut tx = f.access.begin(case_tenant()).await?;
    sqlx::query("UPDATE mdm_access.requests SET expires_at=clock_timestamp()-interval '1 second' WHERE tenant_id=$1::uuid AND id=$2").bind(case_tenant()).bind(Uuid::parse_str(receipt["enrollmentId"].as_str().unwrap())?).execute(&mut *tx).await?;
    tx.commit().await?;
    ensure!(windows(&call(&mut other, &router, Method::GET, ME, None).await?)["used"] == 0);
    Ok(())
}
#[tokio::test]
#[ignore = "MODULE=enrollment.quotas: activation and revocation use one allocation"]
async fn active_registration_replaces_reservation_and_revocation_releases_it() -> Result<()> {
    let f = authority::Authority::open().await?;
    let (router, mut admin, mut other, _server) = hosted(&f).await?;
    let receipt = write(&mut other, &router, Method::POST, SELF, native()).await?;
    let other_proof = crate::device::test_support::admin(case_tenant(), "other-a").await?;
    let service = crate::device::DeviceService::new(
        f.access.registration(),
        case_tenant().into(),
        f.audit.clone(),
    );
    let command = crate::device::BindRegistration {
        operation_id: Uuid::new_v4(),
        request_id: Uuid::parse_str(receipt["enrollmentId"].as_str().unwrap())?,
        expected_generation: 0,
        source: rss_mdm_inventory::ReportSource::MdmWindows,
    };
    let credential =
        crate::device::test_support::proof(case_tenant(), rss_mdm_inventory::Channel::Mdm, 77);
    let bound = service
        .bind(&other_proof, &credential, command.clone())
        .await?;
    ensure!(service.bind(&other_proof, &credential, command).await? == bound);
    let usage = call(&mut other, &router, Method::GET, ME, None).await?;
    ensure!(
        windows(&usage)["active"] == 1
            && windows(&usage)["reserved"] == 0
            && windows(&usage)["used"] == 1
    );
    write(
        &mut admin,
        &router,
        Method::POST,
        &format!(
            "/api/v1/devices/{}/registrations/{}/revoke",
            bound.device, bound.registration
        ),
        json!({}),
    )
    .await?;
    ensure!(windows(&call(&mut other, &router, Method::GET, ME, None).await?)["used"] == 0);
    Ok(())
}

/// An explicitly selected browser checkout consumes only these public HTTP APIs.
/// Ordinary backend T2 runs do not require a frontend repository or Node toolchain.
async fn browser_consumer(admin: &Browser, user: &Browser) -> Result<()> {
    let Ok(checkout) = std::env::var("MDM_REGISTRATION_WEB_WORKTREE") else {
        return Ok(());
    };
    use std::os::unix::fs::OpenOptionsExt;
    let path = std::env::temp_dir().join(format!("mdm-registration-joint-{}.json", Uuid::new_v4()));
    let actor = |b: &Browser| json!({"cookie":b.cookies.iter().map(|(k,v)|format!("{k}={v}")).collect::<Vec<_>>().join("; "),"csrf":b.csrf});
    let manifest = json!({"origin":admin.network.as_ref().unwrap().1,"tenant":case_tenant(),"admin":actor(admin),"user":actor(user)});
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    file.write_all(&serde_json::to_vec(&manifest)?)?;
    drop(file);
    let child = tokio::process::Command::new("pnpm")
        .args(["test:mdm:joint"])
        .current_dir(checkout)
        .env("MDM_REGISTRATION_FIXTURE", &path)
        .kill_on_drop(true)
        .output();
    let outcome = tokio::time::timeout(Duration::from_secs(60), child).await;
    std::fs::remove_file(path)?;
    let output = outcome??;
    ensure!(
        output.status.success(),
        "browser HTTP consumer failed: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    // The consumer leaves no settings or grants for the following contention scenario.
    let mut browser = admin.clone();
    let configuration = authority::Authority::open().await?;
    let router = configuration.router(configuration.enrollment())?;
    let usage = call(&mut user.clone(), &router, Method::GET, ME, None).await?;
    let target = format!(
        "/api/v1/registration-quotas/users/{}/{}",
        usage["instanceId"].as_str().unwrap(),
        usage["principalId"].as_str().unwrap()
    );
    write(
        &mut browser,
        &router,
        Method::PUT,
        &target,
        json!({"expectedRevision":2,"limits":{"agent":null,"windows_mdm":null,"macos_mdm":null}}),
    )
    .await?;
    println!("rss-web browser client consumed real registration HTTP and PostgreSQL");
    Ok(())
}
