#![allow(
    clippy::cognitive_complexity,
    reason = "test scenarios preserve distinct recovery assertions"
)]
use crate::test_support::*;
pub(crate) async fn enrollment_matrix(router: &Router, browser: &mut Browser) -> Result<()> {
    let issue = "/api/v3/enrollments";
    set_device_grants(
        browser,
        router,
        crate::test_support::case::name("device-1"),
        &["inventory_read", "enrollment"],
    )
    .await?;
    let enrollment_fixture = authority::Authority::open().await?;
    let enrollment_router = enrollment_fixture.router(enrollment_fixture.enrollment())?;
    let mut enrollment_browser = browser.clone();
    enrollment_browser.operation = Some(uuid::Uuid::new_v4());
    ensure!(
        enrollment_browser
            .call(
                &enrollment_router,
                Method::POST,
                issue,
                Some(json!({"deviceId":crate::test_support::case::name("device-1"),"password":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","source":"mdm.windows","windowsProfile":"Device"}))
            )
            .await?
            .0
            == StatusCode::OK
    );

    for profile in [json!(null), json!("full"), json!("Unknown")] {
        browser.operation = Some(uuid::Uuid::new_v4());
        let mut body = json!({"deviceId":crate::test_support::case::name("device-1"),"password":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","source":"mdm.windows"});
        if !profile.is_null() {
            body["windowsProfile"] = profile;
        }
        ensure!(
            browser
                .call(router, Method::POST, issue, Some(body))
                .await?
                .0
                == StatusCode::BAD_REQUEST
        );
    }
    browser.operation = Some(uuid::Uuid::new_v4());
    let (status, grant) = browser
        .call(
            router,
            Method::POST,
            issue,
            Some(json!({"deviceId":crate::test_support::case::name("device-1"),"password":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","source":"mdm.windows","windowsProfile":"Device"})),
        )
        .await?;
    ensure!(
        status == StatusCode::OK,
        "enrollment issue failed: {status} {grant}"
    );
    ensure!(
        browser
            .call(
                router,
                Method::POST,
                issue,
                Some(json!({"deviceId":crate::test_support::case::name("device-1"),"password":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","source":"mdm.windows","windowsProfile":"Device"}))
            )
            .await?
            .1
            == grant,
        "issue replay changed result"
    );
    ensure!(browser.call(router, Method::POST, issue, Some(json!({"deviceId":crate::test_support::case::name("device-1"),"password":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","source":"mdm.windows","windowsProfile":"Full"}))).await?.0 == StatusCode::CONFLICT, "changing the authorized Windows profile reused an operation");
    let enrollment = grant["enrollmentId"].as_str().unwrap();
    let status_path = format!("/api/v3/enrollments/{enrollment}");
    let current = browser
        .call(router, Method::GET, &status_path, None)
        .await?;
    ensure!(
        current.0 == StatusCode::OK
            && current.1["status"] == "pending"
            && current.1["registrationId"].is_null()
    );
    let resume = format!("/api/v3/enrollments/{enrollment}/resume");
    browser.operation = Some(uuid::Uuid::new_v4());
    let (_, resumed) = browser
        .call(
            router,
            Method::POST,
            &resume,
            Some(json!({"password": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA"})),
        )
        .await?;
    ensure!(resumed["status"] == "pending");
    ensure!(
        browser
            .call(
                router,
                Method::POST,
                &resume,
                Some(json!({"password":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA"}))
            )
            .await?
            .1
            == resumed
    );
    browser.operation = Some(uuid::Uuid::new_v4());
    ensure!(browser.call(router, Method::POST, issue, Some(json!({"deviceId":"outside","password":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","source":"mdm.windows","windowsProfile":"Device"}))).await?.0 == StatusCode::FORBIDDEN);
    set_device_grants(
        browser,
        router,
        crate::test_support::case::name("device-1"),
        &["inventory_read"],
    )
    .await?;
    let restarted_fixture = authority::Authority::open().await?;
    let restarted = restarted_fixture.router(restarted_fixture.enrollment())?;
    let mut denied = browser.clone();
    denied.operation = Some(uuid::Uuid::new_v4());
    ensure!(
        denied
            .call(
                &restarted,
                Method::POST,
                &resume,
                Some(json!({"password":"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA"}))
            )
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    browser.operation = Some(uuid::Uuid::new_v4());
    set_device_grants(
        browser,
        router,
        crate::test_support::case::name("device-1"),
        &["inventory_read", "enrollment"],
    )
    .await?;
    let cancel = format!("/api/v3/enrollments/{enrollment}/cancel");
    let (status, cancelled) = browser
        .call(router, Method::POST, &cancel, Some(json!({})))
        .await?;
    ensure!(
        browser
            .call(router, Method::GET, &status_path, None)
            .await?
            .1["status"]
            == "cancelled"
    );
    ensure!(status == StatusCode::OK && cancelled["status"] == "cancelled");
    browser.operation = Some(uuid::Uuid::new_v4());
    ensure!(
        browser
            .call(
                router,
                Method::POST,
                &resume,
                Some(json!({"password":"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA"}))
            )
            .await?
            .0
            == StatusCode::CONFLICT
    );
    let mut anonymous = Browser::default();
    ensure!(
        anonymous
            .call(
                router,
                Method::POST,
                issue,
                Some(json!({"deviceId":crate::test_support::case::name("device-1"),"password":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","source":"mdm.windows","windowsProfile":"Device"}))
            )
            .await?
            .0
            == StatusCode::UNAUTHORIZED
    );
    ensure!(
        audit_count(|r| r.action() == "enrollment_create"
            && r.result() == "denied"
            && r.actor().is_none())?
            > 0,
        "preauthentication denial lost action"
    );
    println!("enrollment identity/authorization/replay/audit failure matrix passed");
    Ok(())
}

#[tokio::test]
#[ignore = "MODULE=enrollment.http: create, status, resume, cancel and authorization"]
async fn enrollment_lifecycle_and_reauthorization() -> Result<()> {
    let fixture = authority::Authority::open().await?;
    let router = fixture.router(fixture.authorization().merge(fixture.enrollment()))?;
    let mut browser = fixture.browser("other")?;
    enrollment_matrix(&router, &mut browser).await?;
    Ok(())
}
