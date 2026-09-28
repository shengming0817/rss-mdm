#![allow(
    clippy::cognitive_complexity,
    reason = "test scenarios preserve distinct recovery assertions"
)]
use crate::test_support::*;
pub(crate) async fn revoke_http_matrix(session: &Browser) -> Result<()> {
    let (grant, request, registration, credential, epoch) = (
        uuid::Uuid::new_v4(),
        uuid::Uuid::new_v4(),
        uuid::Uuid::new_v4(),
        uuid::Uuid::new_v4(),
        uuid::Uuid::new_v4(),
    );
    let coverage = serde_json::to_string(&rss_mdm_inventory::coverage())?;
    pg(&format!("INSERT INTO mdm_access.grants(tenant_id,id,actor,instance,device,purpose,state,expires_at) VALUES('{TENANT}','{grant}','revoke-fixture','{INSTANCE}','revoke-device','enrollment','consumed',clock_timestamp()+interval '200 seconds');
        INSERT INTO mdm_access.requests(tenant_id,id,grant_id,source) VALUES('{TENANT}','{request}','{grant}','mdm.windows');
        INSERT INTO mdm_access.devices VALUES('{TENANT}','revoke-device');
        INSERT INTO mdm_access.registrations VALUES('{TENANT}','{registration}','revoke-device','mdm',1,'{request}','active');
        INSERT INTO mdm_access.credentials VALUES('{TENANT}','{credential}','{registration}','mdm',repeat('c',64),'active');
        INSERT INTO mdm_access.report_sources(tenant_id,registration,source,epoch,coverage,enabled) VALUES('{TENANT}','{registration}','mdm.windows','{epoch}','{coverage}',true);"))?;
    let path = format!("/api/v3/devices/revoke-device/registrations/{registration}/revoke");
    let listing = "/api/v3/devices/revoke-device/registrations";
    let fixture = authority::Authority::open().await?;
    let initial = fixture.router(fixture.authorization().merge(fixture.enrollment()))?;
    set_device_grants(
        &mut session.clone(),
        &initial,
        "revoke-device",
        &["inventory_read"],
    )
    .await?;
    let denied = fixture.router(fixture.authorization().merge(fixture.enrollment()))?;
    let mut browser = session.clone();
    ensure!(browser.call(&denied, Method::GET, listing, None).await?.0 == StatusCode::FORBIDDEN);
    browser.operation = Some(uuid::Uuid::new_v4());
    ensure!(
        browser
            .call(&denied, Method::POST, &path, Some(json!({})))
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    set_device_grants(&mut browser, &denied, "revoke-device", &["credentials"]).await?;
    let allowed = fixture.router(fixture.authorization().merge(fixture.enrollment()))?;
    browser = session.clone();
    let listed = browser.call(&allowed, Method::GET, listing, None).await?;
    ensure!(
        listed.0 == StatusCode::OK
            && listed.1["items"][0]["registrationId"] == registration.to_string()
    );
    ensure!(listed.1["items"][0]["status"] == "active" && listed.1["nextCursor"].is_null());
    ensure!(!listed.1.to_string().contains("password") && !listed.1.to_string().contains("secret"));
    ensure!(
        browser
            .call(
                &allowed,
                Method::GET,
                "/api/v3/devices/outside/registrations",
                None
            )
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    ensure!(
        browser
            .call(
                &allowed,
                Method::GET,
                &format!("{listing}?after={registration}"),
                None
            )
            .await?
            .1["items"]
            == json!([])
    );
    ensure!(
        browser
            .call(
                &allowed,
                Method::GET,
                &format!("{listing}?after=invalid"),
                None
            )
            .await?
            .0
            == StatusCode::BAD_REQUEST
    );
    browser.operation = Some(uuid::Uuid::new_v4());
    for bad in [
        "/api/v3/enrollments/not-a-uuid/resume",
        "/api/v3/enrollments/not-a-uuid/cancel",
        "/api/v3/devices/revoke-device/registrations/not-a-uuid/revoke",
    ] {
        let response = browser
            .call(&allowed, Method::POST, bad, Some(json!({})))
            .await?;
        ensure!(response.0 == StatusCode::BAD_REQUEST && response.1["code"] == "malformed_request");
    }
    for body in [None, Some(json!(null)), Some(json!({"unexpected":true}))] {
        let response = browser.call(&allowed, Method::POST, &path, body).await?;
        ensure!(response.0 == StatusCode::BAD_REQUEST && response.1["code"] == "malformed_request");
    }
    let cookie = browser
        .cookies
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("; ");
    let malformed = Request::builder()
        .method(Method::POST)
        .uri(&path)
        .header("host", "mdm.example.test")
        .header("origin", "https://mdm.example.test")
        .header("x-identity-request", "1")
        .header("cookie", cookie)
        .header("x-csrf-token", browser.csrf.as_ref().unwrap())
        .header("idempotency-key", browser.operation.unwrap().to_string())
        .header("content-type", "application/json")
        .body(Body::from("{"))?;
    let response = allowed.clone().oneshot(malformed).await?;
    ensure!(response.status() == StatusCode::BAD_REQUEST);
    let csrf_saved = browser.csrf.take();
    ensure!(
        browser
            .call(&allowed, Method::POST, &path, Some(json!({})))
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    browser.csrf = csrf_saved;
    let first = browser
        .call(&allowed, Method::POST, &path, Some(json!({})))
        .await?;
    ensure!(first.0 == StatusCode::OK, "revoke must use online Identity");
    ensure!(
        browser
            .call(&allowed, Method::POST, &path, Some(json!({})))
            .await?
            == first
    );
    ensure!(
        browser.call(&allowed, Method::GET, listing, None).await?.1["items"][0]["status"]
            == "revoked"
    );
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_access.registrations r JOIN mdm_access.credentials c ON c.tenant_id=r.tenant_id AND c.registration=r.id JOIN mdm_access.report_sources s ON s.tenant_id=r.tenant_id AND s.registration=r.id WHERE r.tenant_id='{TENANT}' AND r.id='{registration}' AND r.state='revoked' AND c.state='revoked' AND NOT s.enabled"
        ))?.trim() == "1"
    );
    ensure!(
        audit_count(|r| r.source() == "mdm.business"
            && r.operation() == Some(browser.operation.unwrap().to_string().as_str())
            && r.action() == "credential_revoke"
            && r.result() == "success")?
            == 1
    );
    Ok(())
}

#[tokio::test]
#[ignore = "MODULE=device.revocation: real capability boundary"]
async fn http_revoke_is_atomic_authorized_and_idempotent() -> Result<()> {
    let fixture = authority::Authority::open().await?;
    revoke_http_matrix(&fixture.browser("other")?).await?;
    Ok(())
}

mod storage;
