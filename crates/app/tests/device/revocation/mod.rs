#![allow(
    clippy::cognitive_complexity,
    reason = "test scenarios preserve distinct recovery assertions"
)]
use crate::audit_test_support::audit_count;
use crate::test_support::{http::*, process::*, runtime::*, *};
pub(crate) async fn revoke_http_matrix(session: &Browser) -> Result<()> {
    let (grant, request, registration, credential, epoch) = (
        uuid::Uuid::new_v4(),
        uuid::Uuid::new_v4(),
        uuid::Uuid::new_v4(),
        uuid::Uuid::new_v4(),
        uuid::Uuid::new_v4(),
    );
    let device = case::name("revoke-device");
    let locator = crate::test_support::runtime::secret("revoke-device")
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    pg(&format!("INSERT INTO mdm_access.grants(tenant_id,id,actor,instance,device,purpose,state,expires_at) VALUES('{TENANT}','{grant}','revoke-fixture','{INSTANCE}','{device}','enrollment','consumed',clock_timestamp()+interval '200 seconds');
        INSERT INTO mdm_access.requests(tenant_id,id,grant_id,source,windows_profile) VALUES('{TENANT}','{request}','{grant}','mdm.windows','Device');
        INSERT INTO mdm_access.devices VALUES('{TENANT}','{device}');
        INSERT INTO mdm_access.registrations(tenant_id,id,device,channel,generation,request_id,state,purpose,epoch) VALUES('{TENANT}','{registration}','{device}','mdm',1,'{request}','active','primary',gen_random_uuid());
        INSERT INTO mdm_access.credentials VALUES('{TENANT}','{credential}','{registration}','mdm','{locator}','active');
        INSERT INTO mdm_access.report_sources(tenant_id,registration,source,epoch,enabled) VALUES('{TENANT}','{registration}','mdm.windows','{epoch}',true);", TENANT = case_tenant()))?;
    let path = format!("/api/v1/devices/{device}/registrations/{registration}/revoke");
    let listing = &format!("/api/v1/devices/{device}/registrations");
    let mut fixture = authority::Authority::open().await?;
    let fixture_resources = std::mem::take(&mut fixture.resources);
    fixture_resources.finish(async {
    change_device_grants(&mut session.clone(), device, &["inventory_read"]).await?;
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
    change_device_grants(&mut browser, device, &["credentials"]).await?;
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
                "/api/v1/devices/outside/registrations",
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
            .0
            == StatusCode::BAD_REQUEST
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
    // More than one default page proves filtering and ordering precede LIMIT.
    pg(&format!("CREATE TEMP TABLE registration_pages AS SELECT n,gen_random_uuid() AS request,gen_random_uuid() AS registration FROM generate_series(2,1002) n;
        INSERT INTO mdm_access.requests(tenant_id,id,source,windows_profile) SELECT '{tenant}',request,'mdm.windows','Full' FROM registration_pages;
        INSERT INTO mdm_access.registrations(tenant_id,id,device,channel,generation,request_id,state,purpose,epoch) SELECT '{tenant}',registration,'{device}','mdm',n,request,'revoked','primary',gen_random_uuid() FROM registration_pages;", tenant=case_tenant()))?;
    let query = format!("{listing}?filter=status==revoked&sort=-generation&fields=registrationId,generation,userContextId");
    let (status, first_page) = browser.call(&allowed, Method::GET, &query, None).await?;
    ensure!(status == StatusCode::OK, "registration page: {status} {first_page}");
    ensure!(first_page["items"].as_array().unwrap().len() == 1000);
    ensure!(first_page["items"][0]["generation"] == 1002);
    ensure!(first_page["items"][999]["generation"] == 3);
    ensure!(first_page["items"][0]["userContextId"] == first_page["items"][0]["registrationId"]);
    ensure!(first_page["items"][0].get("status").is_none());
    let cursor = first_page["nextCursor"].as_str().unwrap();
    let (status, last_page) = browser.call(&allowed, Method::GET, &format!("{query}&cursor={cursor}"), None).await?;
    ensure!(status == StatusCode::OK && last_page["items"].as_array().unwrap().len() == 1);
    ensure!(last_page["items"][0]["generation"] == 2 && last_page["nextCursor"].is_null());
    ensure!(browser.call(&allowed, Method::GET, &format!("{listing}?sort=generation&cursor={cursor}"), None).await?.0 == StatusCode::CONFLICT);
    ensure!(browser.call(&allowed, Method::GET, &format!("{listing}?limit=1001"), None).await?.0 == StatusCode::BAD_REQUEST);
    browser.operation = Some(uuid::Uuid::new_v4());
    for bad in [
        "/api/v1/enrollments/not-a-uuid/resume",
        "/api/v1/enrollments/not-a-uuid/cancel",
        "/api/v1/devices/{device}/registrations/not-a-uuid/revoke",
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
        , TENANT = case_tenant()))?.trim() == "1"
    );
    ensure!(
        audit_count(|r| r.source() == "mdm.business"
            && r.operation() == Some(browser.operation.unwrap().to_string().as_str())
            && r.action() == "credential_revoke"
            && r.result() == "success").await?
            == 1
    );
    Ok(())

    }).await
}

#[tokio::test]
#[ignore = "MODULE=device.revocation: real capability boundary"]
async fn http_revoke_is_atomic_authorized_and_idempotent() -> Result<()> {
    let mut fixture = authority::Authority::open().await?;
    let fixture_resources = std::mem::take(&mut fixture.resources);
    fixture_resources
        .finish(async {
            revoke_http_matrix(&fixture.browser("other")?).await?;
            Ok(())
        })
        .await
}

mod storage;
