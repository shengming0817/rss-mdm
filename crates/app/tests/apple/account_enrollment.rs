//! Account-driven enrollment uses real Identity, PostgreSQL, signed CMS, step-ca and mTLS.
use super::*;
use axum::http::{HeaderMap, header};
use sqlx::Connection;
use x509_cert::der::{Decode, asn1::OctetString};

async fn request(
    f: &Fixture,
    method: Method,
    path: &str,
    body: Vec<u8>,
    headers: &[(&str, String)],
) -> Result<(StatusCode, HeaderMap, Vec<u8>)> {
    let mut r = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "mdm.example.test");
    for (key, value) in headers {
        r = r.header(*key, value);
    }
    let response = f.router.clone().oneshot(r.body(Body::from(body))?).await?;
    let (parts, body) = response.into_parts();
    Ok((
        parts.status,
        parts.headers,
        axum::body::to_bytes(body, 1024 * 1024).await?.to_vec(),
    ))
}
fn cookies(browser: &Browser, flow: Option<&str>) -> String {
    let mut values = browser
        .cookies
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>();
    if let Some(flow) = flow {
        values.push(flow.to_owned())
    }
    values.join("; ")
}
async fn start(f: &Fixture, path: &str, name: &str) -> Result<String> {
    let r = request(
        f,
        Method::GET,
        &format!("{path}?user-identifier={name}"),
        vec![],
        &[],
    )
    .await?;
    ensure!(
        r.0 == StatusCode::OK,
        "browser start: {} {}",
        r.0,
        String::from_utf8_lossy(&r.2)
    );
    ensure!(
        r.1[header::CONTENT_SECURITY_POLICY]
            .to_str()?
            .contains("frame-ancestors 'none'")
    );
    let cookie = r.1[header::SET_COOKIE].to_str()?;
    ensure!(cookie.contains("Secure; HttpOnly; SameSite=Lax"));
    Ok(cookie.split(';').next().unwrap().to_owned())
}
async fn finish(
    f: &Fixture,
    browser: &Browser,
    cookie: &str,
    origin: &str,
    csrf: &str,
) -> Result<(StatusCode, HeaderMap, Vec<u8>)> {
    request(
        f,
        Method::POST,
        "/api/v1/apple/account-enrollment/finish",
        format!("csrf={csrf}").into_bytes(),
        &[
            ("content-type", "application/x-www-form-urlencoded".into()),
            ("origin", origin.into()),
            ("cookie", cookies(browser, Some(cookie))),
        ],
    )
    .await
}
fn flow_path(headers: &HeaderMap) -> Result<String> {
    let value = headers[header::WWW_AUTHENTICATE].to_str()?;
    ensure!(value.starts_with("Bearer method=\"apple-as-web\", url=\""));
    Ok(value
        .split("url=\"")
        .nth(1)
        .unwrap()
        .trim_end_matches('"')
        .strip_prefix("https://mdm.example.test")
        .unwrap()
        .to_owned())
}
fn token(headers: &HeaderMap) -> Result<String> {
    Ok(headers[header::LOCATION]
        .to_str()?
        .strip_prefix("apple-remotemanagement-user-login://authentication-results?access-token=")
        .unwrap()
        .to_owned())
}
fn plist_cms(bytes: &[u8]) -> Result<plist::Dictionary> {
    let cms = cms::content_info::ContentInfo::from_der(bytes)?
        .content
        .decode_as::<cms::signed_data::SignedData>()?;
    Ok(protocol::decode(
        cms.encap_content_info
            .econtent
            .unwrap()
            .decode_as::<OctetString>()?
            .as_bytes(),
    )?)
}
async fn configure(f: &mut Fixture, organization: Uuid, name: &str) -> Result<()> {
    let grants = serde_json::from_value(json!([
        {"operation":"authorization_read","scope":{"kind":"tenant"}},
        {"operation":"authorization_write","scope":{"kind":"tenant"}}
    ]))?;
    crate::test_support::identity::set_grants(
        case_tenant(),
        crate::test_support::case::admin(),
        grants,
    )
    .await?;
    f.browser.operation = Some(Uuid::new_v4());
    let path = format!("/api/v1/apple/account-enrollment/organizations/{organization}");
    let input = json!({"expectedRevision":0,"domain":"managed.example.test","serverUuid":organization,"signingKey":"organization","enabled":true});
    let saved = f
        .browser
        .call(&f.router, Method::PUT, &path, Some(input.clone()))
        .await?;
    ensure!(saved.0 == StatusCode::OK, "organization: {saved:?}");
    ensure!(
        f.browser
            .call(&f.router, Method::PUT, &path, Some(input))
            .await?
            == saved,
        "configuration replay changed"
    );
    f.browser.operation = Some(Uuid::new_v4());
    let bound=f.browser.call(&f.router,Method::PUT,&format!("{path}/accounts/{name}"),Some(json!({"expectedRevision":0,"principalId":crate::test_support::case::admin(),"instanceId":crate::test_support::INSTANCE,"enabled":true}))).await?;
    ensure!(bound.0 == StatusCode::OK, "account mapping: {bound:?}");
    f.browser.operation = None;
    Ok(())
}
fn signed(f: &Fixture, product: &str, build: &str) -> Result<Vec<u8>> {
    let signer = rss_mdm_certificate::apple::ProfileSigner::from_bytes(
        &std::fs::read(f.root.join("apple-profile.pem"))?,
        &std::fs::read(f.root.join("apple-profile.pk8"))?,
        f.app.clock.unix_seconds()?,
    )?;
    Ok(signer.sign(
        &protocol::xml(protocol::dictionary([
            ("LANGUAGE", "en".into()),
            ("PRODUCT", product.into()),
            ("VERSION", build.into()),
        ]))?,
        f.app.clock.unix_seconds()?,
    )?)
}
async fn user_token(
    peer: &lifecycle::Peer,
    bearer: Option<&str>,
) -> Result<(StatusCode, HeaderMap, Vec<u8>)> {
    let body = protocol::xml(protocol::dictionary([
        ("MessageType", "GetToken".into()),
        (
            "UDID",
            crate::test_support::case::name("rss-t2-apple").into(),
        ),
        ("UserID", Uuid::from_u128(27).to_string().into()),
        ("TokenServiceType", "com.apple.maid".into()),
    ]))?;
    let mut r = peer
        .client
        .put(format!("{}/checkin", peer.origin))
        .header("content-type", "application/xml")
        .body(body);
    if let Some(token) = bearer {
        r = r.bearer_auth(token)
    }
    let r = r.send().await?;
    let status = r.status();
    let headers = r.headers().clone();
    Ok((status, headers, r.bytes().await?.to_vec()))
}
fn verify_jwt(f: &Fixture, bytes: &[u8], organization: Uuid) -> Result<()> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let d = protocol::decode(bytes)?;
    let jwt = std::str::from_utf8(d["TokenData"].as_data().unwrap())?;
    let parts = jwt.split('.').collect::<Vec<_>>();
    ensure!(parts.len() == 3);
    let claims: serde_json::Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1])?)?;
    ensure!(
        claims["iss"] == organization.to_string()
            && claims["service_type"] == "com.apple.maid"
            && claims["iat"].as_i64().is_some()
    );
    ensure!(!Uuid::parse_str(claims["jti"].as_str().unwrap())?.is_nil());
    let work = tempfile::tempdir()?;
    let public = work.path().join("public.pem");
    let input = work.path().join("input");
    let signature = work.path().join("signature");
    let key = std::process::Command::new("openssl")
        .args(["x509", "-pubkey", "-noout", "-in"])
        .arg(f.root.join("apple-profile.pem"))
        .output()?;
    ensure!(key.status.success());
    std::fs::write(&public, key.stdout)?;
    std::fs::write(&input, format!("{}.{}", parts[0], parts[1]))?;
    std::fs::write(&signature, URL_SAFE_NO_PAD.decode(parts[2])?)?;
    ensure!(
        std::process::Command::new("openssl")
            .args(["dgst", "-sha256", "-verify"])
            .arg(public)
            .arg("-signature")
            .arg(signature)
            .arg(input)
            .output()?
            .status
            .success(),
        "independent JWT verification failed"
    );
    Ok(())
}
#[tokio::test]
#[ignore = "MODULE=apple.account_enrollment: complete account bootstrap, native binding and reauthentication"]
async fn account_enrollment_and_reauthentication_keep_one_registration() -> Result<()> {
    let mut f = Fixture::start().await?;
    let org = Uuid::new_v4();
    let name = "admin@managed.example.test";
    configure(&mut f, org, name).await?;
    let discovery = request(
        &f,
        Method::GET,
        &format!("/.well-known/com.apple.remotemanagement?user-identifier={name}&model-family=Mac"),
        vec![],
        &[],
    )
    .await?;
    ensure!(discovery.0 == StatusCode::OK);
    let discovery: serde_json::Value = serde_json::from_slice(&discovery.2)?;
    ensure!(discovery["Servers"][0]["Version"] == "mdm-adde");
    let path = format!("/api/v1/apple/account-enrollment/enroll/{org}");
    let payload = signed(&f, "Mac14,2", "23A344")?;
    for body in [
        signed(&f, "iPhone15,2", "23A344")?,
        signed(&f, "Mac14,2", "22A344")?,
        vec![0; 64],
    ] {
        ensure!(request(&f, Method::POST, &path, body, &[]).await?.0 == StatusCode::BAD_REQUEST);
    }
    let initial = request(&f, Method::POST, &path, payload.clone(), &[]).await?;
    ensure!(initial.0 == StatusCode::UNAUTHORIZED);
    ensure!(
        request(
            &f,
            Method::POST,
            &path,
            signed(&f, "iMac20,1", "23A344")?,
            &[]
        )
        .await?
        .0 == StatusCode::UNAUTHORIZED,
        "supported Intel iMac must enter account authentication"
    );
    let mut pg =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    let expired = request(&f, Method::POST, &path, payload.clone(), &[]).await?;
    let expired_id = Uuid::parse_str(flow_path(&expired.1)?.rsplit('/').next().unwrap())?;
    sqlx::query("UPDATE mdm_apple.account_flows SET expires_at=clock_timestamp()-interval '1 second' WHERE tenant_id=$1::uuid AND id=$2").bind(case_tenant()).bind(expired_id).execute(&mut pg).await?;
    ensure!(
        request(&f, Method::POST, &path, payload.clone(), &[])
            .await?
            .0
            == StatusCode::UNAUTHORIZED
    );
    let retained: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM mdm_apple.account_flows WHERE tenant_id=$1::uuid AND id=$2)",
    )
    .bind(case_tenant())
    .bind(expired_id)
    .fetch_one(&mut pg)
    .await?;
    ensure!(!retained, "expired unauthenticated flow was not reclaimed");
    let requests: i64 =
        sqlx::query_scalar("SELECT count(*) FROM mdm_access.requests WHERE tenant_id=$1::uuid")
            .bind(case_tenant())
            .fetch_one(&mut pg)
            .await?;
    ensure!(requests == 0, "discovery/bootstrap allocated enrollment");
    let cookie = start(&f, &flow_path(&initial.1)?, name).await?;
    let csrf = f.browser.csrf.clone().unwrap();
    ensure!(
        finish(&f, &f.browser, &cookie, "https://evil.example.test", &csrf)
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    ensure!(
        finish(&f, &f.browser, &cookie, "https://mdm.example.test", "wrong")
            .await?
            .0
            == StatusCode::UNAUTHORIZED
    );
    let authorized = finish(&f, &f.browser, &cookie, "https://mdm.example.test", &csrf).await?;
    ensure!(
        authorized.0 == StatusCode::PERMANENT_REDIRECT,
        "finish: {} {}",
        authorized.0,
        String::from_utf8_lossy(&authorized.2)
    );
    let bearer = token(&authorized.1)?;
    let replay = finish(&f, &f.browser, &cookie, "https://mdm.example.test", &csrf).await?;
    ensure!(
        replay.0 == authorized.0 && replay.1[header::LOCATION] == authorized.1[header::LOCATION]
    );
    let profile = request(
        &f,
        Method::POST,
        &path,
        payload.clone(),
        &[("authorization", format!("Bearer {bearer}"))],
    )
    .await?;
    ensure!(
        profile.0 == StatusCode::OK,
        "profile: {} {}",
        profile.0,
        String::from_utf8_lossy(&profile.2)
    );
    let repeat = request(
        &f,
        Method::POST,
        &path,
        payload.clone(),
        &[("authorization", format!("Bearer {bearer}"))],
    )
    .await?;
    ensure!(repeat.2 == profile.2, "profile replay changed bytes");
    let d = plist_cms(&profile.2)?;
    let enrollment = Uuid::parse_str(d["PayloadUUID"].as_string().unwrap())?;
    let contents = d["PayloadContent"].as_array().unwrap();
    let mdm = contents[1].as_dictionary().unwrap();
    ensure!(
        mdm["EnrollmentMode"].as_string() == Some("ADDE")
            && mdm["AssignedManagedAppleID"].as_string() == Some(name)
    );
    let scep = contents[0].as_dictionary().unwrap();
    let attempt = Uuid::parse_str(scep["PayloadUUID"].as_string().unwrap())?;
    let challenge = scep["PayloadContent"].as_dictionary().unwrap()["Challenge"]
        .as_string()
        .unwrap();
    let old_profile = request(
        &f,
        Method::POST,
        &format!("/api/v1/enrollments/{enrollment}/profile"),
        json!({"password":challenge}).to_string().into_bytes(),
        &[("content-type", "application/json".into())],
    )
    .await?;
    ensure!(old_profile.0 == StatusCode::UNAUTHORIZED);
    let sessions = rss_mdm_authorization_service::session::SessionAuthority::new(
        f.app.identity.authority.clone(),
        f.app.identity.tenant,
    );
    let admission = rss_mdm_registration_service::enrollment::native::account(
        &f.app.access.registration(),
        &sessions,
        enrollment,
        rss_mdm_apple_channel::account_enrollment::authority(),
        None,
    )
    .await?;
    let mut command = pg.begin().await?;
    sqlx::raw_sql("SET LOCAL ROLE mdm_command_runtime")
        .execute(&mut *command)
        .await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(case_tenant())
        .execute(&mut *command)
        .await?;
    let direct_access: bool = sqlx::query_scalar(
        "SELECT has_table_privilege(current_user,'mdm_apple.account_flows','SELECT,UPDATE')",
    )
    .fetch_one(&mut *command)
    .await?;
    ensure!(
        !direct_access,
        "command role gained account material access"
    );
    let cross_tenant: bool =
        sqlx::query_scalar("SELECT mdm_apple.account_current($1,$2,$3,NULL,NULL)")
            .bind(Uuid::new_v4())
            .bind(enrollment)
            .bind(admission.coordinates().version)
            .fetch_one(&mut *command)
            .await?;
    ensure!(!cross_tenant, "owner gate crossed the transaction tenant");
    let wrong_token: bool =
        sqlx::query_scalar("SELECT mdm_apple.account_current($1::uuid,$2,$3,NULL,$4)")
            .bind(case_tenant())
            .bind(enrollment)
            .bind(admission.coordinates().version)
            .bind("wrong-token-hash")
            .fetch_one(&mut *command)
            .await?;
    ensure!(!wrong_token, "owner gate accepted a changed token hash");
    command.rollback().await?;
    sqlx::query(
        "UPDATE mdm_access.requests SET expected_generation=1 WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(case_tenant())
    .bind(enrollment)
    .execute(&mut pg)
    .await?;
    let mut tx = f.app.access.begin(case_tenant()).await?;
    ensure!(
        matches!(
            admission.current(&mut tx).await,
            Err(rss_mdm_registration_service::Error::Unauthorized)
        ),
        "admission accepted changed persisted generation"
    );
    tx.rollback().await?;
    sqlx::query(
        "UPDATE mdm_access.requests SET expected_generation=0 WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(case_tenant())
    .bind(enrollment)
    .execute(&mut pg)
    .await?;
    let mut device = scep_client::Device::new(enrollment, attempt, challenge)?;
    let csr = device.request(
        &f.root.join("apple-issuer.pem"),
        &Uuid::new_v4().to_string(),
        f.app.clock.unix_seconds()?,
    )?;
    let der = device
        .enroll(
            &f.client()?,
            &f.app.apple()?.channel.scep_fixture()?.0,
            &csr,
        )
        .await?;
    let mut peer = f.authenticate_peer(&device, &der).await?;
    peer.token().await?;
    ensure!(
        native_user(
            &peer,
            "/checkin",
            protocol::dictionary([("MessageType", "UserAuthenticate".into())]),
            Some(&bearer)
        )
        .await?
        .0 == StatusCode::OK
    );
    ensure!(
        native_user(&peer, "/checkin", user_update(&peer), Some(&bearer))
            .await?
            .0
            == StatusCode::OK
    );
    let revision:i64=sqlx::query_scalar("SELECT token_revision FROM mdm_apple.channels WHERE tenant_id=$1::uuid AND user_key=$2 AND state='active'").bind(case_tenant()).bind(Uuid::from_u128(27).to_string()).fetch_one(&mut pg).await?;
    ensure!(
        native_user(&peer, "/checkin", user_update(&peer), None)
            .await?
            .0
            == StatusCode::UNAUTHORIZED
    );
    let unchanged:i64=sqlx::query_scalar("SELECT token_revision FROM mdm_apple.channels WHERE tenant_id=$1::uuid AND user_key=$2 AND state='active'").bind(case_tenant()).bind(Uuid::from_u128(27).to_string()).fetch_one(&mut pg).await?;
    ensure!(
        revision == unchanged,
        "rejected user request changed token state"
    );
    let asset_url = user_asset(&mut f, &peer, &bearer, enrollment).await?;
    ensure!(
        native_user(&peer, "/checkin", user_ddm(), Some(&bearer))
            .await?
            .0
            == StatusCode::OK
    );
    let before:Uuid=sqlx::query_scalar("SELECT id FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND request_id=$2 AND state='active'").bind(case_tenant()).bind(enrollment).fetch_one(&mut pg).await?;
    let accepted = user_token(&peer, Some(&bearer)).await?;
    ensure!(accepted.0 == StatusCode::OK);
    verify_jwt(&f, &accepted.2, org)?;
    let logout = f
        .browser
        .call(
            &f.router,
            Method::POST,
            &format!("/api/v1/identity/tenants/{}/session/logout", case_tenant()),
            None,
        )
        .await?;
    ensure!(logout.0 == StatusCode::NO_CONTENT, "logout: {logout:?}");
    ensure!(
        native_user(&peer, "/checkin", user_update(&peer), Some(&bearer))
            .await?
            .0
            == StatusCode::UNAUTHORIZED
    );
    ensure!(
        native_user(
            &peer,
            "/mdm",
            protocol::dictionary([("Status", "Idle".into())]),
            Some(&bearer)
        )
        .await?
        .0 == StatusCode::UNAUTHORIZED
    );
    ensure!(
        native_user(&peer, "/checkin", user_ddm(), Some(&bearer))
            .await?
            .0
            == StatusCode::UNAUTHORIZED
    );
    ensure!(
        peer.client
            .get(&asset_url)
            .bearer_auth(&bearer)
            .send()
            .await?
            .status()
            == StatusCode::UNAUTHORIZED
    );
    // Certificate renewal retains the original account profile after browser logout;
    // it does not revive the invalid user-channel bearer.
    (peer, device) = f
        .renewal_cycle(&peer, &device, enrollment, Some(name))
        .await?;
    let rejected = user_token(&peer, Some(&bearer)).await?;
    ensure!(rejected.0 == StatusCode::UNAUTHORIZED);
    let renewal_cookie = start(&f, &flow_path(&rejected.1)?, name).await?;
    peer.token().await?; // The device channel retains its independent certificate authority.
    let mut browser = Browser::default();
    ensure!(
        browser
            .login_password(&f.router, "admin", crate::test_support::PASSWORD)
            .await?
            == StatusCode::OK
    );
    let renewed = finish(
        &f,
        &browser,
        &renewal_cookie,
        "https://mdm.example.test",
        browser.csrf.as_ref().unwrap(),
    )
    .await?;
    ensure!(
        renewed.0 == StatusCode::PERMANENT_REDIRECT,
        "reauth: {} {}",
        renewed.0,
        String::from_utf8_lossy(&renewed.2)
    );
    let mut new_token = token(&renewed.1)?;
    ensure!(new_token != bearer);
    let after:Uuid=sqlx::query_scalar("SELECT id FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND request_id=$2 AND state='active'").bind(case_tenant()).bind(enrollment).fetch_one(&mut pg).await?;
    ensure!(after == before);
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM mdm_access.requests WHERE tenant_id=$1::uuid")
            .bind(case_tenant())
            .fetch_one(&mut pg)
            .await?;
    ensure!(count == 1, "reauth created second quota allocation");
    let accepted = user_token(&peer, Some(&new_token)).await?;
    ensure!(accepted.0 == StatusCode::OK);
    verify_jwt(&f, &accepted.2, org)?;
    ensure!(user_token(&peer, Some(&bearer)).await?.0 == StatusCode::UNAUTHORIZED);
    ensure!(
        native_user(&peer, "/checkin", user_ddm(), Some(&new_token))
            .await?
            .0
            == StatusCode::OK
    );
    ensure!(
        peer.client
            .get(&asset_url)
            .bearer_auth(&new_token)
            .send()
            .await?
            .status()
            == StatusCode::OK
    );
    browser.operation = Some(Uuid::new_v4());
    let revised=browser.call(&f.router,Method::PUT,&format!("/api/v1/apple/account-enrollment/organizations/{org}/accounts/{name}"),Some(json!({"expectedRevision":1,"principalId":crate::test_support::case::admin(),"instanceId":crate::test_support::INSTANCE,"enabled":true}))).await?;
    ensure!(revised.0 == StatusCode::OK);
    new_token = recover(&f, &peer, &browser, &new_token, name).await?;
    browser.operation = Some(Uuid::new_v4());
    let rotated=browser.call(&f.router,Method::PUT,&format!("/api/v1/apple/account-enrollment/organizations/{org}"),Some(json!({"expectedRevision":1,"domain":"managed.example.test","serverUuid":org,"signingKey":"organization","enabled":true}))).await?;
    ensure!(rotated.0 == StatusCode::OK);
    new_token = recover(&f, &peer, &browser, &new_token, name).await?;
    let same:Uuid=sqlx::query_scalar("SELECT id FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND request_id=$2 AND state='active'").bind(case_tenant()).bind(enrollment).fetch_one(&mut pg).await?;
    ensure!(same == before);
    let stored:Vec<u8>=sqlx::query_scalar("SELECT material FROM mdm_apple.account_flows WHERE tenant_id=$1::uuid AND enrollment=$2 AND NOT revoked").bind(case_tenant()).bind(enrollment).fetch_one(&mut pg).await?;
    ensure!(
        !stored
            .windows(new_token.len())
            .any(|s| s == new_token.as_bytes()),
        "bearer stored plaintext"
    );
    browser.operation = Some(Uuid::new_v4());
    let disabled=browser.call(&f.router,Method::PUT,&format!("/api/v1/apple/account-enrollment/organizations/{org}/accounts/{name}"),Some(json!({"expectedRevision":2,"principalId":crate::test_support::case::admin(),"instanceId":crate::test_support::INSTANCE,"enabled":false}))).await?;
    ensure!(disabled.0 == StatusCode::OK);
    ensure!(user_token(&peer, Some(&new_token)).await?.0 == StatusCode::UNAUTHORIZED);
    browser.operation = Some(Uuid::new_v4());
    let disabled_organization=browser.call(&f.router,Method::PUT,&format!("/api/v1/apple/account-enrollment/organizations/{org}"),Some(json!({"expectedRevision":2,"domain":"managed.example.test","serverUuid":org,"signingKey":"unavailable-key","enabled":false}))).await?;
    ensure!(
        disabled_organization.0 == StatusCode::OK,
        "missing signing key prevented disable: {disabled_organization:?}"
    );
    pg.close().await?;
    drop(device);
    f.close().await
}

async fn native_user(
    peer: &lifecycle::Peer,
    path: &str,
    mut fields: plist::Dictionary,
    bearer: Option<&str>,
) -> Result<(StatusCode, HeaderMap, Vec<u8>)> {
    fields.insert(
        "UDID".into(),
        crate::test_support::case::name("rss-t2-apple").into(),
    );
    fields.insert("UserID".into(), Uuid::from_u128(27).to_string().into());
    let mut r = peer
        .client
        .put(format!("{}{path}", peer.origin))
        .header("content-type", "application/xml")
        .body(protocol::xml(fields)?);
    if let Some(token) = bearer {
        r = r.bearer_auth(token)
    }
    let r = r.send().await?;
    let status = r.status();
    let headers = r.headers().clone();
    Ok((status, headers, r.bytes().await?.to_vec()))
}
fn user_update(peer: &lifecycle::Peer) -> plist::Dictionary {
    protocol::dictionary([
        ("MessageType", "TokenUpdate".into()),
        ("Topic", peer.topic.clone().into()),
        ("Token", plist::Value::Data(vec![43; 32])),
        ("PushMagic", "account-user-push".into()),
    ])
}
fn user_ddm() -> plist::Dictionary {
    protocol::dictionary([
        ("MessageType", "DeclarativeManagement".into()),
        ("Endpoint", "tokens".into()),
    ])
}
async fn user_asset(
    f: &mut Fixture,
    peer: &lifecycle::Peer,
    bearer: &str,
    enrollment: Uuid,
) -> Result<String> {
    let mut grants = crate::test_support::identity::device_grants(
        None,
        &[
            "configuration_write",
            "operation_read",
            "inventory_collect",
            "inventory_read",
        ],
    )?;
    for operation in [
        crate::authorization::Permission::ResourceRead,
        crate::authorization::Permission::ResourceWrite,
        crate::authorization::Permission::AuthorizationRead,
        crate::authorization::Permission::AuthorizationWrite,
    ] {
        grants.push(crate::authorization::Grant {
            operation,
            scope: crate::authorization::Scope::Tenant,
        });
    }
    crate::test_support::identity::set_grants(
        case_tenant(),
        crate::test_support::case::admin(),
        grants,
    )
    .await?;
    let resource = Uuid::new_v4();
    let content = json!({"fixture":"account-user-asset"});
    crate::test_support::planning_http::native_configuration_resource(
        &mut f.browser,
        &f.router,
        resource,
        "macos",
        "aarch64",
        content.clone(),
    )
    .await?;
    let resource_view = f
        .browser
        .call(
            &f.router,
            Method::GET,
            &format!("/api/v1/resources/{resource}"),
            None,
        )
        .await?;
    ensure!(resource_view.0 == StatusCode::OK);
    let mut pg =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    let device:String=sqlx::query_scalar("SELECT device FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND request_id=$2 AND state='active'").bind(case_tenant()).bind(enrollment).fetch_one(&mut pg).await?;
    pg.close().await?;
    let asset = json!({"identifier":"account-asset","resource":resource,"version":"v1","variant":"default","versionDigest":resource_view.1["versions"][0]["digest"],"contentType":"application/json","profileSchemas":[]});
    let task = ddm::task(
        vec![ddm::declaration(
            "account-asset",
            "com.apple.asset.data",
            json!({}),
        )],
        vec![asset],
    );
    let operation = Uuid::new_v4();
    let created=f.browser.call(&f.router,Method::POST,&format!("/api/v1/devices/{device}/operations"),Some(json!({"operationId":operation,"inputVersion":"1","target":{"kind":"user","userId":Uuid::from_u128(27)},"task":task,"deadline":f.app.clock.unix_seconds()?+300}))).await?;
    ensure!(
        created.0 == StatusCode::ACCEPTED,
        "user asset operation: {created:?}"
    );
    let (id, _) = peer.next("DeviceInformation").await?;
    let next = peer
        .manage(
            "Acknowledged",
            Some(id),
            Some((
                "QueryResponses",
                plist::Value::Dictionary(protocol::dictionary([
                    ("OSVersion", "15.0".into()),
                    ("IsSupervised", true.into()),
                    ("IsAppleSilicon", true.into()),
                ])),
            )),
        )
        .await?;
    let (id, _) = lifecycle::command(&next, "SecurityInfo")?;
    let next = peer
        .manage(
            "Acknowledged",
            Some(id),
            Some((
                "SecurityInfo",
                plist::Value::Dictionary(protocol::dictionary([(
                    "ManagementStatus",
                    plist::Value::Dictionary(protocol::dictionary([
                        ("EnrolledViaDEP", false.into()),
                        ("IsUserEnrollment", false.into()),
                        ("UserApprovedEnrollment", true.into()),
                    ])),
                )])),
            )),
        )
        .await?;
    ensure!(next.is_empty(), "user operation escaped device scope");
    let mut command = None;
    for _ in 0..100 {
        let reply = native_user(
            peer,
            "/mdm",
            protocol::dictionary([("Status", "Idle".into())]),
            Some(bearer),
        )
        .await?;
        ensure!(reply.0 == StatusCode::OK, "user Idle: {}", reply.0);
        if !reply.2.is_empty() {
            command = Some(lifecycle::command(&reply.2, "DeclarativeManagement")?.0);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let command =
        command.ok_or_else(|| anyhow::anyhow!("user declaration publication deadline"))?;
    ensure!(
        native_user(
            peer,
            "/mdm",
            protocol::dictionary([
                ("Status", "Acknowledged".into()),
                ("CommandUUID", command.to_string().into())
            ]),
            Some(bearer)
        )
        .await?
        .0 == StatusCode::OK
    );
    let d = protocol::dictionary([
        ("MessageType", "DeclarativeManagement".into()),
        ("Endpoint", "declaration/asset/account-asset".into()),
    ]);
    let reply = native_user(peer, "/checkin", d, Some(bearer)).await?;
    ensure!(
        reply.0 == StatusCode::OK,
        "user asset declaration: {}",
        reply.0
    );
    let asset: serde_json::Value = serde_json::from_slice(&reply.2)?;
    let url = asset["Payload"]["Reference"]["DataURL"]
        .as_str()
        .unwrap()
        .to_owned();
    let accepted = peer.client.get(&url).bearer_auth(bearer).send().await?;
    ensure!(
        accepted.status() == StatusCode::OK
            && accepted.bytes().await?.as_ref() == serde_json::to_vec(&content)?
    );
    ensure!(
        peer.client.get(&url).send().await?.status() == StatusCode::UNAUTHORIZED,
        "asset accepted missing account bearer"
    );
    Ok(url)
}

async fn recover(
    f: &Fixture,
    peer: &lifecycle::Peer,
    browser: &Browser,
    old: &str,
    name: &str,
) -> Result<String> {
    let challenged = user_token(peer, Some(old)).await?;
    ensure!(challenged.0 == StatusCode::UNAUTHORIZED);
    let cookie = start(f, &flow_path(&challenged.1)?, name).await?;
    let renewed = finish(
        f,
        browser,
        &cookie,
        "https://mdm.example.test",
        browser.csrf.as_ref().unwrap(),
    )
    .await?;
    ensure!(renewed.0 == StatusCode::PERMANENT_REDIRECT);
    let token = token(&renewed.1)?;
    ensure!(token != old && user_token(peer, Some(&token)).await?.0 == StatusCode::OK);
    Ok(token)
}
