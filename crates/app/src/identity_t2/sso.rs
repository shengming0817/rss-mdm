//! Product callback, explicit linking and provider isolation with real HTTPS Keycloak.
use super::*;
use crate::clock::Clock;
const CALLBACK: &str = "https://mdm.example.test/api/v2/oidc/callback";

fn form(html: &str) -> Result<String> {
    let form = html
        .split("<form")
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("provider form missing"))?;
    Ok(form
        .split("action=\"")
        .nth(1)
        .and_then(|v| v.split('"').next())
        .ok_or_else(|| anyhow::anyhow!("provider form action missing"))?
        .replace("&amp;", "&"))
}
fn otp() -> Result<String> {
    let count = crate::clock::SystemClock.unix_seconds()? as u64 / 30;
    let key = ring::hmac::Key::new(
        ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        b"fixture-totp-secret-2339",
    );
    let tag = ring::hmac::sign(&key, &count.to_be_bytes());
    let bytes = tag.as_ref();
    let offset = usize::from(bytes[19] & 15);
    let value = u32::from_be_bytes(bytes[offset..offset + 4].try_into()?) & 0x7fffffff;
    Ok(format!("{:06}", value % 1_000_000))
}
async fn provider_login(url: &str, user: &str) -> Result<reqwest::Url> {
    let client = Client::builder()
        .cookie_store(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(
            std::env::var("MDM_TEST_SSO_CA")?,
        )?)?)
        .build()?;
    let page = client
        .get(url)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;
    let response = client
        .post(form(&page)?)
        .form(&[
            ("username", user),
            ("password", "Fixture-provider-password-2026!"),
            ("credentialId", ""),
        ])
        .send()
        .await?;
    let response = if response.status() == StatusCode::OK {
        let page = response.text().await?;
        client
            .post(form(&page)?)
            .form(&[("otp", otp()?)])
            .send()
            .await?
    } else {
        response
    };
    ensure!(
        response.status().is_redirection(),
        "provider authentication rejected: {}",
        response.status()
    );
    let callback = reqwest::Url::parse(
        response
            .headers()
            .get("location")
            .ok_or_else(|| anyhow::anyhow!("callback absent"))?
            .to_str()?,
    )?;
    ensure!(
        callback.as_str().starts_with(CALLBACK),
        "provider redirected outside product callback"
    );
    Ok(callback)
}
async fn roundtrip(
    router: &Router,
    browser: &mut Browser,
    provider: &str,
    kind: &str,
    user: &str,
) -> Result<()> {
    let mut input = json!({"returnTarget":"home"});
    if kind == "link" {
        input["password"] = PASSWORD.into();
    }
    let (status, begin) = browser
        .call(
            router,
            Method::POST,
            &format!("/api/v2/tenants/{TENANT}/oidc/{provider}/{kind}"),
            Some(input),
        )
        .await?;
    ensure!(
        status == StatusCode::OK,
        "SSO begin {kind}: {status} {begin}"
    );
    let url = begin["authorizationUrl"].as_str().unwrap();
    ensure!(
        reqwest::Url::parse(url)?
            .query_pairs()
            .any(|(k, v)| k == "redirect_uri" && v == CALLBACK)
    );
    if kind == "step-up" {
        ensure!(
            reqwest::Url::parse(url)?
                .query_pairs()
                .any(|(k, v)| k == "acr_values" && v == "2")
        );
    }
    let callback = provider_login(url, user).await?;
    let (status, value) = browser
        .call(
            router,
            Method::GET,
            &format!("{}?{}", callback.path(), callback.query().unwrap()),
            None,
        )
        .await?;
    ensure!(
        status == StatusCode::SEE_OTHER,
        "SSO callback: {status} {value}"
    );
    let returned = reqwest::Url::parse(value["location"].as_str().unwrap())?;
    ensure!(
        returned.origin().ascii_serialization() == "https://mdm.example.test"
            && returned.path() == "/done"
    );
    if kind == "link" {
        ensure!(
            returned
                .query_pairs()
                .any(|(k, v)| k == "identity_result" && v == "linked")
        );
    }
    // Callback sends only the credential cookie; the component session endpoint supplies CSRF.
    let session = browser
        .call(
            router,
            Method::GET,
            &format!("/api/v2/tenants/{TENANT}/session"),
            None,
        )
        .await?;
    ensure!(session.0 == StatusCode::OK);
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "make t2-identity: optional enterprise Keycloak, real MDM Router and PG"]
async fn product_callback_link_step_up_and_provider_isolation() -> Result<()> {
    let mut base: Value =
        serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
    let issuer = std::env::var("MDM_TEST_SSO_ISSUER")?;
    let directory = tempfile::tempdir()?;
    use std::os::unix::fs::PermissionsExt;
    for name in ["state", "credential"] {
        let file = directory.path().join(name);
        std::fs::write(&file, "ab".repeat(32))?;
        std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o600))?;
    }
    base["identity"]["oidc"] = json!({"group_facts_max_age_seconds":300,"state_key_file":directory.path().join("state"),
        "active_credential_key":"current","credential_keys":{"current":directory.path().join("credential")},
        "return_targets":{"home":"https://mdm.example.test/done"},
        "assurance_profiles":[{"tenant_id":TENANT,"issuer":issuer,"client_id":"mdm","keycloak_totp":true}]});
    let config: Config = serde_json::from_value(base.clone())?;
    let policy = Arc::new(crate::access::Policy::new(
        TENANT,
        INSTANCE,
        config.bindings.clone(),
    )?);
    let identity = crate::identity::Identity::for_oidc_fixture(&config, policy).await?;
    let reader = Arc::new(InventoryReader::connect(config.database.options()?).await?);
    let router = crate::api::application(
        config,
        Arc::new(crate::clock::SystemClock),
        monotonic(),
        reader.clone(),
        access_store(&base).await?,
        Some(identity),
    )
    .await?
    .layer(axum::Extension(rss_identity_http_axum::ClientAddress(
        "127.0.0.1".parse()?,
    )));
    let mut admin = Browser::default();
    ensure!(admin.login(&router, "admin").await? == StatusCode::OK);
    let tenant = format!("/api/v2/tenants/{TENANT}");
    let settings = json!({"issuer":issuer,"clientId":"mdm","redirectUri":CALLBACK,"scopes":["openid","profile","email"],"claims":{"email":"email","groups":null},"jit":true});
    let (status,created)=admin.call(&router,Method::POST,&format!("{tenant}/providers"),Some(json!({"settings":settings,"clientSecret":"fixture-secret","caPem":std::fs::read_to_string(std::env::var("MDM_TEST_SSO_CA")?)?}))).await?;
    ensure!(
        status == StatusCode::CREATED,
        "provider create: {status} {created}"
    );
    let provider = created["id"].as_str().unwrap();
    let path = format!("{tenant}/providers/{provider}");
    let (status, enabled) = admin
        .call(
            &router,
            Method::POST,
            &format!("{path}/enabled"),
            Some(json!({"expectedVersion":created["version"],"enabled":true})),
        )
        .await?;
    ensure!(
        status == StatusCode::OK,
        "provider enable: {status} {enabled}"
    );
    let created_local = admin
        .call(
            &router,
            Method::POST,
            &format!("{tenant}/accounts"),
            Some(json!({"login":"sso-local","password":PASSWORD})),
        )
        .await?;
    ensure!(created_local.0 == StatusCode::CREATED);
    let mut linked = Browser::default();
    ensure!(linked.login(&router, "sso-local").await? == StatusCode::OK);
    let original = linked
        .call(&router, Method::GET, "/api/v1/authorization", None)
        .await?
        .1["principal_id"]
        .clone();
    roundtrip(&router, &mut linked, provider, "link", "alice").await?;
    // Explicit linking preserves the local account, including an opaque upstream subject.
    ensure!(
        linked
            .call(&router, Method::GET, "/api/v1/authorization", None)
            .await?
            .1["principal_id"]
            == original
    );
    let mut alice = Browser::default();
    roundtrip(&router, &mut alice, provider, "login", "alice").await?;
    ensure!(
        alice
            .call(&router, Method::GET, "/api/v1/authorization", None)
            .await?
            .1["principal_id"]
            == original
    );
    let mut bob = Browser::default();
    roundtrip(&router, &mut bob, provider, "login", "bob").await?;
    ensure!(
        bob.call(&router, Method::GET, "/api/v1/authorization", None)
            .await?
            .1["principal_id"]
            != original,
        "same email linked two external subjects"
    );
    let mut old = alice.clone();
    roundtrip(&router, &mut alice, provider, "step-up", "alice").await?;
    ensure!(
        old.call(&router, Method::GET, "/api/v1/authorization", None)
            .await?
            .0
            == StatusCode::UNAUTHORIZED
    );
    let security = alice
        .call(
            &router,
            Method::GET,
            &format!("{tenant}/session/security"),
            None,
        )
        .await?;
    ensure!(
        security.0 == StatusCode::OK && security.1["authentication"]["acr"] == "mfa",
        "step-up facts: {}",
        security.1
    );
    let disabled = admin
        .call(
            &router,
            Method::POST,
            &format!("{path}/enabled"),
            Some(json!({"expectedVersion":enabled["version"],"enabled":false})),
        )
        .await?;
    ensure!(disabled.0 == StatusCode::OK);
    ensure!(
        alice
            .call(&router, Method::GET, "/api/v1/authorization", None)
            .await?
            .0
            == StatusCode::UNAUTHORIZED
    );
    ensure!(
        admin
            .call(&router, Method::GET, "/api/v1/authorization", None)
            .await?
            .0
            == StatusCode::OK
    );
    command(
        &["stop", "-t", "1", &std::env::var("MDM_TEST_SSO_CONTAINER")?],
        None,
    )?;
    let mut local = Browser::default();
    ensure!(local.login(&router, "admin").await? == StatusCode::OK);
    ensure!(
        local
            .call(
                &router,
                Method::POST,
                &format!("{tenant}/session/refresh"),
                None
            )
            .await?
            .0
            == StatusCode::OK
    );
    ensure!(
        local
            .call(
                &router,
                Method::POST,
                &format!("{tenant}/session/logout"),
                None
            )
            .await?
            .0
            == StatusCode::NO_CONTENT
    );
    reader.close().await;
    println!("MDM_ENTERPRISE_SSO_MATRIX_PASSED");
    Ok(())
}
