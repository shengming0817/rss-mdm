//! Product callback facts and provider isolation with real HTTPS Keycloak.
use crate::test_support::{http::*, runtime::*, *};
#[path = "sso/authorization.rs"]
mod authorization;
const CALLBACK: &str = "https://mdm.example.test/api/v1/identity/oidc/callback";

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
    user: &str,
) -> Result<()> {
    let input = json!({"returnTarget":"home"});
    let (status, begin) = browser
        .call(
            router,
            Method::POST,
            &format!(
                "/api/v1/identity/tenants/{TENANT}/oidc/{provider}/login",
                TENANT = case_tenant()
            ),
            Some(input),
        )
        .await?;
    ensure!(status == StatusCode::OK, "SSO login: {status} {begin}");
    let url = begin["authorizationUrl"].as_str().unwrap();
    ensure!(
        reqwest::Url::parse(url)?
            .query_pairs()
            .any(|(k, v)| k == "redirect_uri" && v == CALLBACK)
    );
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
    // Callback sends only the credential cookie; the component session endpoint supplies CSRF.
    let session = browser
        .call(
            router,
            Method::GET,
            &format!(
                "/api/v1/identity/tenants/{TENANT}/session",
                TENANT = case_tenant()
            ),
            None,
        )
        .await?;
    ensure!(session.0 == StatusCode::OK);
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "make t2 MODULE=identity.sso: enterprise Keycloak, real MDM Router and PG"]
async fn product_callback_facts_and_provider_isolation() -> Result<()> {
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
    base["identity"]["oidc"] = json!({"group_facts_max_age_seconds":60,"state_key_file":directory.path().join("state"),
        "active_credential_key":"current","credential_keys":{"current":directory.path().join("credential")},
        "return_targets":{"home":"https://mdm.example.test/done"},
        "private_providers":[], "assurance_profiles":[{"tenant_id":case_tenant(),"issuer":issuer,"client_id":"mdm","keycloak_totp":true}]});
    let config: Config = serde_json::from_value(base.clone())?;
    let policy = Arc::new(
        crate::authorization::identity_management::IdentityManagementPolicy::new(INSTANCE)?,
    );
    let mut identity_resources = crate::test_support::runtime::Resources::default();
    let fact_time = rss_identity_postgres::ControlledFactTime::default();
    let identity = crate::identity::Identity::for_oidc_fixture(
        &config,
        policy,
        fact_time.clone(),
        |resource| identity_resources.acquire(resource),
    )
    .await?;
    identity_resources.finish(async {
    let access = database(&base).await?;
    let audit_store = access.audit_store(&config.audit).await?;
    let (router, _, _, _, resources) = crate::api::application_fixture(
        config,
        Arc::new(crate::clock::SystemClock),
        monotonic(),
        access,
        Some(identity),
        audit_store,
    )
    .await?;
    resources.finish(async {
    let router = router.layer(axum::Extension(rss_identity_http_axum::ClientAddress(
        "127.0.0.1".parse()?,
    )));
    let mut admin = Browser::default();
    identity::age_prepared_admin_session()?;
    ensure!(admin.login_password(&router, "admin", PASSWORD).await? == StatusCode::OK);
    let tenant = format!("/api/v1/identity/tenants/{TENANT}", TENANT = case_tenant());
    let settings = json!({"issuer":issuer,"clientId":"mdm","redirectUri":CALLBACK,"scopes":["openid","profile","email"],"claims":{"subject":{"kind":"oidc"},"profile":{"extensionsClaim":null,"maxAgeSeconds":14400},"groups":"groups","departmentSnapshot":{"claim":"organization_snapshot","maxAgeSeconds":120}},"jit":true});
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
    let mut alice = Browser::default();
    roundtrip(&router, &mut alice, provider, "alice").await?;
    let alice_principal=browser_subject(&alice,&router).await?;
    let without_mapping=admin.call(&router,Method::GET,&format!("/api/v1/user-profiles/{alice_principal}?view=latest"),None).await?;
    ensure!(without_mapping.0==StatusCode::OK);
    ensure!(without_mapping.1["fields"].as_array().unwrap().is_empty());
    ensure!(without_mapping.1["profiles"].as_array().unwrap().iter().any(|v|v["source"]["provider"]==provider && v["fixed"]["email"]["status"]=="available"));
    let field=uuid::Uuid::new_v4();
    let definition=serde_json::json!({"key":"federatedEmail","displayName":"Federated email","source":{"kind":"idp","provider":provider},"pointer":"/email","valueType":"string","maxLength":320,"maxItems":null,"minimum":null,"maximum":null,"enabled":true,"sensitive":false,"visibility":"both","displayUse":"profile","required":false,"useExistingObservation":false});
    ensure!(admin.call(&router,Method::PUT,&format!("/api/v1/user-attribute-definitions/{field}"),Some(serde_json::json!({"operationId":uuid::Uuid::new_v4(),"expectedRevision":0,"value":definition}))).await?.0==StatusCode::OK);
    let pending=alice.call(&router,Method::GET,"/api/v1/user-profiles/me",None).await?;
    ensure!(pending.0==StatusCode::OK && pending.1["fields"][0]["status"]=="pending_login");
    let mut previous=alice.clone();
    alice=Browser::default();
    roundtrip(&router,&mut alice,provider,"alice").await?;
    let profile=alice.call(&router,Method::GET,"/api/v1/user-profiles/me",None).await?;
    ensure!(profile.0==StatusCode::OK && profile.1["fields"][0]["status"]=="available" && profile.1["fields"][0]["value"].is_string());
    ensure!(previous.call(&router,Method::GET,"/api/v1/user-profiles/me",None).await?.1["fields"][0]["status"]=="unavailable");
    let profile_principal=profile.1["principalId"].as_str().unwrap().to_owned();
    let mut bob = Browser::default();
    roundtrip(&router, &mut bob, provider, "bob").await?;
    authorization::trusted_facts_and_independent_expiry(
        &router,
        &mut admin,
        &mut alice,
        &bob,
        provider,
        enabled["version"].as_i64().unwrap(),
        &fact_time,
    )
    .await?;
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
    let withdrawn=admin.call(&router,Method::GET,&format!("/api/v1/user-profiles/{profile_principal}?view=latest"),None).await?;
    ensure!(withdrawn.0==StatusCode::OK && withdrawn.1["fields"][0]["status"]=="unavailable");
    println!("MDM_ENTERPRISE_SSO_MATRIX_PASSED");
    Ok(())
    }).await
    }).await
}
