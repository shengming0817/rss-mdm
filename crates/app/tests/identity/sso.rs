//! Product callback facts and provider isolation with real HTTPS Keycloak.
use crate::test_support::{http::*, runtime::*, *};
use anyhow::Context;
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
    let (pool, source, audit) = crate::audit_test_support::request_store().await?;
    let mut resources = Resources::default();
    resources.resource(PoolResource(pool.clone()));
    resources.resource(SourceResource(source));
    let registration = Arc::new(rss_mdm_registration_service::Store::from_pool(pool.clone(), Arc::new(crate::registration_lifecycle::Bridge)));
    let fixture = authority::Authority {
        resources: Default::default(), base: base.clone(), pool: pool.clone(),
        authorization: Arc::new(rss_mdm_authorization_service::Store::from_pool(pool, Arc::new(crate::lifecycle::RuntimeTimer))),
        registration, identity: Arc::new(identity), audit: audit.clone(),
        credentials: Arc::new(crate::enrollment::credentials::Credentials::new(monotonic(), 16)),
    };
    resources.finish(async {
    let sessions = Arc::new(rss_mdm_authorization_service::session::SessionAuthority::new(fixture.identity.authority.clone(), fixture.identity.tenant));
    let profiles = Arc::new(crate::user_profiles::Backend {
        cursor: rss_mdm_query::cursor::CursorCodec::new(&[29;32])?,
        identity: fixture.identity.authority.clone(), tenant: fixture.identity.tenant,
        instance: fixture.identity.instance, audit: audit.clone(),
    });
    let associations = Arc::new(rss_mdm_device_service::Associations::new(audit, fixture.identity.tenant, &[29;32])?);
    let router = fixture.router(rss_mdm_http_contract::Router::new().nest("/api/v1",
        rss_mdm_management_http::user_profiles::routes(profiles)
        .merge(rss_mdm_management_http::device_views::routes(sessions, fixture.identity.authority.clone(), None).with_state(associations)))
        .merge(fixture.authorization()).merge(fixture.enrollment()))?;
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
    let alice_principal=authorization_subject(&alice,&router).await?;
    let without_mapping=admin.call(&router,Method::GET,&format!("/api/v1/user-profiles/{alice_principal}?view=latest"),None).await?;
    ensure!(without_mapping.0==StatusCode::OK);
    ensure!(without_mapping.1["fields"].as_array().unwrap().is_empty());
    ensure!(without_mapping.1["profiles"].as_array().unwrap().iter().any(|v|v["source"]["provider"]==provider && v["fixed"]["email"]["status"]=="available"));
    let observed=without_mapping.1["profiles"].as_array().unwrap().iter().find(|v|v["source"]["provider"]==provider).unwrap();
    ensure!(observed["providerConfigVersion"]==enabled["version"] && observed["sourceRevision"].is_null());
    let accounts=format!("{tenant}/accounts");
    let selected=admin.call(&router,Method::GET,&format!("{accounts}?source={provider}&fields=principalId,email,profileStatus,departmentStatus&filter=principalId=='{alice_principal}'"),None).await?;
    ensure!(selected.0==StatusCode::OK && selected.1["accounts"].as_array().context("selected account")?.len()==1);
    ensure!(selected.1["accounts"][0]["email"].is_string() && selected.1["accounts"][0]["profileStatus"]=="available" && selected.1["accounts"][0]["departmentStatus"]=="available");
    for (condition,matches) in [("department==team",true),("departmentSubtree==engineering",true),("department==engineering",false)] {
        let result=admin.call(&router,Method::GET,&format!("{accounts}?source={provider}&fields=principalId&filter=principalId=='{alice_principal}';{condition}"),None).await?;
        ensure!(result.0==StatusCode::OK && !result.1["accounts"].as_array().context("department account query")?.is_empty()==matches);
    }
    // The device consumer must show multiple real login sources without choosing a hidden
    // authority, and withdraw values when a provider is disabled.
    let (created_status, second)=admin.call(&router,Method::POST,&format!("{tenant}/providers"),Some(json!({"settings":settings,"clientSecret":"fixture-secret","caPem":std::fs::read_to_string(std::env::var("MDM_TEST_SSO_CA")?)?}))).await?;
    ensure!(created_status==StatusCode::CREATED);
    let second_id=second["id"].as_str().context("second provider")?;
    let second_path=format!("{tenant}/providers/{second_id}/enabled");
    let second_enabled=admin.call(&router,Method::POST,&second_path,Some(json!({"expectedVersion":second["version"],"enabled":true}))).await?;
    ensure!(second_enabled.0==StatusCode::OK);
    let admin_id=authorization_subject(&admin,&router).await?;
    let admin_profile=format!("{tenant}/accounts/{admin_id}/profile");
    let local=admin.call(&router,Method::GET,&admin_profile,None).await?;
    ensure!(local.0==StatusCode::OK);
    ensure!(admin.call(&router,Method::PUT,&admin_profile,Some(json!({"operationId":uuid::Uuid::new_v4(),"expectedRevision":local.1["revision"],"value":{"displayName":"Local Device Owner","username":"local-display-alias","email":null,"extensions":{},"maxAgeSeconds":14400}}))).await?.0==StatusCode::OK);
    admin=Browser::default();
    ensure!(admin.login_password(&router,"admin",PASSWORD).await?==StatusCode::OK);
    let link=admin.call(&router,Method::POST,&format!("{tenant}/oidc/{second_id}/link"),Some(json!({"returnTarget":"home","password":PASSWORD}))).await?;
    ensure!(link.0==StatusCode::OK,"second source link was rejected");
    let callback=provider_login(link.1["authorizationUrl"].as_str().context("link URL")?,"bob").await?;
    ensure!(admin.call(&router,Method::GET,&format!("{}?{}",callback.path(),callback.query().context("callback query")?),None).await?.0==StatusCode::SEE_OTHER);
    let mut linked=Browser::default();
    roundtrip(&router,&mut linked,second_id,"bob").await?;
    ensure!(authorization_subject(&linked,&router).await?==admin_id,"linked login changed the relationship principal");
    admin=Browser::default();
    ensure!(admin.login_password(&router,"admin",PASSWORD).await?==StatusCode::OK);
    ensure!(authorization_subject(&admin,&router).await?==admin_id,"link changed the relationship principal");
    let device=crate::test_support::case::name("sso-personnel");
    let directory_rule=json!({"subject":{"kind":"user","user":{"tenantId":case_tenant(),"instanceId":INSTANCE,"principalId":admin_id}},"grants":[{"operation":"inventory_read","scope":{"kind":"all_devices"}},{"operation":"enrollment","scope":{"kind":"all_devices"}},{"operation":"inventory_sensitive_read","scope":{"kind":"tenant"}},{"operation":"user_profiles_read","scope":{"kind":"tenant"}}]});
    crate::test_support::process::pg(&format!("BEGIN; SET LOCAL rss.tenant_id='{}'; INSERT INTO mdm_access.devices(tenant_id,id) VALUES('{}','{}'); INSERT INTO mdm_access.authorization_rules(tenant_id,instance,id,revision,document) VALUES('{}','{}','{}',1,'{}'::jsonb); COMMIT;",case_tenant(),case_tenant(),device,case_tenant(),INSTANCE,uuid::Uuid::new_v4(),directory_rule))?;
    admin.operation=Some(uuid::Uuid::new_v4());
    let owner=admin.call(&router,Method::PUT,&format!("/api/v1/devices/{device}/registration-user"),Some(json!({"expectedRevision":0,"user":{"tenantId":case_tenant(),"instanceId":INSTANCE,"principalId":admin_id}}))).await?;
    admin.operation=None;
    ensure!(owner.0==StatusCode::OK);
    let device_path=format!("/api/v1/device-views/endpoint/{device}");
    let device_view=admin.call(&router,Method::GET,&device_path,None).await?;
    ensure!(device_view.0==StatusCode::OK);
    let people=device_view.1["endpoints"][0]["registrationUser"]["display"]["profiles"].as_array().context("device sources")?;
    ensure!(people.iter().any(|p|p["source"]["kind"]=="identity_local" && p["status"]=="available" && p["displayName"]=="Local Device Owner"));
    ensure!(people.iter().any(|p|p["source"]["provider"]==second_id && p["status"]=="available" && p["username"]=="bob"),"missing linked source: {people:?}");
    for name in ["Local%20Device%20Owner","bob%20Fixture"] {
        let found=admin.call(&router,Method::GET,&format!("/api/v1/device-views?filter=search=icontains=%22{name}%22"),None).await?;
        ensure!(found.0==StatusCode::OK && found.1["items"].as_array().is_some_and(|items|items.len()==1),"a visible source name was not searchable: {found:?}");
    }
    ensure!(admin.call(&router,Method::POST,&second_path,Some(json!({"expectedVersion":second_enabled.1["version"],"enabled":false}))).await?.0==StatusCode::OK);
    let device_view=admin.call(&router,Method::GET,&device_path,None).await?;
    ensure!(device_view.0==StatusCode::OK);
    let withdrawn=device_view.1["endpoints"][0]["registrationUser"]["display"]["profiles"].as_array().context("withdrawn device sources")?;
    ensure!(withdrawn.iter().any(|p|p["source"]["provider"]==second_id && p["status"]=="unavailable" && p["displayName"].is_null() && p["username"].is_null()));
    let denied_source=admin.call(&router,Method::GET,&format!("{accounts}?source={second_id}&fields=principalId,email,profileStatus&filter=principalId=='{admin_id}'"),None).await?;
    ensure!(denied_source.0==StatusCode::OK && denied_source.1["accounts"][0]["profileStatus"]=="unavailable" && denied_source.1["accounts"][0]["email"].is_null());
    let local_source=admin.call(&router,Method::GET,&format!("{accounts}?source=local&fields=principalId,displayName,profileStatus&filter=principalId=='{admin_id}'"),None).await?;
    ensure!(local_source.0==StatusCode::OK && local_source.1["accounts"][0]["displayName"]=="Local Device Owner");
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
