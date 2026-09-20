use super::*;
use uuid::Uuid;
const SECURITY_GROUP: &str = "7bb94be2-8f62-4bd6-93e7-7ec1f79b2363";
async fn put(
    admin: &mut Browser,
    router: &Router,
    path: &str,
    revision: u64,
    value: Value,
) -> Result<Value> {
    let (status, result) = admin
        .call(
            router,
            Method::PUT,
            path,
            Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":revision,"value":value})),
        )
        .await?;
    ensure!(
        status == StatusCode::OK,
        "authorization write: {status} {result}"
    );
    Ok(result)
}
async fn grants(browser: &Browser, router: &Router) -> Result<Value> {
    let (status, result) = browser
        .clone()
        .call(router, Method::GET, "/api/v1/authorization", None)
        .await?;
    ensure!(status == StatusCode::OK);
    Ok(result["grants"].clone())
}
fn allows(grants: &Value, operation: &str) -> bool {
    grants
        .as_array()
        .unwrap()
        .iter()
        .any(|g| g["operation"] == operation)
}
async fn wait_until(deadline: i64) -> Result<()> {
    let seconds = deadline - crate::clock::SystemClock.unix_seconds()? + 1;
    ensure!(seconds <= 25, "bounded fixture deadline");
    if seconds > 0 {
        tokio::time::sleep(Duration::from_secs(seconds as u64)).await;
    }
    Ok(())
}
async fn department(value: Value) -> Result<()> {
    let issuer = std::env::var("MDM_TEST_SSO_ISSUER")?;
    let origin = issuer.strip_suffix("/realms/mdm").unwrap();
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(
            std::env::var("MDM_TEST_SSO_CA")?,
        )?)?)
        .build()?;
    let token: Value = client
        .post(format!(
            "{origin}/realms/master/protocol/openid-connect/token"
        ))
        .form(&[
            ("client_id", "admin-cli"),
            ("grant_type", "password"),
            ("username", "fixture-operator"),
            ("password", "fixture-operator-password"),
        ])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let token = token["access_token"].as_str().unwrap();
    let users: Vec<Value> = client
        .get(format!(
            "{origin}/admin/realms/mdm/users?username=alice&exact=true"
        ))
        .bearer_auth(token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let mut user = users.into_iter().next().unwrap();
    user["attributes"]["organization_snapshot"] = json!([value.to_string()]);
    client
        .put(format!(
            "{origin}/admin/realms/mdm/users/{}",
            user["id"].as_str().unwrap()
        ))
        .bearer_auth(token)
        .json(&user)
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}
pub(super) async fn four_subjects_and_independent_lifetimes(
    router: &Router,
    admin: &mut Browser,
    alice: &mut Browser,
    bob: &Browser,
    provider: &str,
    version: i64,
) -> Result<()> {
    let principal = browser_subject(alice, router).await?;
    let user = json!({"instanceId":INSTANCE,"tenantId":TENANT,"principalId":principal});
    let source = json!({"providerId":provider,"issuer":std::env::var("MDM_TEST_SSO_ISSUER")?,"configurationVersion":version});
    let local_group = Uuid::new_v4();
    let group_path = format!("/api/v1/authorization/user-groups/{local_group}");
    put(
        admin,
        router,
        &group_path,
        0,
        json!({"name":"MDM explicit members","enabled":true,"members":[user]}),
    )
    .await?;
    let cases = [
        (
            json!({"kind":"user","user":user}),
            "inventory_read",
            json!({"kind":"device","id":"user-device"}),
        ),
        (
            json!({"kind":"idp_group","source":source,"id":SECURITY_GROUP}),
            "credentials",
            json!({"kind":"device","id":"group-device"}),
        ),
        (
            json!({"kind":"department","source":source,"id":"engineering","matching":"subtree"}),
            "enrollment",
            json!({"kind":"device","id":"department-device"}),
        ),
        (
            json!({"kind":"department","source":source,"id":"team","matching":"exact"}),
            "group_read",
            json!({"kind":"tenant"}),
        ),
        (
            json!({"kind":"user_group","id":local_group}),
            "device_wipe",
            json!({"kind":"device","id":"local-group-device"}),
        ),
        (
            json!({"kind":"department","source":source,"id":"engineering","matching":"exact"}),
            "policy_read",
            json!({"kind":"tenant"}),
        ),
        (
            json!({"kind":"idp_group","source":{"providerId":Uuid::new_v4(),"issuer":source["issuer"],"configurationVersion":version},"id":SECURITY_GROUP}),
            "resource_read",
            json!({"kind":"tenant"}),
        ),
        (
            json!({"kind":"department","source":{"providerId":provider,"issuer":source["issuer"],"configurationVersion":version+1},"id":"team","matching":"exact"}),
            "scope_read",
            json!({"kind":"tenant"}),
        ),
    ];
    let mut paths = Vec::new();
    for (subject, operation, scope) in cases {
        let path = format!("/api/v1/authorization/rules/{}", Uuid::new_v4());
        put(
            admin,
            router,
            &path,
            0,
            json!({"subject":subject,"grants":[{"operation":operation,"scope":scope}]}),
        )
        .await?;
        paths.push(path);
    }
    let initial = grants(alice, router).await?;
    for operation in [
        "inventory_read",
        "credentials",
        "enrollment",
        "group_read",
        "device_wipe",
    ] {
        ensure!(
            allows(&initial, operation),
            "missing {operation}: {initial}"
        );
    }
    for operation in ["policy_read", "resource_read", "scope_read"] {
        ensure!(!allows(&initial, operation));
    }
    ensure!(grants(bob, router).await?.as_array().unwrap().is_empty());
    ensure!(
        alice
            .call(
                router,
                Method::POST,
                "/api/v1/devices/local-group-device/actions",
                Some(json!({"action":"wipe"}))
            )
            .await?
            .0
            == StatusCode::NOT_IMPLEMENTED
    );
    ensure!(
        alice
            .call(
                router,
                Method::POST,
                "/api/v1/devices/user-device/actions",
                Some(json!({"action":"wipe"}))
            )
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    let group_deadline = initial
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["operation"] == "credentials")
        .unwrap()["observation"]["expiresAt"]
        .as_i64()
        .unwrap();
    let department_deadline = initial
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["operation"] == "enrollment")
        .unwrap()["observation"]["expiresAt"]
        .as_i64()
        .unwrap();
    // A newly signed invalid directory withholds only department grants; old observations remain intact.
    department(json!({"version":1,"sourceRevision":"invalid","nodes":[{"id":"team","displayName":"Team","parentId":"missing"}],"memberships":["team"]})).await?;
    let mut invalid = Browser::default();
    roundtrip(router, &mut invalid, provider, "login", "alice").await?;
    let bad = grants(&invalid, router).await?;
    ensure!(
        !allows(&bad, "enrollment")
            && !allows(&bad, "group_read")
            && allows(&bad, "inventory_read")
            && allows(&bad, "credentials")
            && allows(&bad, "device_wipe")
    );
    ensure!(allows(&grants(alice, router).await?, "enrollment"));
    department(json!({"version":1,"sourceRevision":"mdm-r2","nodes":[{"id":"root","displayName":"Company","parentId":null},{"id":"engineering","displayName":"Engineering","parentId":"root"},{"id":"team","displayName":"Team","parentId":"root"}],"memberships":["team"]})).await?;
    let mut moved = Browser::default();
    roundtrip(router, &mut moved, provider, "login", "alice").await?;
    let newer = grants(&moved, router).await?;
    ensure!(!allows(&newer, "enrollment") && allows(&newer, "group_read"));
    wait_until(group_deadline).await?;
    let group_expired = grants(alice, router).await?;
    ensure!(
        !allows(&group_expired, "credentials")
            && allows(&group_expired, "enrollment")
            && allows(&group_expired, "inventory_read")
    );
    wait_until(department_deadline).await?;
    let expired = grants(alice, router).await?;
    ensure!(
        !allows(&expired, "enrollment")
            && !allows(&expired, "group_read")
            && allows(&expired, "inventory_read")
            && allows(&expired, "device_wipe")
    );
    // A proof's own deadline removes every capability, including direct-user and local-group grants.
    let identity = crate::identity_fixture::identity(TENANT).await?;
    let access = crate::AccessStore::connect(
        crate::identity_fixture::config(TENANT)?
            .access_database
            .options()?,
    )
    .await?;
    let credential = rss_identity_core::session::SessionSecret::parse(
        alice.cookies["__Host-identity-session"].clone(),
    )?;
    let session = identity
        .authority
        .inspect_session(
            identity.tenant,
            credential,
            rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                Duration::from_millis(250),
            ),
        )
        .await?;
    let proof = crate::identity::Principal::new(session)?
        .load_authorization(&access)
        .await?;
    tokio::time::sleep(Duration::from_millis(300)).await;
    ensure!(matches!(
        proof.require(
            crate::authorization::Permission::InventoryRead,
            Some("user-device")
        ),
        Err(crate::Error::Unauthorized)
    ));
    access.close().await;
    for path in paths {
        put(admin, router, &path, 1, Value::Null).await?;
    }
    put(admin, router, &group_path, 1, Value::Null).await?;
    println!("MDM_FOUR_SUBJECTS_REAL_KEYCLOAK_PASSED");
    Ok(())
}
