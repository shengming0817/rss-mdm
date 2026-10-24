//! Two controlled RP backends consume actual Keycloak tokens through the public Broker.
use super::*;
use base64::Engine;
const ROOT: &str = "/api/v1/device-access/broker";
const CONFIG: &str = "/api/v1/device-access/enterprise/configuration";
fn enc(v: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v)
}
async fn admin(
    client: &Client,
    base: &str,
    token: &str,
    method: reqwest::Method,
    path: &str,
    body: Option<Value>,
) -> Result<Value> {
    let mut request = client
        .request(method, format!("{base}{path}"))
        .bearer_auth(token);
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request.send().await?;
    ensure!(
        response.status().is_success(),
        "IdP management {}",
        response.status()
    );
    let bytes = response.bytes().await?;
    if bytes.is_empty() {
        Ok(Value::Null)
    } else {
        Ok(serde_json::from_slice(&bytes)?)
    }
}
async fn configure(f: &mut Fixture, input: Value) -> Result<Value> {
    let reply = f.access_call(Method::POST, CONFIG, Some(input)).await?;
    ensure!(
        reply.0 == StatusCode::OK,
        "enterprise configuration {reply:?}"
    );
    Ok(reply.1)
}
pub(super) async fn ready(f: &mut Fixture) -> Result<Uuid> {
    let (policy, registration) = setup_platform(f, false, true).await?;
    let context = windows_context();
    ensure!(claim(f, &context).await?.0 == StatusCode::OK);
    let begun = user_call(
        f,
        "begin",
        json!({"operationId":Uuid::new_v4(),"policy":policy}),
        true,
    )
    .await?;
    ensure!(begun.0 == StatusCode::OK, "begin {begun:?}");
    let bound=user_call(f,"confirm",json!({"operationId":Uuid::new_v4(),"challenge":begun.1["id"],"nonce":begun.1["nonce"],"localSession":begun.1["localSession"]}),true).await?;
    ensure!(bound.0 == StatusCode::OK, "bound {bound:?}");
    let id = serde_json::from_value(bound.1["id"].clone())?;
    let offered = offer(f, &context, &registration).await?.1["task"].clone();
    ensure!(
        event(
            f,
            &offered,
            &context,
            &registration,
            json!({"kind":"received"})
        )
        .await?
        .0 == StatusCode::OK
    );
    let started = event(
        f,
        &offered,
        &context,
        &registration,
        json!({"kind":"start"}),
    )
    .await?;
    let signed: wire::SignedTask = serde_json::from_value(started.1["permit"].clone())?;
    let wire::TaskPayload::DeviceAccess(task) = signed.payload else {
        anyhow::bail!("access task expected")
    };
    let account = wire::AccessAccount::Windows {
        sid: "S-1-5-21-100-200-300-1001".into(),
        authority: wire::AccessWindowsAuthority::Local,
    };
    ensure!(
        event(
            f,
            &offered,
            &context,
            &registration,
            serde_json::to_value(wire::TaskEvent::DeviceAccessPrepared(
                wire::AccessPrepared {
                    binding_id: id,
                    binding_generation: task.binding_generation,
                    revision: task.revision,
                    definition_digest: task.definition_digest,
                    account: account.clone()
                }
            ))?
        )
        .await?
        .0 == StatusCode::OK
    );
    let envelope = access_envelope(&task, "S-1-5-21-100-200-300-1001")?;
    let escrow = event(
        f,
        &offered,
        &context,
        &registration,
        serde_json::to_value(wire::TaskEvent::CredentialEscrow(wire::CredentialEscrow {
            definition_digest: task.definition_digest,
            materials: vec![envelope],
        }))?,
    )
    .await?;
    ensure!(escrow.0 == StatusCode::OK, "escrow {escrow:?}");
    let ack: wire::TaskEventAck = serde_json::from_value(escrow.1)?;
    let result = wire::AccessResult {
        binding_id: id,
        binding_generation: task.binding_generation,
        revision: task.revision,
        definition_digest: task.definition_digest,
        effect: wire::AccessEffect::Applied {
            account,
            role: wire::AccessRole::Standard,
            mac: None,
            windows: Some(wire::AccessWindowsFacts {
                factor_generation: task.factor_generation,
                recovery: ack.credentials()[0].clone(),
            }),
        },
    };
    let applied = event(
        f,
        &offered,
        &context,
        &registration,
        serde_json::to_value(wire::TaskEvent::DeviceAccessResult(result))?,
    )
    .await?;
    ensure!(applied.0 == StatusCode::OK, "applied {applied:?}");
    Ok(id)
}
async fn backend(
    router: &Router,
    rp: &str,
    secret: &str,
    path: &str,
    body: Option<Value>,
) -> Result<(StatusCode, Value)> {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(if body.is_some() {
                    Method::POST
                } else {
                    Method::GET
                })
                .uri(format!("/api/v1/device-access/relying-parties/{rp}/{path}"))
                .header("host", "mdm.example.test")
                .header("authorization", format!("Bearer {secret}"))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(
                    &body.unwrap_or(Value::Null),
                )?))?,
        )
        .await?;
    let status = response.status();
    let bytes = response.into_body().collect().await?.to_bytes();
    Ok((status, serde_json::from_slice(&bytes)?))
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=device-access.http: real Keycloak and two controlled RP backends"]
async fn two_rps_exchange_cancel_and_revoke() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let issuer = std::env::var("MDM_TEST_SSO_ISSUER")?;
    let ca = std::env::var("MDM_TEST_SSO_CA")?;
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(&ca)?)?)
        .build()?;
    let origin = issuer.trim_end_matches("/realms/mdm");
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
    let token = zeroize::Zeroizing::new(
        token["access_token"]
            .as_str()
            .context("admin token")?
            .to_owned(),
    );
    let admin_base = format!("{origin}/admin/realms/mdm");
    let directory = tempfile::tempdir()?;
    let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1)?;
    let key = openssl::pkey::PKey::from_ec_key(openssl::ec::EcKey::generate(&group)?)?;
    let public = String::from_utf8(key.public_key_to_pem()?)?;
    let signer = directory.path().join("signer");
    std::fs::write(&signer, key.private_key_to_pem_pkcs8()?)?;
    std::fs::set_permissions(&signer, std::fs::Permissions::from_mode(0o600))?;
    let provider = Uuid::new_v4();
    let mut clients = vec![];
    let mut secrets = vec![];
    for rp in ["rp-a", "rp-b"] {
        let target = json!({"id":rp,"issuer":format!("https://mdm.example.test/{rp}"),"client_id":rp,"token_endpoint":format!("{issuer}/protocol/openid-connect/token"),"scopes":["openid"]});
        let confidential = directory.path().join(format!("{rp}-client"));
        std::fs::write(&confidential, "fixture-enterprise-secret")?;
        std::fs::set_permissions(&confidential, std::fs::Permissions::from_mode(0o600))?;
        let secret = enc(&[if rp == "rp-a" { 31 } else { 47 }; 32]);
        let backend_key = directory.path().join(format!("{rp}-backend"));
        std::fs::write(&backend_key, &secret)?;
        std::fs::set_permissions(&backend_key, std::fs::Permissions::from_mode(0o600))?;
        clients.push(json!({"target":target,"provider":provider,"issuer":issuer,"client_secret_file":confidential,"private_ca_file":ca,"private_cidrs":[],"backend_key_id":"test-1","backend_secret_file":backend_key}));
        secrets.push(secret);
        admin(&client,&admin_base,&token,reqwest::Method::POST,"/identity-provider/instances",Some(json!({"alias":rp,"providerId":"jwt-authorization-grant","enabled":true,"config":{"issuer":format!("https://mdm.example.test/{rp}"),"jwtAuthorizationGrantEnabled":"true","jwtAuthorizationGrantAssertionReuseAllowed":"false","jwtAuthorizationGrantMaxAllowedAssertionExpiration":"30","jwtAuthorizationGrantAssertionSignatureAlg":"ES256","jwtAuthorizationGrantLimitAccessTokenExp":"true","useJwksUrl":"false","publicKeySignatureVerifier":public,"publicKeySignatureVerifierKeyId":"enterprise-1"}}))).await?;
        admin(&client,&admin_base,&token,reqwest::Method::POST,"/clients",Some(json!({"clientId":rp,"enabled":true,"protocol":"openid-connect","publicClient":false,"secret":"fixture-enterprise-secret","standardFlowEnabled":false,"attributes":{"oauth2.jwt.authorization.grant.enabled":"true","oauth2.jwt.authorization.grant.idp":rp},"protocolMappers":[{"name":"rp-audience","protocol":"openid-connect","protocolMapper":"oidc-audience-mapper","config":{"included.client.audience":rp,"access.token.claim":"true","id.token.claim":"false"}}]}))).await?;
    }
    admin(&client,&admin_base,&token,reqwest::Method::POST,"/clients",Some(json!({"clientId":"mdm-offboarding","enabled":true,"protocol":"openid-connect","publicClient":false,"secret":"fixture-admin-secret","standardFlowEnabled":false,"serviceAccountsEnabled":true}))).await?;
    let admin_client = admin(
        &client,
        &admin_base,
        &token,
        reqwest::Method::GET,
        "/clients?clientId=mdm-offboarding",
        None,
    )
    .await?;
    let admin_id = admin_client[0]["id"].as_str().context("admin client")?;
    let service_account = admin(
        &client,
        &admin_base,
        &token,
        reqwest::Method::GET,
        &format!("/clients/{admin_id}/service-account-user"),
        None,
    )
    .await?;
    let service_id = service_account["id"].as_str().context("service account")?;
    let management = admin(
        &client,
        &admin_base,
        &token,
        reqwest::Method::GET,
        "/clients?clientId=realm-management",
        None,
    )
    .await?;
    let management_id = management[0]["id"]
        .as_str()
        .context("realm management client")?;
    let mut roles = vec![];
    for role in ["manage-users", "view-users", "query-users"] {
        roles.push(
            admin(
                &client,
                &admin_base,
                &token,
                reqwest::Method::GET,
                &format!("/clients/{management_id}/roles/{role}"),
                None,
            )
            .await?,
        );
    }
    admin(
        &client,
        &admin_base,
        &token,
        reqwest::Method::POST,
        &format!("/users/{service_id}/role-mappings/clients/{management_id}"),
        Some(json!(roles)),
    )
    .await?;
    let admin_secret = directory.path().join("admin-secret");
    std::fs::write(&admin_secret, "fixture-admin-secret")?;
    std::fs::set_permissions(&admin_secret, std::fs::Permissions::from_mode(0o600))?;
    let addresses = vec![format!(
        "127.0.0.1:{}",
        url::Url::parse(&issuer)?
            .port_or_known_default()
            .context("IdP port")?
    )];
    let mut base: Value =
        serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
    base["identity"]["enterprise"] = json!({"key_id":"enterprise-1","signing_key_file":signer,"clients":clients,"administrators":[{"configuration":{"provider":provider,"issuer":issuer,"clientId":"mdm-offboarding","addresses":addresses},"client_secret_file":admin_secret,"private_ca_file":ca}]});
    let mut f = Fixture::from_config(base).await?;
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async {
        for operation in [crate::authorization::Permission::EnterpriseApplicationsWrite,crate::authorization::Permission::EnterpriseApplicationsRead]{f.grants.push(crate::authorization::Grant{operation,scope:crate::authorization::Scope::Tenant});}
        let binding=ready(&mut f).await?;
        let users=admin(&client,&admin_base,&token,reqwest::Method::GET,"/users?username=alice&exact=true",None).await?;let user=users[0]["id"].as_str().context("stable IdP subject")?;
        let assertion_sub=format!("{}/{}/{}",INSTANCE,case_tenant(),f.author_id);
        for rp in ["rp-a","rp-b"]{
            admin(&client,&admin_base,&token,reqwest::Method::POST,&format!("/users/{user}/federated-identity/{rp}"),Some(json!({"identityProvider":rp,"userId":assertion_sub,"userName":"fixture-person"}))).await?;
            configure(&mut f,json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"configuration":{"kind":"relying_party","id":rp,"enabled":true,"callback":format!("https://{rp}.example.test/callback"),"capabilities":["native_key"]}})).await?;
        }
        let person=json!({"instance":INSTANCE,"principal":f.author_id});
        configure(&mut f,json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"configuration":{"kind":"subject","provider":provider,"person":person,"enabled":true,"subject":user,"username":"alice"}})).await?;
        let rng=ring::rand::SystemRandom::new();let pkcs8=ring::signature::EcdsaKeyPair::generate_pkcs8(&ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,&rng).map_err(|_|anyhow::anyhow!("key generation"))?;
        let native=ring::signature::EcdsaKeyPair::from_pkcs8(&ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,pkcs8.as_ref(),&rng).map_err(|_|anyhow::anyhow!("key import"))?;
        let key=native.public_key().as_ref();let operation=Uuid::new_v4();
        let mut registration=rss_mdm_agent_wire::enterprise::KeyRegistration{binding_id:binding,binding_generation:1,factor_generation:1,binding_revision:1,public_key:rss_mdm_agent_wire::platform_sso::PublicKey{kty:"EC".into(),crv:"P-256".into(),x:enc(&key[1..33]),y:enc(&key[33..])},signature:String::new()};
        registration.signature=enc(native.sign(&rng,&registration.signing_bytes(Uuid::parse_str(case_tenant())?,Uuid::parse_str(INSTANCE)?,Uuid::parse_str(&f.author_id)?,operation)?).map_err(|_|anyhow::anyhow!("sign"))?.as_ref());
        configure(&mut f,json!({"operationId":operation,"expectedRevision":0,"configuration":{"kind":"windows_key","registration":registration}})).await?;
        let configurations=f.author.call(&f.router,Method::GET,CONFIG,None).await?;
        ensure!(configurations.0==StatusCode::OK&&configurations.1["items"].as_array().is_some_and(|items|items.len()==4&&items.iter().any(|v|v["kind"]=="subject")&&items.iter().any(|v|v["kind"]=="windows_key")),"configuration directory {configurations:?}");
        let mut browser=Browser::default();ensure!(browser.call(&f.router,Method::POST,&format!("{ROOT}/browser"),None).await?.0==StatusCode::OK);
        let mut sessions=vec![];
        for (index,rp) in ["rp-a","rp-b"].iter().enumerate(){
            let operation=Uuid::new_v4();let begin=json!({"operationId":operation,"bindingId":binding,"relyingParty":rp});
            let challenge=browser.call(&f.router,Method::POST,ROOT,Some(begin.clone())).await?;ensure!(challenge.0==StatusCode::OK,"challenge {challenge:?}");
            ensure!(browser.call(&f.router,Method::POST,ROOT,Some(begin)).await?==challenge);
            let status=browser.call(&f.router,Method::GET,&format!("{ROOT}/{operation}"),None).await?;ensure!(status.0==StatusCode::OK&&status.1["phase"]=="awaiting_proof","normal same-origin GET {status:?}");
            ensure!(!browser.call_headers(&f.router,Method::GET,&format!("{ROOT}/{operation}"),None,Some((&["origin"],&["https://other.example.test"]))).await?.0.is_success());

            let challenge:rss_mdm_agent_wire::enterprise::Challenge=serde_json::from_value(challenge.1)?;
            let signature=enc(native.sign(&rng,&challenge.signing_payload).map_err(|_|anyhow::anyhow!("sign"))?.as_ref());
            let completed=browser.call(&f.router,Method::POST,&format!("{ROOT}/complete"),Some(json!({"operationId":operation,"challengeId":challenge.challenge_id,"nonce":challenge.nonce,"proof":{"signature":signature,"accessToken":null}}))).await?;
            ensure!(completed.0==StatusCode::OK,"complete {completed:?}");ensure!(completed.1["phase"]=="ready"&&completed.1["accessToken"].is_null()&&completed.1["assertion"].is_null());
            ensure!(completed.1["callback"]==format!("https://{rp}.example.test/callback"));
            let body=json!({"session":operation,"operationId":Uuid::new_v4(),"continuation":completed.1["continuation"]});
            let wrong=backend(&f.router,if index==0{"rp-b"}else{"rp-a"},&secrets[1-index],"consume",Some(body.clone())).await?;ensure!(!wrong.0.is_success());
            let consumed=backend(&f.router,rp,&secrets[index],"consume",Some(body.clone())).await?;ensure!(consumed.0==StatusCode::OK,"consume status {}",consumed.0);
            ensure!(consumed.1["subject"]==user&&consumed.1["accessToken"].as_str().is_some_and(|v|v.split('.').count()==3));
            ensure!(backend(&f.router,rp,&secrets[index],"consume",Some(body)).await?==consumed);
            ensure!(backend(&f.router,rp,&secrets[index],&format!("sessions/{operation}"),None).await?.0==StatusCode::OK);
            sessions.push(operation);
        }
        ensure!(browser.call(&f.router,Method::POST,&format!("{ROOT}/{}/cancel",sessions[0]),None).await?.0==StatusCode::OK);
        ensure!(!backend(&f.router,"rp-a",&secrets[0],&format!("sessions/{}",sessions[0]),None).await?.0.is_success());
        let path=format!("/api/v1/devices/{}/device-access/bindings/{binding}",execution::case_device_id());
        ensure!(f.author.login(&f.router,"admin").await?==StatusCode::OK);f.access_authenticator=None;
        let operator=browser_subject(&f.author,&f.router).await?;
        let mut grants=f.grants.clone();grants.push(crate::authorization::Grant{operation:crate::authorization::Permission::IdentityAccountsManage,scope:crate::authorization::Scope::Tenant});
        crate::test_support::identity::set_grants(case_tenant(),&operator,grants).await?;ensure!(f.author.login(&f.router,"admin").await?==StatusCode::OK);
        let offboarding=Uuid::new_v4();
        let denied=f.access_call(Method::PUT,&path,Some(json!({"operationId":offboarding,"expectedRevision":1,"action":{"kind":"offboard","disposition":"keep"}}))).await?;
        ensure!(denied.0==StatusCode::OK,"offboard {denied:?}");
        let operation_path=format!("/api/v1/devices/{}/device-access/operations/{offboarding}/offboarding",execution::case_device_id());
        let identity=f.author.call(&f.router,Method::POST,&format!("{operation_path}/identity"),Some(json!({"kind":"execute"}))).await?;ensure!(identity.0==StatusCode::OK,"Identity disposition {identity:?}");
        let progress=f.author.call(&f.router,Method::GET,&operation_path,None).await?;ensure!(progress.0==StatusCode::OK,"progress {progress:?}");
        let target=progress.1["operation"]["idp"][0]["id"].clone();ensure!(target.is_string(),"frozen IdP target {progress:?}");
        // Empty sessions while the account is enabled cannot close the logout obligation.
        admin(&client,&admin_base,&token,reqwest::Method::POST,&format!("/users/{user}/logout"),None).await?;
        let reconciled=f.author.call(&f.router,Method::POST,&format!("{operation_path}/idp"),Some(json!({"kind":"reconcile","target":target}))).await?;
        ensure!(reconciled.0==StatusCode::OK,"reconcile {reconciled:?}");
        ensure!(reconciled.1["operation"]["idp"][0]["sessions"]=="pending","enabled account's empty sessions prematurely confirmed: {reconciled:?}");
        // Keycloak impersonation creates a real new user session after that observation.
        admin(&client,&admin_base,&token,reqwest::Method::POST,&format!("/users/{user}/impersonation"),None).await?;
        ensure!(admin(&client,&admin_base,&token,reqwest::Method::GET,&format!("/users/{user}/sessions"),None).await?.as_array().is_some_and(|sessions|!sessions.is_empty()));
        for action in ["disable_account","revoke_sessions"]{
            let input=json!({"kind":"execute","target":target,"action":action});
            let applied=f.author.call(&f.router,Method::POST,&format!("{operation_path}/idp"),Some(input.clone())).await?;
            ensure!(applied.0==StatusCode::OK,"IdP disposition {applied:?}");
            ensure!(f.author.call(&f.router,Method::POST,&format!("{operation_path}/idp"),Some(input)).await?.0==StatusCode::OK);
        }
        let state=admin(&client,&admin_base,&token,reqwest::Method::GET,&format!("/users/{user}"),None).await?;ensure!(state["enabled"]==false);
        ensure!(admin(&client,&admin_base,&token,reqwest::Method::GET,&format!("/users/{user}/sessions"),None).await?.as_array().is_some_and(Vec::is_empty));
        let pending=f.author.call(&f.router,Method::GET,&operation_path,None).await?;ensure!(pending.1["complete"]==false,"offline native effects still require confirmation");
        ensure!(!backend(&f.router,"rp-b",&secrets[1],&format!("sessions/{}",sessions[1]),None).await?.0.is_success());
        Ok(())
    }).await
}
