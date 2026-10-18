//! Product ingress and durable authority over real HTTP handlers and PostgreSQL.
#![allow(
    clippy::cognitive_complexity,
    reason = "distinct authentication and lifecycle denial assertions"
)]
use super::*;
use rss_mdm_authorization_service::{
    OperationAuthority, Permission,
    context::AuthorizedPrincipal,
    credential::{ApiKeySecret, RequestCredential},
};

async fn call(
    router: &Router,
    method: Method,
    path: &str,
    headers: &[(&str, &str)],
    input: Option<Value>,
) -> Result<(StatusCode, Value)> {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "mdm.example.test");
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let body = match input {
        Some(input) => {
            request = request.header("content-type", "application/json");
            Body::from(serde_json::to_vec(&input)?)
        }
        None => Body::empty(),
    };
    let response = tokio::spawn(router.clone().oneshot(request.body(body)?)).await??;
    let status = response.status();
    if status == StatusCode::UNAUTHORIZED
        && headers
            .iter()
            .any(|(name, _)| matches!(*name, "authorization" | "x-api-key"))
    {
        ensure!(response.headers().contains_key("www-authenticate"));
    }
    ensure!(response.headers()["cache-control"] == "no-store");
    let bytes = response.into_body().collect().await?.to_bytes();
    Ok((
        status,
        if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes)?
        },
    ))
}
async fn manager(router: &Router) -> Result<Browser> {
    let mut browser = Browser::default();
    let tenant = pg("SELECT management_tenant_id::text FROM public.mdm_installation")?;
    let response = browser
        .call(
            router,
            Method::POST,
            &format!("/api/v1/identity/tenants/{}/login", tenant.trim()),
            Some(json!({"login":"bootstrap","password":PASSWORD})),
        )
        .await?;
    ensure!(
        response.0 == StatusCode::OK,
        "management login: {}",
        response.0
    );
    Ok(browser)
}
async fn policy(
    browser: &mut Browser,
    router: &Router,
    revision: u64,
    networks: Value,
) -> Result<()> {
    let response = browser.call(router, Method::PUT, "/api/v1/tenant-administration/api-access/network-policy", Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":revision,"networks":networks}))).await?;
    ensure!(
        response.0 == StatusCode::OK,
        "network policy: {}",
        response.0
    );
    ensure!(response.1["revision"] == revision + 1);
    Ok(())
}
async fn valid(store: &crate::Database, grant: &OperationAuthority) -> Result<bool> {
    let mut tx = store.begin(case_tenant()).await?;
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&mut *tx)
            .await?;
    let valid = grant.valid(&mut tx, Permission::InventoryRead, now).await?;
    tx.rollback().await?;
    Ok(valid)
}

#[tokio::test]
#[ignore = "MODULE=authorization.programmatic: real HTTP, credentials and PostgreSQL"]
async fn programmatic_keys_tokens_and_online_network_policy() -> Result<()> {
    let Fixture {
        resources,
        router,
        mut admin,
        store,
        ..
    } = fixture().await?;
    resources.finish(async {
        let mut manager = manager(&router).await?;
        let network_path = "/api/v1/tenant-administration/api-access/network-policy";
        let (status, initial) = manager.call(&router, Method::GET, network_path, None).await?;
        ensure!(status == StatusCode::OK && initial["networks"] == json!([]) && initial["revision"] == 0);
        ensure!(admin.call(&router, Method::GET, network_path, None).await?.0 == StatusCode::UNAUTHORIZED);
        let login_path = format!("/api/v1/identity/tenants/{}/bearer/login", case_tenant());
        let login = json!({"login":case::login("admin"),"password":PASSWORD});
        ensure!(call(&router, Method::POST, &login_path, &[], Some(login.clone())).await?.0 == StatusCode::FORBIDDEN);

        ensure!(audit_count(|r| r.action()=="authentication" && r.status()==403 && r.result()=="denied")? > 0);
        let id = Uuid::new_v4();
        let metadata = json!({"name":"automation","enabled":true,"expiresAt":null,"grants":[{"operation":"inventory_read","scope":{"kind":"all_devices"}}]});
        let operation = Uuid::new_v4();
        let create = json!({"id":id,"operationId":operation,"metadata":metadata});
        let (status, issued) = admin.call(&router, Method::POST, "/api/v1/api-keys", Some(create.clone())).await?;
        ensure!(status == StatusCode::OK, "key creation: {status}");
        let secret = issued["secret"].as_str().ok_or_else(|| anyhow::anyhow!("missing first secret"))?.to_owned();
        ensure!(secret.len() == 101);
        let (_, replay) = admin.call(&router, Method::POST, "/api/v1/api-keys", Some(create)).await?;
        ensure!(replay["secret"].is_null() && replay["receipt"] == issued["receipt"]);
        let key_path = format!("/api/v1/api-keys/{id}");
        let (_, read) = admin.call(&router, Method::GET, &key_path, None).await?;
        ensure!(!read.to_string().contains(&secret) && read["id"] == id.to_string());
        let inventory = format!("{}/inventory", case_device());
        ensure!(call(&router, Method::GET, &inventory, &[("x-api-key", &secret)], None).await?.0 == StatusCode::FORBIDDEN);
        policy(&mut manager, &router, 0, json!(["127.0.0.1/32"])).await?;
        ensure!(call(&router, Method::GET, &inventory, &[("x-api-key", &secret)], None).await?.0 == StatusCode::OK);
        ensure!(call(&router, Method::GET, "/api/v1/api-keys", &[("x-api-key", &secret)], None).await?.0 == StatusCode::FORBIDDEN);
        ensure!(call(&router, Method::GET, "/api/v1/policies", &[("x-api-key", &secret)], None).await?.0 == StatusCode::FORBIDDEN);
        let (status, token) = call(&router, Method::POST, &login_path, &[], Some(login.clone())).await?;
        ensure!(status == StatusCode::OK, "bearer login: {status}");
        let bearer = format!("Bearer {}", token["accessToken"].as_str().ok_or_else(|| anyhow::anyhow!("missing bearer"))?);
        ensure!(call(&router, Method::GET, &inventory, &[("authorization", &bearer)], None).await?.0 == StatusCode::OK);
        ensure!(call(&router,Method::GET,"/api/v1/apple/organizations",&[("authorization",&bearer)],None).await?.0==StatusCode::OK);
        for (method,path) in [(Method::GET,"/api/v1/self-enrollments"),(Method::POST,"/api/v1/self-enrollments"),(Method::GET,"/api/v1/registration-quotas/me")] {
            ensure!(call(&router,method,path,&[("authorization",&bearer)],Some(json!({}))).await?.0==StatusCode::FORBIDDEN);
        }
        for headers in [vec![("authorization", bearer.as_str()), ("x-api-key", secret.as_str())], vec![("x-api-key", secret.as_str()), ("x-api-key", secret.as_str())], vec![("authorization", bearer.as_str()), ("authorization", bearer.as_str())], vec![("x-api-key", secret.as_str()), ("cookie", "__Host-identity-session=broken")]] {
            ensure!(call(&router, Method::GET, &inventory, &headers, None).await?.0 == StatusCode::BAD_REQUEST);
        }
        let digest = pg(&format!("SELECT encode(secret_digest,'hex') FROM mdm_access.api_keys WHERE tenant_id='{}' AND id='{id}'", case_tenant()))?;
        ensure!(digest.trim().len() == 64 && !digest.contains(&secret));

        let access = store.authorization_store();
        let parsed = ApiKeySecret::parse(secret.clone())?;
        let proof = AuthorizedPrincipal::from_identity(access.authenticate_key(case_tenant(), &parsed).await?).load_authorization(&access).await?;
        let grant = OperationAuthority::all_devices(proof.authorization()?, &proof, Permission::InventoryRead)?;
        ensure!(valid(&store, &grant).await?);
        let (status, rotation) = admin.call(&router, Method::POST, &format!("{key_path}/rotate"), Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":1}))).await?;
        ensure!(status == StatusCode::OK);
        let rotated = rotation["secret"].as_str().ok_or_else(|| anyhow::anyhow!("missing rotated secret"))?.to_owned();
        ensure!(rotated != secret && valid(&store, &grant).await?);
        ensure!(call(&router, Method::GET, &inventory, &[("x-api-key", &secret)], None).await?.0 == StatusCode::UNAUTHORIZED);
        ensure!(call(&router, Method::GET, &inventory, &[("x-api-key", &rotated)], None).await?.0 == StatusCode::OK);
        let (identity, identity_resources) = crate::test_support::identity::identity(case_tenant()).await?;
        identity_resources.finish(async {
            let sessions = rss_mdm_authorization_service::session::SessionAuthority::new(identity.authority.clone(), identity.tenant);
            ensure!(sessions.authenticate(&access, RequestCredential::ApiKey(parsed)).await.is_err());
            Ok(())
        }).await?;
        let mut named = metadata.clone(); named["name"] = json!("renamed");
        ensure!(admin.call(&router, Method::PUT, &key_path, Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":2,"metadata":named}))).await?.0 == StatusCode::OK);
        ensure!(valid(&store, &grant).await?);
        let mut disabled = named.clone(); disabled["enabled"] = json!(false);
        ensure!(admin.call(&router, Method::PUT, &key_path, Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":3,"metadata":disabled}))).await?.0 == StatusCode::OK);
        ensure!(!valid(&store, &grant).await?);
        ensure!(call(&router, Method::GET, &inventory, &[("x-api-key", &rotated)], None).await?.0 == StatusCode::UNAUTHORIZED);
        ensure!(admin.call(&router, Method::PUT, &key_path, Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":4,"metadata":named}))).await?.0 == StatusCode::OK);
        ensure!(!valid(&store, &grant).await?);
        ensure!(call(&router, Method::GET, &inventory, &[("x-api-key", &rotated)], None).await?.0 == StatusCode::OK);
        policy(&mut manager, &router, 1, json!(["192.0.2.0/24"])).await?;
        for (name, credential) in [("authorization", bearer.as_str()), ("x-api-key", rotated.as_str())] {
            ensure!(call(&router, Method::GET, &inventory, &[(name, credential), ("x-forwarded-for", "192.0.2.1")], None).await?.0 == StatusCode::FORBIDDEN);
        }
        ensure!(call(&router, Method::POST, &login_path, &[("x-forwarded-for", "192.0.2.1")], Some(login)).await?.0 == StatusCode::FORBIDDEN);
        policy(&mut manager, &router, 2, json!(["127.0.0.1"])).await?;
        let logout = format!("/api/v1/identity/tenants/{}/bearer/logout", case_tenant());
        ensure!(call(&router, Method::POST, &logout, &[("authorization", &bearer)], None).await?.0 == StatusCode::NO_CONTENT);
        ensure!(call(&router, Method::GET, &inventory, &[("authorization", &bearer)], None).await?.0 == StatusCode::UNAUTHORIZED);
        ensure!(admin.call(&router, Method::POST, &format!("{key_path}/revoke"), Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":5}))).await?.0 == StatusCode::OK);
        ensure!(call(&router, Method::GET, &inventory, &[("x-api-key", &rotated)], None).await?.0 == StatusCode::UNAUTHORIZED);
        policy(&mut manager, &router, 3, json!([])).await?;
        Ok(())
    }).await
}

#[tokio::test]
#[ignore = "MODULE=authorization.programmatic: real key scope, lifecycle and transaction settlement"]
async fn key_scope_expiry_creator_independence_and_uncertain_issuance() -> Result<()> {
    let Fixture {
        resources,
        router,
        mut admin,
        audit_store,
        store,
        ..
    } = fixture().await?;
    resources.finish(async {
        let mut manager = manager(&router).await?;
        policy(&mut manager, &router, 0, json!(["127.0.0.1"])).await?;
        let scoped = json!({"name":"scoped","enabled":true,"expiresAt":null,"grants":[{"operation":"inventory_read","scope":{"kind":"device","id":case::name("device-1")}}]});
        let id = Uuid::new_v4();
        let create = json!({"id":id,"operationId":Uuid::new_v4(),"metadata":scoped});
        audit_store.inject_next_fault(rss_audit_postgres::PgFault::CommitUnknownAfterAck);
        let (status, unknown) = admin.call(&router, Method::POST, "/api/v1/api-keys", Some(create.clone())).await?;
        ensure!(status == StatusCode::SERVICE_UNAVAILABLE && unknown.get("secret").is_none());
        ensure!(pg(&format!("SELECT count(*) FROM mdm_access.api_keys WHERE tenant_id='{}' AND id='{id}'",case_tenant()))?.trim() == "1");
        let (status, replay) = admin.call(&router, Method::POST, "/api/v1/api-keys", Some(create)).await?;
        ensure!(status == StatusCode::OK && replay["secret"].is_null());
        let path = format!("/api/v1/api-keys/{id}");
        let (status, rotation) = admin.call(&router, Method::POST, &format!("{path}/rotate"), Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":1}))).await?;
        ensure!(status == StatusCode::OK);
        let secret = rotation["secret"].as_str().ok_or_else(|| anyhow::anyhow!("missing rotated secret"))?.to_owned();
        let inventory = format!("{}/inventory",case_device());
        ensure!(call(&router, Method::GET, &inventory, &[("x-api-key",&secret)], None).await?.0 == StatusCode::OK);
        ensure!(call(&router, Method::GET, "/api/v1/devices/outside-key-scope/inventory", &[("x-api-key",&secret)], None).await?.0 == StatusCode::FORBIDDEN);
        ensure!(store.authorization_store().authenticate_key(&Uuid::new_v4().to_string(), &ApiKeySecret::parse(secret.clone())?).await.is_err());
        for permission in ["identity_accounts_manage","identity_providers_manage","authorization_write","tenant_create"] {
            let mut input = scoped.clone(); input["grants"]=json!([{"operation":permission,"scope":{"kind":"tenant"}}]);
            ensure!(admin.call(&router, Method::PUT, &path, Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":2,"metadata":input}))).await?.0 == StatusCode::BAD_REQUEST);
        }
        // Real rollback after the key write: no metadata, operation receipt or secret escapes.
        let failed_id = Uuid::new_v4();
        pg("REVOKE INSERT ON mdm_audit.receipts FROM mdm_access")?;
        let failed = admin.call(&router, Method::POST, "/api/v1/api-keys", Some(json!({"id":failed_id,"operationId":Uuid::new_v4(),"metadata":scoped}))).await;
        pg("GRANT INSERT ON mdm_audit.receipts TO mdm_access")?;
        let (status, result) = failed?;
        ensure!(!status.is_success() && result.get("secret").is_none());
        ensure!(pg(&format!("SELECT count(*) FROM mdm_access.api_keys WHERE tenant_id='{}' AND id='{failed_id}'",case_tenant()))?.trim() == "0");
        // Expiry uses current persisted metadata, not a credential cache.
        pg(&format!("UPDATE mdm_access.api_keys SET metadata=jsonb_set(metadata,'{{expiresAt}}',to_jsonb(floor(extract(epoch FROM clock_timestamp()))::bigint-1)) WHERE tenant_id='{}' AND id='{id}'",case_tenant()))?;
        ensure!(call(&router, Method::GET, &inventory, &[("x-api-key",&secret)], None).await?.0 == StatusCode::UNAUTHORIZED);
        pg(&format!("UPDATE mdm_access.api_keys SET metadata=jsonb_set(metadata,'{{expiresAt}}','null') WHERE tenant_id='{}' AND id='{id}'",case_tenant()))?;
        let login_path=format!("/api/v1/identity/tenants/{}/bearer/login",case_tenant());
        let (status, token)=call(&router,Method::POST,&login_path,&[],Some(json!({"login":case::login("admin"),"password":PASSWORD}))).await?;
        ensure!(status==StatusCode::OK);
        let bearer=format!("Bearer {}",token["accessToken"].as_str().ok_or_else(||anyhow::anyhow!("missing bearer"))?);
        // Creator is audit metadata only; disabling it rejects its token but leaves tenant Key usable.
        let account_path=format!("/api/v1/identity/tenants/{}/accounts/{}/enabled",case_tenant(),case_admin());
        ensure!(admin.call(&router,Method::POST,&account_path,Some(json!({"enabled":false}))).await?.0==StatusCode::OK);
        ensure!(call(&router,Method::GET,&inventory,&[("authorization",&bearer)],None).await?.0==StatusCode::UNAUTHORIZED);
        ensure!(call(&router,Method::GET,&inventory,&[("x-api-key",&secret)],None).await?.0==StatusCode::OK);
        let receipts=pg(&format!("SELECT result FROM mdm_access.authorization_operations WHERE tenant_id='{}'",case_tenant()))?;
        ensure!(!receipts.contains(&secret));
        policy(&mut manager,&router,1,json!([])).await?;
        Ok(())
    }).await
}

#[tokio::test]
#[ignore = "MODULE=authorization.programmatic: programmatic business writes and managed enrollment"]
async fn business_writes_bind_key_actor_and_managed_enrollment() -> Result<()> {
    let Fixture {
        resources,
        router,
        mut admin,
        ..
    } = fixture().await?;
    resources.finish(async {
        let mut manager = manager(&router).await?;
        policy(&mut manager, &router, 0, json!(["127.0.0.1"])).await?;
        let id = Uuid::new_v4();
        let metadata = json!({"name":"automation-writer","enabled":true,"expiresAt":null,"grants":[
            {"operation":"registration_configuration_read","scope":{"kind":"tenant"}},
            {"operation":"registration_configuration_write","scope":{"kind":"tenant"}},
            {"operation":"audit_read","scope":{"kind":"tenant"}},
            {"operation":"resource_write","scope":{"kind":"tenant"}},
            {"operation":"resource_read","scope":{"kind":"tenant"}},
            {"operation":"enrollment","scope":{"kind":"all_devices"}},
            {"operation":"inventory_read","scope":{"kind":"all_devices"}}
        ]});
        let (status, created) = admin.call(&router, Method::POST, "/api/v1/api-keys", Some(json!({"id":id,"operationId":Uuid::new_v4(),"metadata":metadata}))).await?;
        ensure!(status == StatusCode::OK);
        let secret = created["secret"].as_str().ok_or_else(|| anyhow::anyhow!("missing key"))?;
        for path in ["/api/v1/registration-quotas/defaults","/api/v1/audit-events","/api/v1/apple/organizations"] {
            ensure!(call(&router,Method::GET,path,&[("x-api-key",secret)],None).await?.0==StatusCode::OK,"business read: {path}");
        }
        let organization=Uuid::new_v4();
        let ade_path=format!("/api/v1/apple/organizations/{organization}/ade");
        let ade_operation=Uuid::new_v4().to_string();
        let configured=call(&router,Method::PUT,&format!("{ade_path}/configuration"),&[("x-api-key",secret),("idempotency-key",&ade_operation)],Some(json!({"expectedRevision":0,"enabled":false,"serverUuid":organization,"orgId":"programmatic-test","rotateKey":false}))).await?;
        ensure!(configured.0==StatusCode::OK,"ADE configuration: {}",configured.0);
        ensure!(call(&router,Method::GET,&ade_path,&[("x-api-key",secret)],None).await?.0==StatusCode::OK);
        let usage_path=format!("/api/v1/registration-quotas/users/{INSTANCE}/{}/usage",case_admin());
        ensure!(call(&router,Method::GET,&usage_path,&[("x-api-key",secret)],None).await?.0==StatusCode::OK);
        let resource = Uuid::new_v4();
        let resource_path = format!("/api/v1/resources/{resource}");
        let operation = Uuid::new_v4();
        let body = json!({"operationId":operation,"expectedRevision":0,"input":{"action":"create","kind":"script"}});
        let written = call(&router, Method::POST, &resource_path, &[("x-api-key",secret)], Some(body.clone())).await?;
        ensure!(written.0 == StatusCode::OK, "resource write: {}", written.0);
        ensure!(call(&router, Method::POST, &resource_path, &[("x-api-key",secret)], Some(body)).await? == written);
        ensure!(call(&router, Method::GET, &resource_path, &[("x-api-key",secret)], None).await?.0 == StatusCode::OK);
        let actor = format!("api-key:{id}");
        ensure!(audit_count(|r| r.actor()==Some(actor.as_str()) && r.decoded.event().facts().actor().kind().as_str()=="api_key" && r.operation()==Some(operation.to_string().as_str()) && r.result()=="success")? > 0);
        let enrollment_op = Uuid::new_v4().to_string();
        let enrollment = call(&router, Method::POST, "/api/v1/enrollments", &[("x-api-key",secret),("idempotency-key",&enrollment_op)], Some(json!({"deviceId":case::name("device-1"),"password":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","source":"mdm.windows","windowsProfile":"Device"}))).await?;
        ensure!(enrollment.0 == StatusCode::OK, "managed enrollment: {}", enrollment.0);
        let enrollment_id=enrollment.1["enrollmentId"].as_str().ok_or_else(|| anyhow::anyhow!("missing enrollment"))?;
        ensure!(call(&router,Method::GET,&format!("/api/v1/enrollments/{enrollment_id}"),&[("x-api-key",secret)],None).await?.0==StatusCode::OK);
        let key_path=format!("/api/v1/api-keys/{id}");
        let mut reduced=metadata.clone(); reduced["grants"]=json!([{"operation":"inventory_read","scope":{"kind":"all_devices"}}]);
        ensure!(admin.call(&router,Method::PUT,&key_path,Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"metadata":reduced}))).await?.0==StatusCode::OK);
        let resume_op=Uuid::new_v4().to_string();
        ensure!(call(&router,Method::POST,&format!("/api/v1/enrollments/{enrollment_id}/resume"),&[("x-api-key",secret),("idempotency-key",&resume_op)],Some(json!({"password":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA"}))).await?.0==StatusCode::FORBIDDEN);
        ensure!(call(&router,Method::GET,&resource_path,&[("x-api-key",secret)],None).await?.0==StatusCode::FORBIDDEN);
        policy(&mut manager,&router,1,json!([])).await?;
        Ok(())
    }).await
}

#[tokio::test]
#[ignore = "MODULE=authorization.programmatic: original API key rechecked after streamed body"]
async fn streamed_content_rejects_rotated_key_before_binding() -> Result<()> {
    use futures::SinkExt;
    use sha2::{Digest, Sha256};
    let Fixture {
        resources,
        router,
        mut admin,
        ..
    } = fixture().await?;
    resources.finish(async {
        let mut manager = manager(&router).await?;
        policy(&mut manager,&router,0,json!(["127.0.0.1"])).await?;
        let id=Uuid::new_v4();
        let metadata=json!({"name":"stream-writer","enabled":true,"expiresAt":null,"grants":[{"operation":"resource_write","scope":{"kind":"tenant"}},{"operation":"resource_read","scope":{"kind":"tenant"}}]});
        let (status,issued)=admin.call(&router,Method::POST,"/api/v1/api-keys",Some(json!({"id":id,"operationId":Uuid::new_v4(),"metadata":metadata}))).await?;
        ensure!(status==StatusCode::OK);
        let secret=issued["secret"].as_str().ok_or_else(||anyhow::anyhow!("missing key"))?;
        let resource=Uuid::new_v4();
        let path=format!("/api/v1/resources/{resource}");
        let bytes=b"#!/bin/sh\nprintf '{}'\n";
        let digest:[u8;32]=Sha256::digest(bytes).into();
        let script=json!({"profile":"posix_sh","runAs":"system","encoding":"utf8","parameters":{"type":"object","properties":{},"required":[],"additionalProperties":false},"bindings":{},"output":{"type":"object","properties":{},"required":[],"additionalProperties":false},"purpose":{"kind":"action"},"timeoutSeconds":60,"outputBytes":4096,"maxRows":1});
        for (revision,input) in [(0,json!({"action":"create","kind":"script"})),(1,json!({"action":"version","version":"v1","kind":"script","variants":[{"platform":"macos","architecture":"aarch64","key":"default","declaration":{"kind":"script","artifact":{"reference":"script","length":bytes.len(),"sha256":digest},"definition":script}}]}))] {
            let result=call(&router,Method::POST,&path,&[("x-api-key",secret)],Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":revision,"input":input}))).await?;
            ensure!(result.0==StatusCode::OK,"script prepare: {}",result.0);
        }
        let operation=Uuid::new_v4();
        let upload_path=|op|format!("{path}/content?version=v1&variant=default&platform=macos&architecture=aarch64&operation={op}");
        let (mut sender,stream)=futures::channel::mpsc::channel::<Result<Vec<u8>,std::io::Error>>(1);
        let request=Request::builder().method(Method::POST).uri(upload_path(operation)).header("host","mdm.example.test").header("x-api-key",secret).header("content-type","application/octet-stream").body(Body::from_stream(stream))?;
        let running=tokio::spawn(router.clone().oneshot(request));
        sender.send(Ok(bytes[..1].to_vec())).await?;
        let observer=sqlx::postgres::PgPoolOptions::new().max_connections(1).connect_with(crate::device::test_support::options("postgres")?).await?;
        let claimed=tokio::time::timeout(Duration::from_secs(5),async {
            loop {
                let count:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_content.uploads WHERE tenant_id=$1::uuid AND document->'value'->'upload'->>'id'=$2 AND epoch IS NOT NULL").bind(case_tenant()).bind(operation.to_string()).fetch_one(&observer).await?;
                if count==1 { return Ok::<_,anyhow::Error>(()); }
                tokio::task::yield_now().await;
            }
        }).await;
        observer.close().await;
        let rotated:Result<String>=async {
            claimed??;
            let (status,rotation)=admin.call(&router,Method::POST,&format!("/api/v1/api-keys/{id}/rotate"),Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":1}))).await?;
            ensure!(status==StatusCode::OK);
            let rotated=rotation["secret"].as_str().ok_or_else(||anyhow::anyhow!("missing rotated key"))?.to_owned();
            sender.send(Ok(bytes[1..].to_vec())).await?;
            Ok(rotated)
        }.await;
        drop(sender);
        let response=running.await??;
        let rotated=rotated?;
        ensure!(response.status()==StatusCode::UNAUTHORIZED,"rotated upload: {}",response.status());
        ensure!(pg(&format!("SELECT count(*) FROM mdm_content.bindings WHERE tenant_id='{}' AND operation='{operation}'",case_tenant()))?.trim()=="0");
        ensure!(audit_count(|r|r.operation()==Some(operation.to_string().as_str()) && r.status()==201 && r.result()=="success")?==0);
        let replacement=Uuid::new_v4();
        let response=router.clone().oneshot(Request::builder().method(Method::POST).uri(upload_path(replacement)).header("host","mdm.example.test").header("x-api-key",rotated).header("content-type","application/octet-stream").body(Body::from(bytes.to_vec()))?).await?;
        ensure!(response.status()==StatusCode::CREATED,"new key upload: {}",response.status());
        ensure!(pg(&format!("SELECT count(*) FROM mdm_content.bindings WHERE tenant_id='{}' AND operation='{replacement}'",case_tenant()))?.trim()=="1");
        policy(&mut manager,&router,1,json!([])).await?;
        Ok(())
    }).await
}
