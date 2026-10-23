//! Product PSSO HTTP/PG tests: protocol evidence, deployment order and lifecycle fencing.
use super::*;
use anyhow::Context;
use http_body_util::BodyExt;
use openssl::{
    ec::{EcGroup, EcKey},
    nid::Nid,
    pkey::{PKey, Private},
};
use rss_mdm_apple_channel::platform_sso::crypto;
use rss_mdm_apple_mdm::platform_sso::{Configuration, PublicKey};
use serde_json::Value;
use sqlx::Connection;

struct Key {
    private: PKey<Private>,
    signer: crypto::Signer,
    public: PublicKey,
}
impl Key {
    fn new() -> Result<Self> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let private = PKey::from_ec_key(EcKey::generate(&group)?)?;
        Ok(Self {
            signer: crypto::Signer::from_pem(&private.private_key_to_pem_pkcs8()?)?,
            public: crypto::coordinates(&private)?,
            private,
        })
    }
}
pub(super) fn configuration(root: &std::path::Path) -> Result<config::PlatformSso> {
    use std::os::unix::fs::PermissionsExt;
    let key = Key::new()?;
    let path = root.join(format!("psso-{}.pem", Uuid::new_v4()));
    std::fs::write(&path, key.private.private_key_to_pem_pkcs8()?)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(config::PlatformSso {
        configuration: Configuration {
            team_id: "ABCDEFGHIJ".into(),
            extension_id: "com.rss.psso.extension".into(),
            application_id: "com.rss.psso".into(),
            application_version: "1.0".into(),
            client_id: Uuid::new_v4(),
        },
        active_key: "active".into(),
        signing_keys: [("active".into(), path)].into(),
    })
}
async fn call(f: &Fixture, path: &str, body: Value) -> Result<(StatusCode, Value)> {
    let request = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header("host", "mdm.example.test")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body)?))?;
    let response = f.router.clone().oneshot(request).await?;
    let status = response.status();
    Ok((
        status,
        serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?,
    ))
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=apple.platform_sso: real nonce storage, tenant boundary and authenticated registration HTTP"]
async fn nonce_is_bounded_and_never_stored_in_plaintext() -> Result<()> {
    let f = Fixture::with_options(None, None, false, None, false, true).await?;
    let result=async {
        let base=format!("/api/v1/apple/platform-sso/{}",case_tenant());
        let (status,value)=call(&f,&format!("{base}/nonce"),json!({})).await?;
        ensure!(status==StatusCode::OK,"nonce {status}: {value}");
        ensure!(crypto::decode(value["nonce"].as_str().context("nonce")?)?.len()==32);
        let mut c=sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?).await?;
        let (digest,context,seconds):(Vec<u8>,Value,i64)=sqlx::query_as("SELECT nonce_digest,context,expires_at-floor(extract(epoch FROM clock_timestamp()))::bigint FROM mdm_apple.psso_challenges WHERE tenant_id=$1::uuid AND id=$2")
            .bind(case_tenant()).bind(serde_json::from_value::<Uuid>(value["id"].clone())?).fetch_one(&mut c).await?;
        ensure!(digest==crypto::digest(value["nonce"].as_str().unwrap())&&context==json!({})&&(1..=120).contains(&seconds));
        ensure!(call(&f,&format!("/api/v1/apple/platform-sso/{}/nonce",Uuid::new_v4()),json!({})).await?.0==StatusCode::UNAUTHORIZED);
        let invalid=Request::builder().method(Method::POST).uri(format!("{base}/token")).header("host","mdm.example.test").header("content-type","application/x-www-form-urlencoded").body(Body::from("platform_sso_version=1.0&grant_type=refresh_token&assertion=opaque"))?;
        ensure!(f.router.clone().oneshot(invalid).await?.status()==StatusCode::BAD_REQUEST);
        ensure!(call(&f,&format!("{base}/browser/begin"),json!({"bindingId":Uuid::new_v4()})).await?.0==StatusCode::UNAUTHORIZED);
        let protected=Request::builder().method(Method::POST).uri("/api/v1/agent/runtime/platform-sso/bootstrap").header("host","mdm.example.test:9445").header("content-type","application/json").body(Body::from(serde_json::to_vec(&json!({"operationId":Uuid::new_v4(),"kind":"device"}))?))?;
        ensure!(f.router.clone().oneshot(protected).await?.status()==StatusCode::UNAUTHORIZED);
        // Capacity is a tenant budget, not an unbounded public nonce allocator.
        sqlx::query("INSERT INTO mdm_apple.psso_challenges(tenant_id,id,purpose,nonce_digest,expires_at,context) SELECT $1::uuid,gen_random_uuid(),'login',decode(repeat('ab',32),'hex'),floor(extract(epoch FROM clock_timestamp()))::bigint+120,'{}'::jsonb FROM generate_series(1,4096)").bind(case_tenant()).execute(&mut c).await?;
        ensure!(call(&f,&format!("{base}/nonce"),json!({})).await?.0==StatusCode::SERVICE_UNAVAILABLE);
        sqlx::query("DELETE FROM mdm_apple.psso_challenges WHERE tenant_id=$1::uuid").bind(case_tenant()).execute(&mut c).await?;
        c.close().await?;Ok(())
    }.await;
    f.close().await?;
    result
}

async fn grants(_f: &Fixture) -> Result<()> {
    use crate::authorization::{Grant, Permission, Scope};
    let mut grants = crate::test_support::identity::device_grants(
        None,
        &[
            "enrollment",
            "credentials",
            "inventory_read",
            "inventory_collect",
            "configuration_write",
            "security_operate",
            "operation_read",
            "operation_cancel",
            "account_write",
            "device_association_write",
        ],
    )?;
    grants.extend(
        [
            Permission::InventorySensitiveRead,
            Permission::ResourceRead,
            Permission::ResourceWrite,
            Permission::PolicyRead,
            Permission::PolicyWrite,
            Permission::ScopeRead,
            Permission::ScopeWrite,
            Permission::RegistrationConfigurationRead,
        ]
        .into_iter()
        .map(|operation| Grant {
            operation,
            scope: Scope::Tenant,
        }),
    );
    crate::test_support::identity::set_grants(
        case_tenant(),
        crate::test_support::case::admin(),
        grants,
    )
    .await
}
fn agent_label() -> &'static str {
    crate::test_support::case::name("psso-agent")
}
async fn agent(f: &Fixture, path: &str, input: Value) -> Result<(StatusCode, Value)> {
    crate::test_support::agent::agent_call(
        &f.router,
        Method::POST,
        &format!("/api/v1/agent/runtime/platform-sso/{path}"),
        Some(agent_label()),
        Some(input),
    )
    .await
}
async fn pair(
    f: &Fixture,
    agent_device: &str,
) -> Result<rss_mdm_registration_service::device::endpoints::PrimaryRegistration> {
    use rss_mdm_inventory::Channel;
    use rss_mdm_inventory_service::objects::{ObjectReader, SnapshotProgress};
    use rss_mdm_registration_service::device::endpoints::current_in;
    let mut c =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    let mdm = current_in(&mut c, case_tenant(), case_device(), Channel::Mdm)
        .await?
        .context("MDM member")?;
    let other = current_in(&mut c, case_tenant(), agent_device, Channel::Agent)
        .await?
        .context("Agent member")?;
    let proof = crate::device::test_support::admin(case_tenant(), "admin-a").await?;
    f.app
        .associations
        .confirm(
            &proof,
            &rss_mdm_device_service::Confirm {
                operation_id: Uuid::new_v4(),
                association_id: None,
                expected_version: 0,
                mdm: mdm.clone(),
                agent: other,
                evidence: "operator verified the same enrolled Mac".into(),
            },
            &rss_mdm_audit_integration::RequestAudit::new(
                case_tenant().into(),
                "device_association_confirm",
            ),
        )
        .await?;
    let objects = rss_mdm_device_service::planning::PlanningObjects::new(f.app.audit_store.clone());
    let mut tx = c.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(case_tenant())
        .execute(&mut *tx)
        .await?;
    let snapshot = objects.freeze(&mut tx, f.app.identity.tenant).await?;
    let mut ready = false;
    for _ in 0..16 {
        if matches!(
            objects
                .advance(&mut tx, f.app.identity.tenant, &snapshot)
                .await?,
            SnapshotProgress::Ready
        ) {
            ready = true;
            break;
        }
    }
    ensure!(ready, "small paired fixture snapshot");
    tx.commit().await?;
    c.close().await?;
    Ok(mdm)
}
async fn installed_application(
    registration: Uuid,
    dataset: &str,
    version: Option<&str>,
) -> Result<()> {
    use rss_mdm_inventory::{FieldKey, Scalar};
    use sha2::{Digest, Sha256};
    let key = FieldKey::parse("device.software.apple.installed_applications")?;
    let definition = crate::test_support::inventory::definition(dataset, "mdm.apple", &[key]);
    crate::test_support::inventory::register_definition(&definition)?;
    let mut c =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    let mut tx = c.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(case_tenant())
        .execute(&mut *tx)
        .await?;
    let epoch:Uuid=sqlx::query_scalar("SELECT epoch FROM mdm_access.report_sources WHERE tenant_id=$1::uuid AND registration=$2 AND source='mdm.apple' AND enabled").bind(case_tenant()).bind(registration).fetch_one(&mut *tx).await?;
    let scope = rss_mdm_registration_service::device::scope_dataset(
        rss_request_context::TenantId::parse(case_tenant())?,
        registration,
        "mdm.apple",
        epoch,
        dataset,
    )?
    .encode()?;
    let mut object =
        std::collections::BTreeMap::from([("id".into(), Scalar::String("com.rss.psso".into()))]);
    if let Some(v) = version {
        object.insert("version".into(), Scalar::String(v.into()));
    }
    let value = definition
        .field(key)?
        .canonical_value(Scalar::Array(vec![Scalar::Object(object)]))?;
    let Scalar::Array(items) = &value else {
        unreachable!()
    };
    let bytes = serde_json::to_vec(&value)?;
    let field = serde_json::to_vec(definition.field(key)?)?;
    let fd = format!("{:x}", Sha256::digest(&field));
    let digest = format!("{:x}", Sha256::digest(&bytes));
    let value_version = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&(1, &fd, &digest))?)
    );
    sqlx::query("INSERT INTO mdm.array_versions(tenant_id,version,format,field,definition_digest,item_count,canonical_bytes,digest,definition) VALUES($1::uuid,$2,1,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING")
        .bind(case_tenant()).bind(&value_version).bind(key.as_str()).bind(fd).bind(items.len() as i64).bind(bytes.len() as i64).bind(digest).bind(field).execute(&mut *tx).await?;
    let payload = serde_json::to_vec(&items[0])?;
    sqlx::query("INSERT INTO mdm.array_items(tenant_id,version,ordinal,payload,digest,prefix_bytes) VALUES($1::uuid,$2,0,$3,sha256($3),$4) ON CONFLICT DO NOTHING")
        .bind(case_tenant()).bind(&value_version).bind(&payload).bind(payload.len() as i64).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm.inventory(field_scope,tenant_id,journal,generation,scope,coverage,field,value_version,batch_id,observed_at,received_at,state,last_known_version,last_known_batch,last_known_observed,last_known_received,registration,source,epoch,collection_sequence) VALUES('{\"kind\":\"device\"}',$1::uuid,'mdm.observation.v1','inventory-projection-v1',$2,$3,$4,$5,'psso-fixture',floor(extract(epoch FROM clock_timestamp()))::bigint,floor(extract(epoch FROM clock_timestamp()))::bigint,'known',$5,'psso-fixture',floor(extract(epoch FROM clock_timestamp()))::bigint,floor(extract(epoch FROM clock_timestamp()))::bigint,$6,'mdm.apple',$7,1)")
        .bind(case_tenant()).bind(scope).bind(serde_json::to_string(&definition.coverage()?)?).bind(key.as_str()).bind(value_version).bind(registration.to_string()).bind(epoch.to_string()).execute(&mut *tx).await?;
    tx.commit().await?;
    c.close().await?;
    Ok(())
}
async fn register_key(
    f: &Fixture,
    kind: &str,
    binding: Option<Uuid>,
    registration: Uuid,
    signing: &Key,
    encryption: &Key,
) -> Result<Value> {
    let (status,challenge)=agent(f,"bootstrap",json!({"operationId":Uuid::new_v4(),"kind":kind,"bindingId":binding,"bindingGeneration":binding.map(|_|1)})).await?;
    ensure!(
        status == StatusCode::OK,
        "bootstrap {kind}: {status} {challenge}"
    );
    let now = f.app.clock.unix_seconds()?;
    let proof=signing.signer.sign("rss-mdm-platform-sso-registration+jwt",&json!({"iss":registration,"aud":format!("{}/register",challenge["endpoints"]["base"].as_str().unwrap()),"challengeId":challenge["id"],"sourceId":challenge["sourceId"],"sourceVersion":challenge["sourceVersion"],"nonce":challenge["nonce"],"encryptionKeyId":crypto::kid(&encryption.public)?,"iat":now,"exp":now+120}))?;
    let input = json!({"operationId":Uuid::new_v4(),"challengeId":challenge["id"],"signingKey":signing.public,"encryptionKey":encryption.public,"proof":proof});
    let (status, receipt) = agent(f, "register", input.clone()).await?;
    ensure!(
        status == StatusCode::OK,
        "register {kind}: {status} {receipt}"
    );
    ensure!(
        agent(f, "register", input).await?.0 == StatusCode::UNAUTHORIZED,
        "one-use registration proof"
    );
    Ok(receipt)
}
fn apv(key: &PublicKey, nonce: &str) -> Result<String> {
    let mut point = vec![4];
    point.extend(crypto::decode(&key.x)?);
    point.extend(crypto::decode(&key.y)?);
    let mut bytes = Vec::new();
    for part in [b"Apple".as_slice(), point.as_slice(), nonce.as_bytes()] {
        bytes.extend((part.len() as u32).to_be_bytes());
        bytes.extend(part);
    }
    Ok(crypto::encode(&bytes))
}
fn decrypt(key: &Key, token: &str) -> Result<Value> {
    use sha2::{Digest, Sha256};
    let parts = token.split('.').collect::<Vec<_>>();
    ensure!(parts.len() == 5 && parts[1].is_empty());
    let header: Value = serde_json::from_slice(&crypto::decode(parts[0])?)?;
    ensure!(header["alg"] == "ECDH-ES" && header["enc"] == "A256GCM");
    let peer = crypto::public(&serde_json::from_value(header["epk"].clone())?)?;
    let mut deriver = openssl::derive::Deriver::new(&key.private)?;
    deriver.set_peer(&peer)?;
    let mut input = 1u32.to_be_bytes().to_vec();
    input.extend(deriver.derive_to_vec()?);
    for part in [
        b"A256GCM".to_vec(),
        crypto::decode(header["apu"].as_str().context("apu")?)?,
        crypto::decode(header["apv"].as_str().context("apv")?)?,
    ] {
        input.extend((part.len() as u32).to_be_bytes());
        input.extend(part);
    }
    input.extend(256u32.to_be_bytes());
    let cek = Sha256::digest(input);
    let plain = openssl::symm::decrypt_aead(
        openssl::symm::Cipher::aes_256_gcm(),
        &cek,
        Some(&crypto::decode(parts[2])?),
        parts[0].as_bytes(),
        &crypto::decode(parts[3])?,
        &crypto::decode(parts[4])?,
    )?;
    Ok(serde_json::from_slice(&plain)?)
}
async fn login_request(
    f: &Fixture,
    device: &Key,
    user: &Key,
    encryption: &Key,
    id: &Value,
) -> Result<String> {
    use rss_mdm_apple_mdm::platform_sso::{ASSERTION_TYPE, LOGIN_TYPE, SCOPE};
    let rt = f.ade.platform_sso.as_ref().context("PSSO")?;
    let (status, nonce) = call(
        f,
        &format!("/api/v1/apple/platform-sso/{}/nonce", case_tenant()),
        json!({}),
    )
    .await?;
    ensure!(status == StatusCode::OK);
    let now = f.app.clock.unix_seconds()?;
    let client_nonce = Uuid::new_v4().to_string();
    let inner=user.signer.sign(ASSERTION_TYPE,&json!({"iss":id,"sub":id,"aud":rt.endpoints.issuer,"iat":now,"exp":now+120,"scope":SCOPE,"nonce":client_nonce,"request_nonce":nonce["nonce"]}))?;
    device.signer.sign(LOGIN_TYPE,&json!({"iss":rt.configuration.client_id,"client_id":rt.configuration.client_id,"aud":rt.endpoints.token,"sub":id,"username":id,"grant_type":"urn:ietf:params:oauth:grant-type:jwt-bearer","iat":now,"exp":now+120,"scope":SCOPE,"nonce":client_nonce,"request_nonce":nonce["nonce"],"assertion":inner,"jwe_crypto":{"alg":"ECDH-ES","enc":"A256GCM","apv":apv(&encryption.public,&client_nonce)?}})).map_err(Into::into)
}
async fn token(f: &Fixture, assertion: &str) -> Result<(StatusCode, String)> {
    let mut form = url::form_urlencoded::Serializer::new(String::new());
    form.append_pair("platform_sso_version", "1.0")
        .append_pair("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
        .append_pair("assertion", assertion);
    let request = Request::builder()
        .method(Method::POST)
        .uri(format!(
            "/api/v1/apple/platform-sso/{}/token",
            case_tenant()
        ))
        .header("host", "mdm.example.test")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(form.finish()))?;
    let response = f.router.clone().oneshot(request).await?;
    let status = response.status();
    if status == StatusCode::OK {
        ensure!(response.headers()["content-type"] == "application/jose");
    }
    Ok((
        status,
        String::from_utf8(response.into_body().collect().await?.to_bytes().to_vec())?,
    ))
}

async fn binding(f: &mut Fixture, device: &str) -> Result<Uuid> {
    let scope = Uuid::new_v4();
    f.policy_post(&format!("/api/v1/scopes/{scope}"),0,json!({"action":"put","definition":{"targets":[{"kind":"device","id":device}],"limitations":null,"exclusions":[]}})).await?;
    let policy = Uuid::new_v4();
    f.policy_post(&format!("/api/v1/policies/{policy}"),0,json!({"action":"put","enabled":true,"definition":{"scope":scope,"action":{"kind":"device_access","selfEnrollment":true,"role":null}}})).await?;
    // Policy publication starts scope reconciliation; first association requires its current result.
    let mut c =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(case_tenant())
        .execute(&mut c)
        .await?;
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let state: String =
                sqlx::query_scalar("SELECT mdm_planning.scope_admission($1,$2)->>'state'")
                    .bind(scope)
                    .bind(device)
                    .fetch_one(&mut c)
                    .await?;
            if state == "fresh" {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    c.close().await?;
    let user_call = |path: &str, input: Value| {
        let request = Request::builder()
            .method(Method::POST)
            .uri(format!("/api/v1/agent/runtime/device-access/{path}"))
            .header("host", "mdm.example.test:9445")
            .header("content-type", "application/json")
            .header(
                "x-rss-user-session",
                &f.browser.cookies["__Host-identity-session"],
            )
            .extension(crate::test_support::agent::evidence(agent_label()).unwrap())
            .body(Body::from(serde_json::to_vec(&input).unwrap()))
            .unwrap();
        f.router.clone().oneshot(request)
    };
    let response = user_call(
        "begin",
        json!({"operationId":Uuid::new_v4(),"policy":policy}),
    )
    .await?;
    let status = response.status();
    let challenge: Value =
        serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;
    ensure!(status == StatusCode::OK, "P1 begin {status}: {challenge}");
    let response=user_call("confirm",json!({"operationId":Uuid::new_v4(),"challenge":challenge["id"],"nonce":challenge["nonce"],"localSession":challenge["localSession"]})).await?;
    let status = response.status();
    let receipt: Value = serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;
    ensure!(
        status == StatusCode::OK && receipt["state"] == "pending",
        "P1 confirm {status}: {receipt}"
    );
    Ok(serde_json::from_value(receipt["id"].clone())?)
}
async fn applied_binding(id: Uuid) -> Result<()> {
    use rss_mdm_agent_wire::runtime::{
        AccessEffect, AccessMacFacts, AccessObservation, AccessRole,
    };
    use rss_mdm_registration_service::device_access::{self as access, storage};
    let mut c =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    let mut tx = c.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(case_tenant())
        .execute(&mut *tx)
        .await?;
    let mut b = storage::locked_in(&mut tx, Uuid::parse_str(case_tenant())?, id).await?;
    // The task/result protocol has its own P1 proof. This test consumes its legal Applied fact.
    b.state = access::State::Active;
    b.applied_revision = Some(b.revision);
    b.received_revision = Some(b.revision);
    b.effect = Some(AccessEffect::Applied {
        account: b.account.clone().context("local account")?,
        role: AccessRole::Standard,
        mac: Some(AccessMacFacts {
            secure_token: AccessObservation::Present,
            volume_owner: AccessObservation::Unknown,
            filevault_unlock: AccessObservation::Unknown,
        }),
    });
    storage::save_in(&mut tx, &b, b.revision).await?;
    tx.commit().await?;
    c.close().await?;
    Ok(())
}
async fn browser_exchange(
    f: &Fixture,
    binding: Uuid,
    user: &Key,
    registered: &Value,
    access: &str,
) -> Result<(StatusCode, axum::http::HeaderMap, Value)> {
    use rss_mdm_apple_mdm::platform_sso::BRIDGE_TYPE;
    let base = format!("/api/v1/apple/platform-sso/{}", case_tenant());
    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("{base}/browser/begin"))
        .header("host", "mdm.example.test")
        .header("origin", "https://mdm.example.test")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(
            &json!({"bindingId":binding}),
        )?))?;
    let response = f.router.clone().oneshot(request).await?;
    let status = response.status();
    let headers = response.headers().clone();
    let challenge: Value =
        serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;
    if status != StatusCode::OK {
        return Ok((status, headers, challenge));
    }
    let cookie = headers["set-cookie"]
        .to_str()?
        .split(';')
        .next()
        .context("browser cookie")?;
    let now = f.app.clock.unix_seconds()?;
    let proof=user.signer.sign(BRIDGE_TYPE,&json!({"iss":registered["sourceId"],"sourceVersion":registered["sourceVersion"],"aud":challenge["audience"],"nonce":challenge["nonce"],"accessToken":access,"iat":now,"exp":now+120}))?;
    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("{base}/browser/complete"))
        .header("host", "mdm.example.test")
        .header("origin", "https://mdm.example.test")
        .header("cookie", cookie)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(
            &json!({"challengeId":challenge["id"],"nonce":challenge["nonce"],"proof":proof}),
        )?))?;
    let response = f.router.clone().oneshot(request).await?;
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.into_body().collect().await?.to_bytes();
    Ok((
        status,
        headers,
        if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes)?
        },
    ))
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "MODULE=apple.platform_sso: native double signature/JWE, pending registration, P2 browser session and key revocation"]
async fn native_registration_login_browser_bridge_and_revocation() -> Result<()> {
    let mut f = Fixture::with_options(None, None, false, None, false, true).await?;
    let worker = f.policy_worker().await?;
    let result=async {
        let (peer,_device)=f.ready_local_peer().await?;grants(&f).await?;
        let account=Uuid::new_v4();
        let mut context=crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::MacOs);
        context["interactiveUser"]=json!({"identity":"501","generatedUid":account,"sessionId":Uuid::new_v4(),"administrator":false});
        let agent_receipt=crate::test_support::agent::seed_service(f.app.agent_enrollment.as_ref().context("Agent service")?,agent_label(),crate::test_support::case::name("psso-agent-device"),json!({"executionContext":context,"platform":"macos","architecture":"aarch64","capabilities":["inventory.collect.v1","device_access.v1"]})).await?;
        let agent_registration:Uuid=serde_json::from_value(agent_receipt["registrationId"].clone())?;
        let agent_device=agent_receipt["deviceId"].as_str().context("Agent device")?;
        let mdm=pair(&f,agent_device).await?;
        ensure!(agent(&f,"bootstrap",json!({"operationId":Uuid::new_v4(),"kind":"device"})).await?.0==StatusCode::CONFLICT,"application/profile observations are required");
        let profile=f.ade.platform_sso.as_ref().unwrap().profile()?;
        let (_,operation)=f.configuration_policy(json!({"platform":"macos","request":{"kind":"install_profile","profile":profile}}),None,"retain").await?;
        let (security,_) = peer.next("SecurityInfo").await?;
        let waiting = peer.manage("Acknowledged",Some(security),Some(("SecurityInfo",protocol::dictionary([("ManagementStatus",protocol::dictionary([("EnrolledViaDEP",false.into()),("UserApprovedEnrollment",true.into()),("IsUserEnrollment",false.into())]).into())]).into()))).await?;
        ensure!(waiting.is_empty(),"RSS profile waits for application observation: {}",String::from_utf8_lossy(&waiting));
        installed_application(mdm.registration_id,"psso-applications",Some("1.0")).await?;
        installed_application(mdm.registration_id,"psso-missing-version",None).await?;
        ensure!(agent(&f,"bootstrap",json!({"operationId":Uuid::new_v4(),"kind":"device"})).await?.0==StatusCode::CONFLICT,"a valid scope must not mask another scope missing version");
        {
            let mut pg=sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?).await?;
            sqlx::query("SELECT set_config('rss.tenant_id',$1,false)").bind(case_tenant()).execute(&mut pg).await?;
            let cfg=serde_json::to_value(f.ade.platform_sso.as_ref().unwrap().qualification_configuration()?)?;
            let valid:bool=sqlx::query_scalar("SELECT mdm_apple.application_valid_until($1,$2,floor(extract(epoch FROM clock_timestamp()))::bigint) IS NOT NULL").bind(mdm.registration_id).bind(&cfg).fetch_one(&mut pg).await?;
            ensure!(!valid,"missing version in another scope must reject application qualification");
            sqlx::query("DELETE FROM mdm.inventory i USING mdm.collection_definitions d WHERE (i.tenant_id,i.coverage,i.source)=(d.tenant_id,d.coverage,d.source) AND i.tenant_id=$1::uuid AND d.dataset='psso-missing-version'").bind(case_tenant()).execute(&mut pg).await?;
            let valid:bool=sqlx::query_scalar("SELECT mdm_apple.application_valid_until($1,$2,floor(extract(epoch FROM clock_timestamp()))::bigint) IS NOT NULL").bind(mdm.registration_id).bind(&cfg).fetch_one(&mut pg).await?;
            ensure!(valid,"valid scope alone qualifies");
        }
        let (execute,_)=peer.next("InstallProfile").await?;
        let bytes=peer.manage("Acknowledged",Some(execute),None).await?;
        let (observe,_)=lifecycle::command(&bytes,"ProfileList")?;
        ensure!(agent(&f,"bootstrap",json!({"operationId":Uuid::new_v4(),"kind":"device"})).await?.0==StatusCode::CONFLICT,"ACK is not observed readiness");
        let payload=&profile.payloads[0];
        let observed=plist::Value::Array(vec![protocol::dictionary([("PayloadIdentifier",profile.identifier.clone().into()),("PayloadUUID",profile.uuid.to_string().into()),("PayloadVersion",1.into()),("PayloadContent",plist::Value::Array(vec![protocol::dictionary([("PayloadIdentifier",payload.identifier.clone().into()),("PayloadUUID",payload.uuid.to_string().into()),("PayloadVersion",1.into()),("PayloadType","com.apple.extensiblesso".into())]).into()]))]).into()]);
        peer.manage("Acknowledged",Some(observe),Some(("ProfileList",observed))).await?;
        ensure!(f.operation(operation).await?["commandStatus"]=="applied");
        let device=Key::new()?;let device_encryption=Key::new()?;let user=Key::new()?;let encryption=Key::new()?;
        let mut c=sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?).await?;
        sqlx::query("INSERT INTO mdm_apple.psso_challenges(tenant_id,id,purpose,nonce_digest,expires_at,context) SELECT $1::uuid,gen_random_uuid(),'login',decode(repeat('ab',32),'hex'),floor(extract(epoch FROM clock_timestamp()))::bigint+120,'{}'::jsonb FROM generate_series(1,4096)").bind(case_tenant()).execute(&mut c).await?;
        ensure!(call(&f,&format!("/api/v1/apple/platform-sso/{}/nonce",case_tenant()),json!({})).await?.0==StatusCode::SERVICE_UNAVAILABLE);
        let registered_device=register_key(&f,"device",None,agent_registration,&device,&device_encryption).await?;
        let binding=binding(&mut f,agent_device).await?;
        let registered=register_key(&f,"user",Some(binding),agent_registration,&user,&encryption).await?;
        sqlx::query("DELETE FROM mdm_apple.psso_challenges WHERE tenant_id=$1::uuid AND purpose='login'").bind(case_tenant()).execute(&mut c).await?;
        c.close().await?;
        let pending=login_request(&f,&device,&user,&encryption,&registered["sourceId"]).await?;
        ensure!(token(&f,&pending).await?.0==StatusCode::BAD_REQUEST,"pending binding cannot log in");
        applied_binding(binding).await?;
        let assertion=login_request(&f,&device,&user,&encryption,&registered["sourceId"]).await?;
        let (one,two)=tokio::join!(token(&f,&assertion),token(&f,&assertion));
        let (one,two)=(one?,two?);
        let (success,replay)=if one.0==StatusCode::OK {(one,two)}else{(two,one)};
        ensure!(success.0==StatusCode::OK&&replay.0==StatusCode::BAD_REQUEST,"concurrent nonce use: {} {} / {} {}",success.0,success.1,replay.0,replay.1);
        let response=success.1;
        let tokens=decrypt(&encryption,&response)?;
        ensure!(tokens["token_type"]=="Bearer"&&tokens["expires_in"]==300&&tokens["refresh_token"].as_str().is_some_and(|s|s.len()==43));
        ensure!(decrypt(&device_encryption,&response).is_err(),"response is encrypted to user key");
        ensure!(token(&f,&assertion).await?.0==StatusCode::BAD_REQUEST,"nonce replay");
        let (status,headers,body)=browser_exchange(&f,binding,&user,&registered,tokens["access_token"].as_str().context("access token")?).await?;
        ensure!(status==StatusCode::OK,"browser exchange {status}: {body}");
        ensure!(headers.get_all("set-cookie").iter().any(|h|h.to_str().is_ok_and(|s|s.starts_with("__Host-identity-session="))),"P2 must issue ordinary Identity session");
        let secret=headers.get_all("set-cookie").iter().filter_map(|h|h.to_str().ok()).find_map(|v|v.strip_prefix("__Host-identity-session=").and_then(|v|v.split(';').next())).context("platform cookie")?;
        let session=f.app.identity.authority.inspect_session(f.app.identity.tenant,rss_identity_core::session::SessionSecret::parse(secret.into())?,crate::identity::deadline()).await?;
        let reference=serde_json::to_value(session.reference()?)?;
        {
            let mut pg=sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?).await?;
            sqlx::query("SELECT set_config('rss.tenant_id',$1,false)").bind(case_tenant()).execute(&mut pg).await?;
            sqlx::query("INSERT INTO mdm_access.current_users(tenant_id,device,revision,registration,generation,session_reference,confirmed_at) SELECT tenant_id,device,1,id,generation,$3,floor(extract(epoch FROM clock_timestamp()))::bigint FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND id=$2")
                .bind(case_tenant()).bind(agent_registration).bind(&reference).execute(&mut pg).await?;
        }
        directory_session(&mut f,agent_device,true).await?;
        // A local lookup must not evaluate an unrelated source, even if its document is corrupt.
        {
            let mut pg=sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?).await?;
            sqlx::query("BEGIN").execute(&mut pg).await?;
            sqlx::query("SELECT set_config('rss.tenant_id',$1,true)").bind(case_tenant()).execute(&mut pg).await?;
            sqlx::query("UPDATE mdm_apple.psso_sources SET document=jsonb_set(document,'{bindingGeneration}','\"invalid\"'::jsonb) WHERE tenant_id=$1::uuid AND id=$2::uuid")
                .bind(case_tenant()).bind(registered["sourceId"].as_str().context("source id")?).execute(&mut pg).await?;
            sqlx::query("SET LOCAL ROLE mdm_access").execute(&mut pg).await?;
            let cfg=serde_json::to_value(f.ade.platform_sso.as_ref().unwrap().qualification_configuration()?)?;
            let count:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_apple.platform_session_qualifications($1,$2,floor(extract(epoch FROM statement_timestamp()))::bigint)")
                .bind(Uuid::new_v4()).bind(cfg).fetch_one(&mut pg).await?;
            ensure!(count==0,"missing source has no qualification and cannot evaluate another source");
            sqlx::query("ROLLBACK").execute(&mut pg).await?;
        }
        // Changing protected evidence must invalidate the cached qualification immediately.
        {
            let mut pg=sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?).await?;
            sqlx::query("SELECT set_config('rss.tenant_id',$1,false)").bind(case_tenant()).execute(&mut pg).await?;
            let cipher:Vec<u8>=sqlx::query_scalar("SELECT response FROM mdm_apple.attempts WHERE tenant_id=$1::uuid AND id=$2").bind(case_tenant()).bind(observe).fetch_one(&mut pg).await?;
            sqlx::query("UPDATE mdm_apple.attempts SET response=set_byte(response,octet_length(response)-1,get_byte(response,octet_length(response)-1)#1) WHERE tenant_id=$1::uuid AND id=$2").bind(case_tenant()).bind(observe).execute(&mut pg).await?;
            directory_session(&mut f,agent_device,false).await?;
            sqlx::query("UPDATE mdm_apple.attempts SET response=$3 WHERE tenant_id=$1::uuid AND id=$2").bind(case_tenant()).bind(observe).bind(cipher).execute(&mut pg).await?;
        }
        directory_session(&mut f,agent_device,true).await?;
        let fresh=login_request(&f,&device,&user,&encryption,&registered["sourceId"]).await?;
        ensure!(token(&f,&fresh).await?.0==StatusCode::OK,"fresh SE renewal");
        ensure!(browser_exchange(&f,binding,&user,&registered,tokens["access_token"].as_str().unwrap()).await?.0==StatusCode::UNAUTHORIZED,"renewal replaces the native access token");
        let replacement=Key::new()?;
        let replaced=register_key(&f,"device",None,agent_registration,&replacement,&device_encryption).await?;
        ensure!(replaced["sourceId"]==registered_device["sourceId"]&&replaced["sourceVersion"]==2);
        directory_session(&mut f,agent_device,false).await?;
        let stale=login_request(&f,&replacement,&user,&encryption,&registered["sourceId"]).await?;
        ensure!(token(&f,&stale).await?.0==StatusCode::BAD_REQUEST,"parent key replacement invalidates old user registration");
        let repaired=register_key(&f,"user",Some(binding),agent_registration,&user,&encryption).await?;
        ensure!(repaired["sourceVersion"]==2);
        let valid=login_request(&f,&replacement,&user,&encryption,&repaired["sourceId"]).await?;
        let (status,response)=token(&f,&valid).await?;ensure!(status==StatusCode::OK);
        let current_tokens=decrypt(&encryption,&response)?;
        let current_access=current_tokens["access_token"].as_str().context("current native token")?;
        ensure!(browser_exchange(&f,binding,&user,&repaired,current_access).await?.0==StatusCode::OK,"token is valid immediately before logout");
        let revoked=agent(&f,&format!("sources/{}/revoke",repaired["sourceId"].as_str().unwrap()),json!({})).await?;
        ensure!(revoked.0==StatusCode::OK&&revoked.1["revoked"]==true);
        let invalid=login_request(&f,&replacement,&user,&encryption,&repaired["sourceId"]).await?;ensure!(token(&f,&invalid).await?.0==StatusCode::BAD_REQUEST);
        ensure!(browser_exchange(&f,binding,&user,&repaired,current_access).await?.0==StatusCode::UNAUTHORIZED);
        Ok(())
    }.await;
    ensure!(worker.shutdown().join().await?.is_clean());
    f.close().await?;
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "MODULE=apple.platform_sso: independent providers bypass RSS deployment prerequisites"]
async fn third_party_profile_dispatch_without_rss_runtime() -> Result<()> {
    third_party_profile_dispatch(false).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "MODULE=apple.platform_sso: independent provider with RSS runtime enabled"]
async fn third_party_profile_dispatch_with_rss_runtime() -> Result<()> {
    third_party_profile_dispatch(true).await
}
async fn third_party_profile_dispatch(enabled: bool) -> Result<()> {
    let mut f = Fixture::with_options(None, None, false, None, false, enabled).await?;
    let worker = f.policy_worker().await?;
    let result: Result<()> = async {
        let (peer, _) = f.ready_local_peer().await?;
        grants(&f).await?;
        let configuration = Configuration {
            team_id: "THIRDPARTY".into(),
            extension_id: "com.vendor.extension".into(),
            application_id: "com.vendor.application".into(),
            application_version: "1.0".into(),
            client_id: Uuid::new_v4(),
        };
        let mut profile = configuration.profile(
            "https://vendor.example",
            Uuid::parse_str(case_tenant())?,
            Uuid::new_v4(),
            Uuid::new_v4(),
        )?;
        profile.identifier = format!("com.vendor.profile.{}", profile.uuid);
        profile.payloads[0].identifier = format!("{}.extension", profile.identifier);
        f.configuration_policy(
            json!({"platform":"macos","request":{"kind":"install_profile","profile":profile}}),
            None,
            "retain",
        )
        .await?;
        peer.next("InstallProfile").await?;
        Ok(())
    }
    .await;
    ensure!(worker.shutdown().join().await?.is_clean());
    f.close().await?;
    result
}

async fn directory_session(f: &mut Fixture, device: &str, active: bool) -> Result<()> {
    let (status, detail) = f
        .browser
        .call(
            &f.router,
            Method::GET,
            &format!("/api/v1/device-views/endpoint/{device}"),
            None,
        )
        .await?;
    ensure!(
        status == StatusCode::OK,
        "directory detail {status}: {detail}"
    );
    let user = &detail["endpoints"]
        .as_array()
        .context("endpoints")?
        .iter()
        .find(|e| e["id"] == device)
        .context("agent endpoint")?["currentUser"];
    ensure!(
        user["state"] == if active { "active" } else { "invalidated" },
        "SSO currentUser {user}"
    );
    let (status, page) = f
        .browser
        .call(
            &f.router,
            Method::GET,
            &format!(
                "/api/v1/device-views?limit=1&search={}",
                crate::test_support::case::admin()
            ),
            None,
        )
        .await?;
    ensure!(
        status == StatusCode::OK,
        "directory search {status}: {page}"
    );
    let found = page["items"]
        .as_array()
        .context("items")?
        .iter()
        .flat_map(|g| g["endpoints"].as_array().into_iter().flatten())
        .any(|e| e["id"] == device && e["currentUser"]["state"] == "active");
    ensure!(found == active, "SSO search {page}");
    Ok(())
}
