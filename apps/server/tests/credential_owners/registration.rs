use super::*;
use anyhow::Context as _;
use rss_mdm_agent_wire::runtime as w;
#[tokio::test]
#[ignore = "T2: explicit DA delivery authorization and RSS material custody across distinct real endpoints"]
async fn access_binding_requires_current_device_authority() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let (device, grant) = material::seed_registration(&c).await?;
    let p = material::authenticated_agent(
        &c,
        grant,
        &device,
        vec![
            w::Capability::InventoryCollectionV1,
            w::Capability::CredentialsWindowsV1,
            w::Capability::DeviceAccessV1,
            w::Capability::DeviceAccessWhfbV1,
        ],
    )
    .await
    .context("authenticate the Agent runtime profile")?;
    let mut tx = seed(&c).await?;
    rss_mdm_registration_service::device::require_use_in(
        &mut tx,
        &p,
        rss_mdm_registration_service::device::ConsumerUse::AgentTask,
    )
    .await?;
    tx.commit().await?;
    let before: i64 =
        sqlx::query_scalar("SELECT count(*) FROM rss_audit.records WHERE tenant_id=$1::uuid")
            .bind(c.tenant.to_string())
            .fetch_one(&c.operator)
            .await?;
    let mut tx = seed(&c).await?;
    assert!(matches!(
        rss_mdm_device_access_postgres::delivery::resolve_on(&mut tx, &p).await,
        Err(rss_mdm_device_access_postgres::Error::Forbidden)
    ));
    let delivered: i64 =
        sqlx::query_scalar("SELECT count(*) FROM rss_da.agent_delivery WHERE tenant_id=$1::uuid")
            .bind(c.tenant.to_string())
            .fetch_one(&mut *tx)
            .await?;
    assert_eq!(delivered, 0);
    tx.rollback().await?;
    let after: i64 =
        sqlx::query_scalar("SELECT count(*) FROM rss_audit.records WHERE tenant_id=$1::uuid")
            .bind(c.tenant.to_string())
            .fetch_one(&c.operator)
            .await?;
    assert_eq!(before, after);
    // Keep the full proof's nested async state off the test thread's stack.
    Box::pin(delivery_lifecycle(&c, &p, &device))
        .await
        .context("prove delivery between distinct DA and Agent registrations")?;
    c.close().await;
    Ok(())
}

/// Registrar facts are legal prerequisites; independent DA TLS issuance is proved by foundation.
/// This seam authenticates two different real certificates and never substitutes the Agent peer.
#[expect(
    clippy::cognitive_complexity,
    reason = "one pair of authenticated DA and Agent identities proves explicit authorization then rejects disabled, stale and revoked delivery facts"
)]
async fn delivery_lifecycle(
    c: &Context,
    agent: &rss_mdm_registration_service::DevicePrincipal,
    _agent_device: &rss_mdm_agent_wire::DeviceId,
) -> Result<()> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use rss_mdm_device_access_postgres::delivery;
    use rss_mdm_install_support::StorageProfile;
    use rss_mdm_registration_service::device::{self, endpoints::DaRegistration};
    use sha2::{Digest, Sha256};
    let device = &rss_mdm_agent_wire::DeviceId::new_v4();
    let (peer, certificate, csr) =
        material::peer_material(c, device, rss_mdm_agent_wire::pki::Purpose::DaDevice)
            .await
            .context("verify the purpose-bound DA device certificate")?;
    let meta = peer.metadata();
    let tenant = Uuid::parse_str(&c.tenant.to_string())?;
    let grant = Uuid::new_v4();
    let credential = Uuid::new_v4();
    let issuance = Uuid::new_v4();
    let operation = Uuid::new_v4();
    let receipt = rss_mdm_agent_wire::da::Registration {
        service_id: Uuid::parse_str(&c.inputs.installation.instance_id)?,
        tenant,
        device: *device,

        credential,
        issuance_id: issuance,
        operation_id: operation,
    };
    let mut tx = seed(c).await?;
    sqlx::query("INSERT INTO rss_da.certificate_grants(certificate_purpose,tenant_id,id,operation_id,source,actor,instance,device,secret_digest,request_digest,state,expires_at) VALUES('da_device',$1,$2,$2,'administrator','seed',$3,$4,repeat('0',64),repeat('1',64),'consumed',clock_timestamp()+interval '1 hour')")
        .bind(tenant).bind(grant).bind(&c.inputs.installation.instance_id).bind(device.into_uuid()).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO rss_da.devices (tenant_id, id, channel, certificate_grant_id, state, purpose, epoch) VALUES ($1, $2, NULL, $3, 'active', 'da_device', $4)")
        .bind(tenant).bind(device.into_uuid()).bind(grant).bind(Uuid::new_v4()).execute(&mut *tx).await?;
    let fingerprint = format!("{:x}", Sha256::digest(&certificate));
    sqlx::query("INSERT INTO rss_da.credentials (tenant_id, id, device, channel, locator, state, purpose) VALUES ($1, $2, $3, NULL, $4, 'active', 'da_device')")
        .bind(tenant).bind(credential).bind(device.into_uuid()).bind(&fingerprint).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO rss_da.certificate_issuances(tenant_id,id,grant_id,operation_id,request_digest,authority_digest,csr,spki,identity,profile,not_before,not_after,state,certificate_chain,metadata,fingerprint,activation_operation,activation_digest,activation_result,credential) VALUES($1,$2,$3,$4,repeat('1',64),repeat('2',64),$5,$6,$7,'{}',$8,$9,'issued',$10,$11,$12,$4,repeat('3',64),$13,$14)")
        .bind(tenant).bind(issuance).bind(grant).bind(operation).bind(csr)
        .bind(meta.spki.iter().map(|v|format!("{v:02x}")).collect::<String>()).bind(&meta.identity)
        .bind(meta.not_before).bind(meta.not_after).bind(serde_json::json!([STANDARD.encode(certificate)]))
        .bind(serde_json::to_value(meta)?).bind(fingerprint)
        .bind(serde_json::json!({"kind":"da_device","receipt":receipt})).bind(credential).execute(&mut *tx).await?;
    tx.commit().await?;
    let da_pool = c.inputs.pool("shared", "da_access").await?;
    let mut tx = da_pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await?;
    let da =
        device::authenticate_endpoint_in(StorageProfile::Da, &mut tx, c.execution(), &peer).await?;
    assert_eq!(da.kind(), device::RegistrationKind::DaDevice);
    assert_eq!(agent.kind(), device::RegistrationKind::Agent);
    assert_ne!(da.device(), agent.device());
    assert!(
        device::require_use_in(&mut tx, &da, device::ConsumerUse::AgentTask)
            .await
            .is_err()
    );
    let resolved = delivery::resolve_on(&mut tx, &da).await?;
    assert_eq!(resolved.device(), device);
    tx.rollback().await?;
    // Neither valid credential creates a delivery relationship without explicit authorization.
    let mut tx = seed(c).await?;
    assert!(delivery::resolve_on(&mut tx, agent).await.is_err());
    tx.rollback().await?;
    let anchor = DaRegistration { device: *device };
    Box::pin(embedded_status(c, &anchor))
        .await
        .context("embedded DA management HTTP")?;
    let person = Box::pin(super::da_authorization::authorize(c, agent, &anchor))
        .await
        .context("authorize Agent delivery using the real Identity proof")?;
    Box::pin(super::da_materials::verify(c, agent, &anchor, person))
        .await
        .context("prove RSS custody and recovery across distinct DA and Agent identities")?;
    let mut tx = c.database.archive_pool().begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await?;
    let resolved = delivery::resolve_on(&mut tx, agent).await?;
    assert_eq!(resolved.device(), device);
    tx.rollback().await?;
    let mut tx = seed(c).await?;
    assert_eq!(
        delivery::for_da_on(&mut tx, tenant, &anchor)
            .await?
            .unwrap()
            .device,
        *agent.device()
    );
    sqlx::query("UPDATE rss_da.agent_delivery SET enabled=false,revision=2 WHERE tenant_id=$1 AND da_device=$2").bind(tenant).bind(device.into_uuid()).execute(&mut *tx).await?;
    assert!(delivery::resolve_on(&mut tx, agent).await.is_err());
    sqlx::query("UPDATE rss_da.agent_delivery SET enabled=true,revision=3,agent_device=$3 WHERE tenant_id=$1 AND da_device=$2").bind(tenant).bind(device.into_uuid()).bind(Uuid::new_v4()).execute(&mut *tx).await?;
    assert!(delivery::resolve_on(&mut tx, agent).await.is_err());
    sqlx::query(
        "UPDATE rss_da.agent_delivery SET agent_device=$3 WHERE tenant_id=$1 AND da_device=$2",
    )
    .bind(tenant)
    .bind(device.into_uuid())
    .bind(agent.device().into_uuid())
    .execute(&mut *tx)
    .await?;
    sqlx::query("UPDATE rss_da.credentials SET state = 'revoked' WHERE tenant_id = $1 AND id = $2")
        .bind(tenant)
        .bind(credential)
        .execute(&mut *tx)
        .await?;
    assert!(delivery::resolve_on(&mut tx, agent).await.is_err());
    tx.rollback().await?;
    da_pool.close().await;
    Ok(())
}

async fn embedded_status(
    c: &Context,
    da: &rss_mdm_registration_service::device::endpoints::DaRegistration,
) -> Result<()> {
    use rss_mdm_authorization_service::{Permission, credential::RequestCredential};
    let allowed = c.account(&[Permission::OperationRead]).await?;
    let denied = c.account(&[Permission::AccountWrite]).await?;
    let cookie = |account: &crate::authority_t2_support::Account| -> Result<String> {
        let RequestCredential::Cookie(secret) = account.credential()? else {
            anyhow::bail!("expected account session");
        };
        Ok(format!("__Host-identity-session={}", secret.expose()))
    };
    let allowed = cookie(&allowed)?;
    let denied = cookie(&denied)?;
    let address = std::net::TcpListener::bind("127.0.0.1:0")?.local_addr()?;
    let mut config =
        crate::host_t2_support::configuration(&c.inputs, "shared", address, Uuid::new_v4()).await?;
    let provider = provider::Provider::new(&c.inputs.directory).await?;
    let address = std::net::TcpListener::bind("127.0.0.1:0")?.local_addr()?;
    let origin = format!("https://localhost:{}", address.port());
    let trust = provider
        .publish(
            &c.operator,
            &c.tenant.to_string(),
            &c.inputs.installation.instance_id,
            &origin,
        )
        .await?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(
        provider.directory.join("provider.pk8"),
        std::fs::Permissions::from_mode(0o600),
    )?;
    config["device_access"]["registration"] = serde_json::json!({
        "listen":address,"origin":origin,"certificate_file":provider.directory.join("server.pem"),"private_key_file":provider.directory.join("server.key"),
        "certificate_days":365,"configuration_lifetime":3600,
        "providers":[{"purpose":"da_device","issuer":trust.issuers[0].digest,"origin":format!("https://localhost:{}",provider.port),"tls_root_file":provider.directory.join("task-trust-ca/ca.pem"),"provisioner":"rss-da-device","kid":"da-test","provisioner_key_file":provider.directory.join("provider.pk8")}]
    });
    let admin = c
        .account(&[Permission::Enrollment, Permission::Credentials])
        .await?;
    crate::host_t2_support::run(config, |client, base| async move {
        let url = format!(
            "{base}/api/v1/tenants/{}/apple/platform-sso/status",
            c.tenant
        );
        let get = |cookie: &str| {
            client
                .get(&url)
                .query(&[("deviceId", da.device.to_string())])
                .header("cookie", cookie)
                .send()
        };
        assert_eq!(get(&denied).await?.status(), 403);
        let status = get(&allowed)
            .await?
            .error_for_status()?
            .json::<serde_json::Value>()
            .await?;
        assert_eq!(status["device"], serde_json::json!(da.device));
        assert_eq!(status["login"], "unknown");
        assert_eq!(status["deployment"], "unobserved");
        Box::pin(lifecycle_http(
            c, &client, &base, &origin, &provider, &admin,
        ))
        .await
    })
    .await
}

#[path = "../../../../hack/test-support/da_provider.rs"]
mod provider;

async fn lifecycle_http(
    c: &Context,
    browser: &reqwest::Client,
    base: &str,
    origin: &str,
    fixture: &provider::Provider,
    admin: &crate::authority_t2_support::Account,
) -> Result<()> {
    use rss_mdm_agent_wire::{da, enroll};
    use serde_json::{Value, json};
    let management = format!("{base}/api/v1/tenants/{}/da", c.tenant);
    let protocol = format!("{origin}/api/v1/da");
    let login=browser.post(format!("{base}/api/v1/identity/tenants/{}/login",c.tenant))
        .header("origin","https://mdm.example.test").header("x-identity-request","1")
        .json(&json!({"login":format!("foundation-{}",admin.user.principal_id),"password":"foundation-only-valid-password"})).send().await?.error_for_status()?;
    let cookie = login
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok()?.split(';').next())
        .find(|v| v.starts_with("__Host-identity-session="))
        .context("embedded Identity cookie")?
        .to_owned();
    let csrf = login.json::<Value>().await?["csrfToken"]
        .as_str()
        .context("embedded CSRF")?
        .to_owned();
    let post = |path: String| {
        browser
            .post(path)
            .header("origin", "https://mdm.example.test")
            .header("x-identity-request", "1")
            .header("x-csrf-token", &csrf)
            .header("cookie", &cookie)
    };
    let public = fixture.client(None)?;
    let mut peer = None::<reqwest::Client>;
    let mut first = None::<da::Registration>;
    for index in 1..=2 {
        let request = da::GrantRequest {
            operation_id: Uuid::new_v4(),
            secret: rss_mdm_agent_wire::runtime::Secret::parse(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaA",
            )?,
            csr: fixture.csr(index)?,
            expires_in_seconds: 600,
        };
        let source = match peer.as_ref() {
            None => post(format!("{management}/grants")),
            Some(peer) => peer.post(format!("{protocol}/renewal-grants")),
        };
        let grant: da::Grant = read_response(source.json(&request).send().await?).await?;
        let issue = da::CertificateRequest {
            operation_id: Uuid::new_v4(),
            grant_id: grant.grant_id,
            secret: request.secret,
            csr: request.csr,
        };
        let candidate: enroll::Candidate = read_response(
            public
                .post(format!("{protocol}/certificates"))
                .json(&issue)
                .send()
                .await?,
        )
        .await?;
        let current = fixture.client(Some((&candidate, index)))?;
        let registration: da::Registration = read_response(
            current
                .post(format!("{protocol}/activate"))
                .json(&enroll::ActivationRequest {
                    wire_version: 1,
                    operation_id: Uuid::new_v4(),
                    issuance_id: candidate.issuance_id,
                })
                .send()
                .await?,
        )
        .await?;
        if let Some(old) = &first {
            assert_eq!(old.device, registration.device);
            assert_ne!(old.credential, registration.credential);
        } else {
            first = Some(registration);
        }
        if let Some(previous) = peer.replace(current) {
            assert_eq!(
                previous
                    .get(format!("{protocol}/configuration-trust"))
                    .send()
                    .await?
                    .status(),
                401
            );
        }
    }
    let device = first.context("initial activation")?.device;
    let revoke = format!("{management}/devices/{device}/registration/revoke");
    post(revoke.clone())
        .json(&json!({"operationId":Uuid::new_v4()}))
        .send()
        .await?
        .error_for_status()?;
    assert_eq!(
        peer.context("renewed peer")?
            .get(format!("{protocol}/configuration-trust"))
            .send()
            .await?
            .status(),
        401
    );
    sqlx::query("DELETE FROM mdm_access.authorization_rules WHERE tenant_id=$1::uuid AND id=$2")
        .bind(c.tenant.to_string())
        .bind(admin.rule)
        .execute(&c.operator)
        .await?;
    assert_eq!(
        post(revoke)
            .json(&json!({"operationId":Uuid::new_v4()}))
            .send()
            .await?
            .status(),
        403
    );
    Ok(())
}
async fn read_response<T: serde::de::DeserializeOwned>(response: reqwest::Response) -> Result<T> {
    let status = response.status();
    let body = response.text().await?;
    anyhow::ensure!(
        status.is_success(),
        "embedded registration {status}: {body}"
    );
    Ok(serde_json::from_str(&body)?)
}
