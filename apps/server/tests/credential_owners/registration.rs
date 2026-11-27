use super::*;
use anyhow::Context as _;
use rss_mdm_agent_wire::runtime as w;
#[tokio::test]
#[ignore = "T2: explicit DA delivery authorization and RSS material custody across distinct real endpoints"]
async fn access_binding_requires_current_device_authority() -> Result<()> {
    let c = Context::open("da_embedded", &[]).await?;
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
    let da_pool = c.inputs.pool(&c.profile, "da_access").await?;
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
    Box::pin(embedded_status(c, &anchor, *agent.device()))
        .await
        .context("embedded DA management HTTP")?;
    Box::pin(super::da_authorization::authorize(c, agent, &anchor))
        .await
        .context("authorize Agent delivery and verify custody across the distinct DA and Agent identities")?;
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
    agent: rss_mdm_agent_wire::DeviceId,
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
        crate::host_t2_support::configuration(&c.inputs, &c.profile, address, Uuid::new_v4())
            .await?;
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
    config["recovery_credentials"] = serde_json::json!({"active_key":"native","key_files":{"native":c.inputs.directory.join("native.key")},
        "recipients":[{"certificate_file":c.inputs.directory.join("task-trust-ca/ca.pem"),"private_key_file":c.inputs.directory.join("task-trust-ca/ca.key")}]});
    let oidc =
        device_oidc::Keycloak::start(&provider.directory, "https://mdm.example.test").await?;
    config["identity"]["oidc"] =
        identity_http::federation_config(&provider.directory, "https://mdm.example.test", true)?;
    oidc.configure(&mut config["identity"]["oidc"], &c.tenant.to_string());
    let admin = c
        .account(&[
            Permission::OperationRead,
            Permission::Enrollment,
            Permission::Credentials,
            Permission::IdentityProvidersManage,
            Permission::PolicyWrite,
            Permission::AccountWrite,
        ])
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
        Box::pin(embedded_step_up(c, &client, &base, &admin, da, &oidc))
            .await
            .context("embedded OIDC employee operation")?;
        Box::pin(lifecycle_http(
            c, &client, &base, &origin, &provider, &admin, agent,
        ))
        .await
    })
    .await
}

async fn employee_device(
    c: &Context,
    da: &rss_mdm_registration_service::device::endpoints::DaRegistration,
    principal: Uuid,
) -> Result<rss_mdm_device_access_postgres::device_access::Binding> {
    let tenant = c.tenant.to_string();
    let mut tx = seed(c).await?;
    let epoch = rss_mdm_registration_service::device::endpoints::current_da_epoch_in(
        &mut tx, &tenant, &da.device,
    )
    .await?;
    let installation = Uuid::parse_str(&c.inputs.installation.instance_id)?;
    let binding = super::da_materials::seed_windows_binding(
        &mut tx,
        Uuid::parse_str(&tenant)?,
        installation,
        da,
        principal,
        rss_mdm_device_access_postgres::device_access::account_delivery::Target::Da {
            installation,
            epoch,
        },
    )
    .await?;
    tx.commit().await?;
    Ok(binding)
}

async fn embedded_step_up(
    c: &Context,
    client: &reqwest::Client,
    base: &str,
    admin: &crate::authority_t2_support::Account,
    da: &rss_mdm_registration_service::device::endpoints::DaRegistration,
    oidc: &device_oidc::Keycloak,
) -> Result<()> {
    let admin_session = admin.cookie_session()?;
    let tenant = c.tenant.to_string();
    oidc.install(
        client,
        base,
        &tenant,
        &format!("__Host-identity-session={}", admin_session.expose()),
        &admin_session.csrf(),
    )
    .await?;
    let employee = c
        .account(&[rss_mdm_authorization_service::Permission::OperationRead])
        .await?;
    let session = employee.cookie_session()?;
    let principal = Uuid::parse_str(&employee.user.principal_id)?;
    oidc.link_employee(&c.operator, &tenant, principal).await?;
    let binding = employee_device(c, da, principal).await?;
    let resource = format!(
        "{base}/api/v1/tenants/{tenant}/devices/{}/device-access/bindings/{}",
        da.device, binding.id
    );
    let cookie = format!("__Host-identity-session={}", session.expose());
    let input = serde_json::json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"action":{"kind":"repair_binding"}});
    let grant = oidc
        .grant(client, base, &resource, &cookie, &session.csrf(), &input)
        .await?;
    let put = |change: &serde_json::Value, grant: &str| {
        client
            .put(&resource)
            .header("origin", "https://mdm.example.test")
            .header("cookie", format!("{cookie}; {grant}"))
            .header("x-identity-request", "1")
            .header("x-csrf-token", session.csrf())
            .json(change)
            .send()
    };
    oidc.expire_grant(&c.operator, &tenant, principal).await?;
    assert_eq!(put(&input, &grant).await?.status(), 401);
    let grant = oidc
        .grant(client, base, &resource, &cookie, &session.csrf(), &input)
        .await?;
    let mut wrong = input.clone();
    wrong["operationId"] = Uuid::new_v4().to_string().into();
    assert_eq!(put(&wrong, &grant).await?.status(), 401);
    let saved: serde_json::Value = put(&input, &grant)
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(saved["revision"], 2);
    assert_eq!(saved["operationId"], input["operationId"]);
    Ok(())
}

#[path = "../../../../hack/test-support/device_oidc.rs"]
mod device_oidc;
use crate::identity_http;
#[path = "../../../../hack/test-support/da_provider.rs"]
mod provider;

#[allow(
    clippy::cognitive_complexity,
    reason = "the two listener lifecycle proof exercises original and renewed peers before and after revocation"
)]
async fn lifecycle_http(
    c: &Context,
    browser: &reqwest::Client,
    base: &str,
    origin: &str,
    fixture: &provider::Provider,
    admin: &crate::authority_t2_support::Account,
    agent: rss_mdm_agent_wire::DeviceId,
) -> Result<()> {
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
    let (first_peer, initial) =
        activate_from_grant(fixture, &protocol, post(format!("{management}/grants")), 1).await?;
    let (renewed_peer, renewed) = activate_from_grant(
        fixture,
        &protocol,
        first_peer.post(format!("{protocol}/renewal-grants")),
        2,
    )
    .await?;
    assert_eq!(initial.device, renewed.device);
    assert_ne!(initial.credential, renewed.credential);
    let trust = format!("{protocol}/configuration-trust");
    assert_eq!(first_peer.get(&trust).send().await?.status(), 401);
    let device = renewed.device;
    let report = rss_mdm_agent_wire::da::StatusReport {
        identity: rss_mdm_agent_wire::da::ReportIdentity {
            service_id: renewed.service_id,
            tenant: renewed.tenant,
            device_id: device,
        },
        sequence: 1,
        observed_at: Some(time::OffsetDateTime::now_utc().unix_timestamp()),
        client_version: "embedded".into(),
        contract_version: 1,
        modules: rss_mdm_agent_wire::da::ClientModules {
            da: rss_mdm_agent_wire::da::ModuleObservation {
                installed: Some(true),
                enabled: Some(true),
            },
            mdm: rss_mdm_agent_wire::da::ModuleObservation {
                installed: Some(true),
                enabled: Some(true),
            },
            application: rss_mdm_agent_wire::da::ModuleApplication::Applied,
        },
        health: rss_mdm_agent_wire::da::Health::Unknown,
        binding: rss_mdm_agent_wire::da::Health::Unknown,
        factor: rss_mdm_agent_wire::da::Health::Unknown,
        configuration_digest: None,
        errors: vec![],
    };
    let credentials = format!(
        "{base}/api/v1/tenants/{}/devices/{device}/device-access",
        c.tenant
    );
    let id = Box::pin(embedded_credential(
        c,
        admin,
        &renewed,
        &credentials,
        &post,
        agent,
    ))
    .await?;
    let reported = renewed_peer
        .post(format!("{protocol}/status-reports"))
        .json(&report)
        .send()
        .await?;
    reported.error_for_status()?;
    let status_url = format!("{management}/admin/devices/{device}/status");
    let detail = browser
        .get(&status_url)
        .header("cookie", &cookie)
        .send()
        .await?
        .error_for_status()?
        .json::<Value>()
        .await?;
    assert_eq!(detail["report"]["modules"], json!(report.modules));
    let denied = c
        .account(&[rss_mdm_authorization_service::Permission::AccountWrite])
        .await?;
    let rss_mdm_authorization_service::credential::RequestCredential::Cookie(credential) =
        denied.credential()?
    else {
        anyhow::bail!("expected browser session")
    };
    assert_eq!(
        browser
            .get(&status_url)
            .header(
                "cookie",
                format!("__Host-identity-session={}", credential.expose())
            )
            .send()
            .await?
            .status(),
        403
    );
    let claim = ordered(
        c,
        device,
        agent,
        renewed_peer.post(format!("{protocol}/credential-operations/next")),
    )
    .await?;
    claim.error_for_status()?;
    let revoke = format!("{management}/devices/{device}/registration/revoke");
    post(revoke.clone())
        .json(&json!({"operationId":Uuid::new_v4()}))
        .send()
        .await?
        .error_for_status()?;
    assert_eq!(renewed_peer.get(&trust).send().await?.status(), 401);
    let historical = browser
        .get(format!("{credentials}/credential-operations/{id}"))
        .header("cookie", &cookie)
        .send()
        .await?
        .error_for_status()?
        .json::<Value>()
        .await?;
    assert_eq!(historical["request"]["operationId"], json!(id));
    assert_eq!(
        renewed_peer
            .post(format!("{protocol}/credential-operations/next"))
            .send()
            .await?
            .status(),
        401
    );
    let mut tx = seed(c).await?;
    sqlx::query("DELETE FROM rss_da.agent_delivery WHERE tenant_id=$1::uuid AND da_device=$2")
        .bind(c.tenant.to_string())
        .bind(device.into_uuid())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
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
async fn activate_from_grant(
    fixture: &provider::Provider,
    protocol: &str,
    submit: reqwest::RequestBuilder,
    index: u8,
) -> Result<(reqwest::Client, rss_mdm_agent_wire::da::Registration)> {
    use rss_mdm_agent_wire::{da, enroll};
    let request = da::GrantRequest {
        operation_id: Uuid::new_v4(),
        secret: rss_mdm_agent_wire::runtime::Secret::parse(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaA",
        )?,
        csr: fixture.csr(index)?,
        expires_in_seconds: 600,
    };
    let grant: da::Grant = read_response(submit.json(&request).send().await?).await?;
    let candidate: enroll::Candidate = read_response(
        fixture
            .client(None)?
            .post(format!("{protocol}/certificates"))
            .json(&da::CertificateRequest {
                operation_id: Uuid::new_v4(),
                grant_id: grant.grant_id,
                secret: request.secret,
                csr: request.csr,
            })
            .send()
            .await?,
    )
    .await?;
    let peer = fixture.client(Some((&candidate, index)))?;
    let registration = read_response(
        peer.post(format!("{protocol}/activate"))
            .json(&enroll::ActivationRequest {
                wire_version: 1,
                operation_id: Uuid::new_v4(),
                issuance_id: candidate.issuance_id,
            })
            .send()
            .await?,
    )
    .await?;
    Ok((peer, registration))
}
async fn read_response<T: serde::de::DeserializeOwned>(response: reqwest::Response) -> Result<T> {
    let path = response.url().path().to_owned();
    let status = response.status();
    let body = response.text().await?;
    anyhow::ensure!(
        status.is_success(),
        "embedded {path} returned {status}: {body}"
    );
    Ok(serde_json::from_str(&body)?)
}

#[path = "../../../../hack/test-support/da_recovery.rs"]
mod da_recovery;
async fn embedded_credential(
    c: &Context,
    admin: &crate::authority_t2_support::Account,
    registration: &rss_mdm_agent_wire::da::Registration,
    base: &str,
    post: &impl Fn(String) -> reqwest::RequestBuilder,
    agent: rss_mdm_agent_wire::DeviceId,
) -> Result<Uuid> {
    use serde_json::{Value, json};
    let native = std::fs::read(c.inputs.directory.join("native.key"))?;
    let recipient = super::recipient(c)?;
    let id = recipient.id().to_string();
    let protection = recovery::Protection::new(
        recovery::KeyRing::new(
            "native".into(),
            vec![("native".into(), zeroize::Zeroizing::new(native))],
        )?,
        vec![recipient],
    )?;
    let mut tx = seed(c).await?;
    let (binding, _, _) = da_recovery::seed(
        &mut tx,
        registration,
        Uuid::parse_str(&admin.user.principal_id)?,
        &protection,
        &id,
    )
    .await?;
    tx.commit().await?;
    let version = Uuid::new_v4();
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let policy = json!({"id":Uuid::new_v4(),"version":version,"revision":1,"device":registration.device,"enabled":true,
        "notBefore":now-1,"expiresAt":now+3600,"runLifetimeSeconds":600,
        "operation":{"kind":"verify_rss_login","binding":binding.id,"bindingGeneration":binding.generation,"sid":da_recovery::SID}});
    let _: Value = read_response(
        post(format!("{base}/credential-policies"))
            .json(&policy)
            .send()
            .await?,
    )
    .await?;
    let mut tx = seed(c).await?;
    sqlx::query("INSERT INTO rss_da.agent_delivery(tenant_id,da_device,agent_installation,agent_device,enabled,revision) VALUES($1::uuid,$2,$3,$4,true,1)")
        .bind(c.tenant.to_string()).bind(registration.device.into_uuid()).bind(Uuid::parse_str(&c.inputs.installation.instance_id)?).bind(agent.into_uuid()).execute(&mut *tx).await?;
    tx.commit().await?;
    let mut previous = None;
    for _ in 0..2 {
        let op = Uuid::new_v4();
        let input = json!({"operationId":op,"bindingId":binding.id,"bindingGeneration":binding.generation,"action":"verify","replaces":previous,"policyVersion":version});
        let status: Value = read_response(
            ordered(
                c,
                registration.device,
                agent,
                post(format!("{base}/credential-operations")).json(&input),
            )
            .await?,
        )
        .await?;
        assert_eq!(status["state"], "accepted");
        previous = Some(op);
    }
    previous.context("settled replacement identity")
}

/// Hold the Agent registration fence while the live HTTP handler starts, then observe that the DA fence is still available.
async fn ordered(
    c: &Context,
    device: rss_mdm_agent_wire::DeviceId,
    agent: rss_mdm_agent_wire::DeviceId,
    request: reqwest::RequestBuilder,
) -> Result<reqwest::Response> {
    use rss_mdm_registration_service::device::endpoints;
    let tenant = c.tenant.to_string();
    let mut tx = c.operator.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(&tenant)
        .execute(&mut *tx)
        .await?;
    endpoints::lock_in(
        rss_mdm_install_support::StorageProfile::Mdm,
        &mut tx,
        &tenant,
        &agent,
        rss_mdm_inventory::Channel::Agent,
    )
    .await?;
    let check = async {
        let result = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let waiting: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT FROM pg_stat_activity a WHERE pg_backend_pid()=ANY(pg_blocking_pids(a.pid)))",
                )
                .fetch_one(&mut *tx)
                .await?;
                if waiting {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            endpoints::lock_da_in(&mut tx, &tenant, &device).await?;
            Ok::<_, anyhow::Error>(())
        })
        .await;
        tx.rollback().await?;
        result
            .context("observe the HTTP handler waiting on Agent while the DA fence is available")?
    };
    let (response, verified) = tokio::join!(request.send(), check);
    let response = response?;
    if !response.status().is_success() {
        anyhow::bail!(
            "credential request returned {} at {}",
            response.status(),
            response.url().path()
        );
    }
    verified?;
    Ok(response)
}
