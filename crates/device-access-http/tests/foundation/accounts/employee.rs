use super::*;
use ring::{
    rand::SystemRandom,
    signature::{self, KeyPair as _},
};
use rss_mdm_agent_wire::enterprise::KeyRegistration;
use rss_mdm_device_access::deployment::{Deployment, Observation};

#[allow(
    clippy::too_many_arguments,
    reason = "exercise the registered device and its independent employee browser through the existing HTTPS fixture"
)]
pub(super) async fn recover(
    c: &Context,
    client: &reqwest::Client,
    peer: &reqwest::Client,
    base: &str,
    r: &da::Registration,
    policy: &da::Publication,
    binding: Uuid,
    employee: Uuid,
    original: &w::AccessResult,
) -> Result<i64> {
    let (cookie, csrf) = credentials::login(c, client, employee).await?;
    let management = format!(
        "{}/api/v1/tenants/{}/devices/{}/device-access",
        c.browser_origin, r.tenant, r.device
    );
    let resource = format!("{management}/bindings/{binding}");
    let mut browser =
        enterprise::Browser::new(c, client, resource.clone(), cookie.clone(), csrf.clone());
    browser.register().await?;
    let w::AccessEffect::Applied { account, .. } = &original.effect else {
        anyhow::bail!("expected original applied account");
    };
    let mut observation = Observation {
        tenant: r.tenant,
        installation: r.service_id,
        device: r.device,
        authority: business::authority_id(),
        sequence: 1,
        issued_at: now() - 1,
        expires_at: now() + 600,
        revoked: false,
        policy: policy.id,
        policy_version: policy.version,
        configuration: None,
        deployment: Deployment::Windows {
            interactive_broker: true,
        },
        local_session: Some(w::AccessLocalSession {
            account: account.clone(),
            session_id: Uuid::new_v4(),
        }),
        applications: vec![],
    };
    let credential = cookie.split_once('=').unwrap().1;
    let post = |path: &str| {
        peer.post(format!("{base}/device-access/{path}"))
            .header("x-rss-user-session", credential)
    };
    let put = |input: &Value, authorization: &str| {
        client
            .put(&resource)
            .header("origin", &c.browser_origin)
            .header("x-csrf-token", &csrf)
            .header("x-identity-request", "1")
            .header("cookie", authorization)
            .json(input)
            .send()
    };
    let key = SigningKey::new()?;
    let previous = rss_mdm_device_access_postgres::enterprise::WindowsSource {
        renewed_by: None,
        id: Uuid::new_v4(),
        version: 1,
        binding_id: binding,
        binding_generation: 1,
        factor_generation: 1,
        binding_revision: 1,
        person: rss_mdm_device_access::Person {
            instance: r.service_id,
            principal: employee,
        },
        public_key: key.public.clone(),
    };
    sqlx::query("INSERT INTO rss_da.windows_sources(tenant_id,binding,id,version,document) VALUES($1,$2,$3,1,$4)")
        .bind(r.tenant).bind(binding).bind(previous.id).bind(sqlx::types::Json(&previous)).execute(&c.operator).await?;
    let malformed = client
        .post(format!("{resource}/step-up/oidc/{}", Uuid::new_v4()))
        .header("cookie", &cookie)
        .header("origin", &c.browser_origin)
        .header("x-csrf-token", &csrf)
        .header("x-identity-request", "1")
        .json(&json!({}))
        .send()
        .await?;
    assert_eq!(malformed.status(), 400);
    let mine: Value = material::success(
        client
            .get(&resource)
            .header("cookie", &cookie)
            .send()
            .await?,
    )
    .await?;
    assert_eq!(mine["id"], binding.to_string());
    let other = material::seed_administrator(c, Some(&r.device)).await?;
    let (other_cookie, other_csrf) = credentials::login(c, client, other).await?;
    let foreign = client
        .get(&resource)
        .header("cookie", &other_cookie)
        .send()
        .await?;
    assert_eq!(foreign.status(), 404);
    let denied = client.post(format!("{resource}/step-up"))
        .header("cookie", &other_cookie).header("x-csrf-token", &other_csrf)
        .header("origin", &c.browser_origin).header("x-identity-request","1")
        .json(&json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"action":{"kind":"reset_factors"}}))
        .send().await?;
    assert_eq!(denied.status(), 404);
    let mut reset = Uuid::nil();
    let mut repair = Uuid::nil();
    for (revision, action) in [(1, "repair_binding"), (2, "reset_factors")] {
        if revision == 1 {
            let grant = rss_mdm_authorization_service::Grant {
                operation: rss_mdm_authorization_service::Permission::AccountWrite,
                scope: rss_mdm_authorization_service::Scope::Device { id: r.device },
            };
            sqlx::query("UPDATE rss_da.authorization_rules SET document=jsonb_set(document,'{grants}',(document->'grants') || jsonb_build_array($3::jsonb)),revision=revision+1 WHERE tenant_id=$1 AND document#>>'{subject,user,principalId}'=$2")
                .bind(r.tenant).bind(employee.to_string()).bind(sqlx::types::Json(grant)).execute(&c.operator).await?;
        } else {
            sqlx::query("DELETE FROM rss_da.authorization_rules WHERE tenant_id=$1 AND document#>>'{subject,user,principalId}'=$2")
                .bind(r.tenant).bind(employee.to_string()).execute(&c.operator).await?;
        }
        let operation = Uuid::new_v4();
        let input =
            json!({"operationId":operation,"expectedRevision":revision,"action":{"kind":action}});
        assert!(put(&input, &cookie).await?.status().is_client_error());
        let grant = if revision == 2 {
            let oidc = c.oidc.get().context("standalone Keycloak")?;
            oidc.employee_grant(
                super::super::device_oidc::DeviceChange {
                    client,
                    base: &c.browser_origin,
                    resource: &resource,
                    session: &cookie,
                    csrf: &csrf,
                    input: &input,
                },
                &c.operator,
                &c.tenant.to_string(),
                employee,
            )
            .await?
        } else {
            browser.grant(&input).await?
        };
        let wrong = json!({"operationId":Uuid::new_v4(),"expectedRevision":revision,"action":{"kind":action}});
        assert_eq!(
            put(&wrong, &format!("{cookie}; {grant}")).await?.status(),
            401
        );
        if revision == 1 {
            repair = operation;
        }
        let auth = format!("{cookie}; {grant}");
        let (one, two) = tokio::join!(put(&input, &auth), put(&input, &auth));
        let saved: Value = material::success(one?).await?;
        assert_eq!(material::success::<Value>(two?).await?, saved);
        let replay: Value = material::success(put(&input, &cookie).await?).await?;
        assert_eq!(replay, saved);
        let original: Value = material::success(
            client
                .get(format!("{management}/operations/{operation}"))
                .header("cookie", &cookie)
                .send()
                .await?,
        )
        .await?;
        assert_eq!(original, saved);
        assert_eq!(saved["revision"], revision + 1);
        assert_eq!(saved["factorGeneration"], if revision == 1 { 1 } else { 2 });
        reset = operation;
    }
    let repair_progress: Value = material::success(
        client
            .get(format!("{management}/operations/{repair}/execution"))
            .header("cookie", &cookie)
            .send()
            .await?,
    )
    .await?;
    assert_eq!(repair_progress["revision"], 2);
    assert_eq!(repair_progress["cancellation"], "confirmed");
    assert_eq!(
        client
            .get(format!("{management}/operations/{repair}"))
            .header("cookie", other_cookie)
            .send()
            .await?
            .status(),
        404
    );
    let next = || peer.post(format!("{base}/account-operations/next")).send();
    let offer: da::AccountOffer = material::success(next().await?).await?;
    assert_eq!(offer.operation_id, reset);
    let task = observe(peer, base, &offer, da::AccountObservation::Received)
        .await?
        .permit
        .context("employee reset permit")?;
    let Some(w::AccessWindowsPlan::Initialize {
        recipient,
        expected_revision,
    }) = &task.windows
    else {
        anyhow::bail!("expected factor rotation")
    };
    let subject = w::CredentialSubject::RssLogin {
        binding,
        binding_generation: 1,
        sid: match account {
            w::AccessAccount::Windows { sid, .. } => sid.clone(),
            _ => anyhow::bail!("expected Windows account"),
        },
    };
    observe(
        peer,
        base,
        &offer,
        da::AccountObservation::Prepared(w::AccessPrepared {
            binding_id: binding,
            binding_generation: 1,
            revision: task.revision,
            definition_digest: task.definition_digest,
            account: account.clone(),
        }),
    )
    .await?;
    let payload = credentials::seal(
        task.definition_digest,
        &recipient.public_key,
        &subject,
        *expected_revision,
        &task.material_aad(&subject, *expected_revision)?,
        &URL_SAFE_NO_PAD.encode([53; 32]),
    )?;
    let receipt = observe(peer, base, &offer, da::AccountObservation::Escrow(payload))
        .await?
        .receipt
        .context("new custody")?;
    observe(
        peer,
        base,
        &offer,
        da::AccountObservation::Result(
            w::AccessResult {
                binding_id: binding,
                binding_generation: 1,
                revision: task.revision,
                definition_digest: task.definition_digest,
                effect: w::AccessEffect::Applied {
                    account: account.clone(),
                    role: w::AccessRole::Standard,
                    mac: None,
                    windows: Some(w::AccessWindowsFacts::RssFactor(w::AccessRssFacts {
                        factor_generation: 2,
                        recovery: receipt,
                    })),
                },
            }
            .into(),
        ),
    )
    .await?;
    let progress: Value = material::success(
        client
            .get(format!("{management}/operations/{reset}/execution"))
            .header("cookie", &cookie)
            .send()
            .await?,
    )
    .await?;
    assert_eq!(progress["execution"], "succeeded");
    assert_eq!(progress["revision"], task.revision);
    let registration = |k: &SigningKey, operation: Uuid| -> Result<KeyRegistration> {
        let mut registration = KeyRegistration {
            binding_id: binding,
            binding_generation: 1,
            factor_generation: 2,
            binding_revision: task.revision,
            public_key: k.public.clone(),
            signature: String::new(),
        };
        let bytes = registration.signing_bytes(r.tenant, r.service_id, employee, operation)?;
        registration.signature = URL_SAFE_NO_PAD.encode(
            k.key
                .sign(&SystemRandom::new(), &bytes)
                .map_err(|_| anyhow::anyhow!("test signing"))?
                .as_ref(),
        );
        Ok(registration)
    };
    let renew = |k: &SigningKey| registration(k, reset);
    let endpoint = format!("operations/{reset}/windows-key");
    let verified = observation.local_session.clone();
    observation.local_session = Some(w::AccessLocalSession {
        account: w::AccessAccount::Windows {
            sid: "S-1-5-21-2-3-4-1003".into(),
            authority: w::AccessWindowsAuthority::Local,
        },
        session_id: Uuid::new_v4(),
    });
    material::empty(
        peer.post(format!("{base}/deployment-evidence"))
            .json(&business::signed(&observation)?)
            .send()
            .await?,
    )
    .await?;
    assert_eq!(
        post(&endpoint).json(&renew(&key)?).send().await?.status(),
        401
    );
    let shared: w::AccessDirectory = material::success(
        peer.get(format!("{base}/device-access"))
            .header("x-rss-user-session", credential)
            .send()
            .await?,
    )
    .await?;
    assert_eq!(shared.device_id, r.device);
    assert!(shared.bindings.iter().all(|b| b.id != binding));
    observation.local_session = verified;
    observation.sequence += 1;
    material::empty(
        peer.post(format!("{base}/deployment-evidence"))
            .json(&business::signed(&observation)?)
            .send()
            .await?,
    )
    .await?;
    let mut invalid = renew(&key)?;
    invalid.signature = URL_SAFE_NO_PAD.encode([0u8; 64]);
    assert_eq!(post(&endpoint).json(&invalid).send().await?.status(), 401);
    let replacement = SigningKey::new()?;
    let change = Uuid::new_v4();
    let manager = material::seed_administrator(c, None).await?;
    let privilege = rss_mdm_authorization_service::Grant {
        operation: rss_mdm_authorization_service::Permission::EnterpriseApplicationsWrite,
        scope: rss_mdm_authorization_service::Scope::Tenant,
    };
    sqlx::query("UPDATE rss_da.authorization_rules SET document=jsonb_set(document,'{grants}',(document->'grants') || jsonb_build_array($3::jsonb)),revision=revision+1 WHERE tenant_id=$1 AND document#>>'{subject,user,principalId}'=$2")
        .bind(r.tenant).bind(manager.to_string()).bind(sqlx::types::Json(privilege)).execute(&c.operator).await?;
    let (mgmt_cookie, mgmt_csrf) = credentials::login(c, client, manager).await?;
    let config = format!(
        "{}/api/v1/tenants/{}/device-access/enterprise/configuration",
        c.browser_origin, r.tenant
    );
    let mut admin = enterprise::Browser::new(c, client, config, mgmt_cookie, mgmt_csrf);
    admin.register().await?;
    let change = json!({"operationId":change,"expectedRevision":1,"configuration":{"kind":"windows_key","registration":registration(&replacement, change)?}});
    material::empty(admin.submit(&change).await?).await?;
    let rejected: String =
        material::success(post(&endpoint).json(&renew(&replacement)?).send().await?).await?;
    assert_eq!(rejected, "registration_required");
    // Restore the independent fixture branch in which the administrator left the original source intact.
    sqlx::query("UPDATE rss_da.windows_sources SET version=1, document=$3 WHERE tenant_id=$1 AND binding=$2")
        .bind(r.tenant).bind(binding).bind(sqlx::types::Json(&previous)).execute(&c.operator).await?;
    for (candidate, expected) in [
        (&SigningKey::new()?, "registration_required"),
        (&key, "current"),
        (&key, "current"),
    ] {
        let result: String =
            material::success(post(&endpoint).json(&renew(candidate)?).send().await?).await?;
        assert_eq!(result, expected);
    }
    let version: i64 = sqlx::query_scalar(
        "SELECT version FROM rss_da.windows_sources WHERE tenant_id=$1 AND binding=$2",
    )
    .bind(r.tenant)
    .bind(binding)
    .fetch_one(&c.operator)
    .await?;
    assert_eq!(version, 2);
    Ok(task.revision)
}

struct SigningKey {
    key: signature::EcdsaKeyPair,
    public: rss_mdm_agent_wire::platform_sso::PublicKey,
}
impl SigningKey {
    fn new() -> Result<Self> {
        let rng = SystemRandom::new();
        let alg = &signature::ECDSA_P256_SHA256_FIXED_SIGNING;
        let der = signature::EcdsaKeyPair::generate_pkcs8(alg, &rng)
            .map_err(|_| anyhow::anyhow!("test key generation"))?;
        let key = signature::EcdsaKeyPair::from_pkcs8(alg, der.as_ref(), &rng)
            .map_err(|_| anyhow::anyhow!("test key"))?;
        let raw = key.public_key().as_ref();
        let public = rss_mdm_agent_wire::platform_sso::PublicKey {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: URL_SAFE_NO_PAD.encode(&raw[1..33]),
            y: URL_SAFE_NO_PAD.encode(&raw[33..]),
        };
        Ok(Self { key, public })
    }
}
