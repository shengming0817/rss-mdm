//! The independent DA certificate and signed native facts reach the real PSSO/Identity owners.
use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use openssl::{
    ec::{EcGroup, EcKey},
    nid::Nid,
    pkey::{PKey, Private},
};
use rss_identity_core::session::{BearerSecret, SessionSecret};
use rss_mdm_agent_wire::{da, platform_sso as wire, runtime as access};
use rss_mdm_device_access::deployment::{Deployment, Observation};
use rss_mdm_device_access_postgres::{
    self as pg,
    platform_sso::{self as psso, crypto},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub fn deadline() -> rss_request_context::Deadline {
    rss_request_context::Deadline::at(std::time::Instant::now() + Duration::from_secs(10))
}
struct Key {
    private: PKey<Private>,
    public: wire::PublicKey,
    signer: crypto::Signer,
}
impl Key {
    fn new() -> Result<Self> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let private = PKey::from_ec_key(EcKey::generate(&group)?)?;
        let public = crypto::coordinates(&private)?;
        let signer = crypto::Signer::from_pem(&private.private_key_to_pem_pkcs8()?)?;
        Ok(Self {
            private,
            public,
            signer,
        })
    }
}
pub fn configuration(
    dir: &std::path::Path,
) -> Result<rss_mdm_device_access_runtime::platform::PlatformSso> {
    let key = dir.join("platform-signer.pem");
    host::private(&key, &Key::new()?.private.private_key_to_pem_pkcs8()?)?;
    Ok(rss_mdm_device_access_runtime::platform::PlatformSso {
        configuration: wire::Configuration {
            team_id: "ABCDEFGHIJ".into(),
            extension_id: "com.example.da.extension".into(),
            application_id: "com.example.da".into(),
            application_version: "1.0".into(),
            client_id: Uuid::new_v4(),
        },
        active_key: "active".into(),
        signing_keys: [("active".into(), key)].into(),
        password_providers: vec![],
    })
}
pub fn runtime(dir: &std::path::Path, origin: &str) -> Result<Arc<psso::Runtime>> {
    let config: rss_da_app::config::Config =
        rss_da_app::config::load(&dir.join("host-runtime.json"))?;
    Ok(config
        .platform_sso
        .unwrap()
        .load(origin, business::authorities()?.as_ref())?)
}
async fn post(
    c: &Context,
    client: &reqwest::Client,
    path: &str,
    content_type: &str,
    body: String,
) -> Result<(axum::http::StatusCode, String)> {
    let response = client
        .post(format!("{}{path}", c.browser_origin))
        .header("content-type", content_type)
        .body(body)
        .send()
        .await?;
    Ok((response.status(), response.text().await?))
}
async fn register(
    peer: &reqwest::Client,
    base: &str,
    device: &rss_mdm_agent_wire::DeviceId,
    kind: wire::Kind,
    binding: Option<&pg::device_access::Binding>,
    key: &Key,
) -> Result<wire::RegistrationReceipt> {
    let challenge: wire::BootstrapResponse = material::success(
        peer.post(format!("{base}/platform-sso/bootstrap"))
            .json(&wire::Bootstrap {
                operation_id: Uuid::new_v4(),
                kind,
                binding_id: binding.map(|b| b.id),
                binding_generation: binding.map(|b| b.generation),
            })
            .send()
            .await?,
    )
    .await?;
    let proof = key.signer.sign(
        wire::REGISTRATION_TYPE,
        &serde_json::to_value(wire::RegistrationClaims {
            iss: device.to_owned(),
            aud: format!("{}/register", challenge.endpoints.base),
            challenge_id: challenge.id,
            source_id: challenge.source_id,
            source_version: challenge.source_version,
            nonce: challenge.nonce,
            encryption_key_id: key.public.key_id()?,
            iat: now(),
            exp: now() + 120,
        })?,
    )?;
    let receipt: wire::RegistrationReceipt = material::success(
        peer.post(format!("{base}/platform-sso/register"))
            .json(&wire::Registration {
                operation_id: Uuid::new_v4(),
                challenge_id: challenge.id,
                signing_key: Some(key.public.clone()),
                encryption_key: key.public.clone(),
                proof,
            })
            .send()
            .await?,
    )
    .await?;
    assert!(receipt.registered);
    assert_eq!(
        receipt.registration_trust,
        wire::RegistrationTrust::DaDevicePop
    );
    assert!(!receipt.hardware_attested);
    Ok(receipt)
}
fn part(output: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    output.extend(u32::try_from(value.len())?.to_be_bytes());
    output.extend(value);
    Ok(())
}
fn apv(key: &Key, nonce: &str) -> Result<String> {
    let mut point = vec![4];
    point.extend(URL_SAFE_NO_PAD.decode(&key.public.x)?);
    point.extend(URL_SAFE_NO_PAD.decode(&key.public.y)?);
    let mut value = Vec::new();
    part(&mut value, b"Apple")?;
    part(&mut value, &point)?;
    part(&mut value, nonce.as_bytes())?;
    Ok(URL_SAFE_NO_PAD.encode(value))
}
fn decrypt(key: &Key, token: &str) -> Result<Value> {
    let parts: Vec<_> = token.split('.').collect();
    anyhow::ensure!(
        parts.len() == 5 && parts[1].is_empty(),
        "native compact JWE"
    );
    let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0])?)?;
    assert_eq!(header["alg"], "ECDH-ES");
    assert_eq!(header["enc"], "A256GCM");
    let public = crypto::public(&serde_json::from_value(header["epk"].clone())?)?;
    let mut deriver = openssl::derive::Deriver::new(&key.private)?;
    deriver.set_peer(&public)?;
    let mut kdf = 1u32.to_be_bytes().to_vec();
    kdf.extend(deriver.derive_to_vec()?);
    part(&mut kdf, b"A256GCM")?;
    part(
        &mut kdf,
        &URL_SAFE_NO_PAD.decode(header["apu"].as_str().unwrap())?,
    )?;
    part(
        &mut kdf,
        &URL_SAFE_NO_PAD.decode(header["apv"].as_str().unwrap())?,
    )?;
    kdf.extend(256u32.to_be_bytes());
    let plaintext = openssl::symm::decrypt_aead(
        openssl::symm::Cipher::aes_256_gcm(),
        &Sha256::digest(kdf),
        Some(&URL_SAFE_NO_PAD.decode(parts[2])?),
        parts[0].as_bytes(),
        &URL_SAFE_NO_PAD.decode(parts[3])?,
        &URL_SAFE_NO_PAD.decode(parts[4])?,
    )?;
    Ok(serde_json::from_slice(&plaintext)?)
}
async fn native_login(
    c: &Context,
    client: &reqwest::Client,
    b: &rss_mdm_device_access_http::Business,
    source: &wire::RegistrationReceipt,
    device: &Key,
    user: &Key,
) -> Result<String> {
    let rt = b.platform.context.runtime()?;
    let path = format!("/api/v1/apple/platform-sso/{}", c.tenant);
    let (status, response) = post(
        c,
        client,
        &format!("{path}/nonce"),
        "application/json",
        String::new(),
    )
    .await?;
    anyhow::ensure!(status.is_success(), "native nonce: {status} {response}");
    let nonce: Value = serde_json::from_str(&response)?;
    let client_nonce = "foundation-native-client-nonce";
    let inner = user.signer.sign(
        wire::ASSERTION_TYPE,
        &json!({
            "iss":source.source_id,"sub":source.source_id,"aud":rt.endpoints(Uuid::parse_str(&c.tenant.to_string())?)?.issuer,
            "iat":now(),"exp":now()+120,"scope":wire::SCOPE,
            "nonce":client_nonce,"request_nonce":nonce["nonce"],
        }),
    )?;
    let assertion = device.signer.sign(
        wire::LOGIN_TYPE,
        &json!({
            "iss":rt.configuration.client_id,"client_id":rt.configuration.client_id,
            "aud":rt.endpoints(Uuid::parse_str(&c.tenant.to_string())?)?.token,"sub":source.source_id,"username":source.source_id,
            "grant_type":wire::GRANT,"iat":now(),"exp":now()+120,"scope":wire::SCOPE,
            "nonce":client_nonce,"request_nonce":nonce["nonce"],"assertion":inner,
            "jwe_crypto":{"alg":"ECDH-ES","enc":"A256GCM","apv":apv(user,client_nonce)?},
        }),
    )?;
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("platform_sso_version", "1.0")
        .append_pair("grant_type", wire::GRANT)
        .append_pair("assertion", &assertion)
        .finish();
    let (status, response) = post(
        c,
        client,
        &format!("{path}/token"),
        "application/x-www-form-urlencoded",
        body,
    )
    .await?;
    anyhow::ensure!(status.is_success(), "native login: {status} {response}");
    let tokens = decrypt(user, &response)?;
    Ok(tokens["access_token"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("native access token"))?
        .into())
}
async fn browser_session(
    c: &Context,
    client: &reqwest::Client,
    binding: Uuid,
    source: &wire::RegistrationReceipt,
    user: &Key,
    token: String,
) -> Result<SessionSecret> {
    let url = format!(
        "{}/api/v1/apple/platform-sso/{}/browser",
        c.browser_origin, c.tenant
    );
    let response = client
        .post(format!("{url}/begin"))
        .header("origin", &c.browser_origin)
        .json(&wire::BrowserBegin {
            binding_id: binding,
        })
        .send()
        .await?
        .error_for_status()?;
    let cookie = response
        .headers()
        .get("set-cookie")
        .context("browser challenge cookie")?
        .to_str()?
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let challenge: wire::BrowserChallenge = response.json().await?;
    assert_eq!(
        challenge.audience,
        psso::browser_audience(&c.browser_origin)
    );
    let proof = user.signer.sign(
        wire::BRIDGE_TYPE,
        &serde_json::to_value(wire::BrowserClaims {
            iss: source.source_id,
            aud: psso::browser_audience(&c.browser_origin),
            nonce: challenge.nonce.clone(),
            source_version: source.source_version,
            access_token: token,
            iat: now(),
            exp: now() + 120,
        })?,
    )?;
    let input = wire::BrowserComplete {
        challenge_id: challenge.id,
        nonce: challenge.nonce,
        proof,
    };
    let complete = || {
        client
            .post(format!("{url}/complete"))
            .header("origin", &c.browser_origin)
            .json(&input)
    };
    assert_eq!(complete().send().await?.status(), 401);
    let response = complete()
        .header("cookie", &cookie)
        .send()
        .await?
        .error_for_status()?;
    let issued = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|h| h.to_str().ok())
        .filter_map(|h| {
            h.split(';')
                .next()?
                .strip_prefix("__Host-identity-session=")
        })
        .next()
        .context("Identity session cookie")?;
    let secret = SessionSecret::parse(issued.to_owned())?;
    assert_eq!(
        complete().header("cookie", &cookie).send().await?.status(),
        401
    );
    Box::pin(c.authority.inspect_session(
        c.execution(),
        SessionSecret::parse(secret.expose().into())?,
        deadline(),
    ))
    .await?;
    Ok(secret)
}

pub async fn verify(
    c: &Context,
    m: &material::Material,
    registration: &da::Registration,
    peer: &reqwest::Client,
    client: &reqwest::Client,
    base: &str,
) -> Result<SessionSecret> {
    let management = c.management_base();
    let b = business::assemble(c, m)?;
    let rt = b.platform.context.runtime()?;
    let token = material::administrator(c).await?;
    let principal = c
        .authority
        .inspect_bearer(
            c.execution(),
            BearerSecret::parse(token.clone())?,
            deadline(),
        )
        .await?
        .account()
        .principal
        .as_uuid();
    let old: Value = sqlx::query_scalar("SELECT definition FROM rss_da.policies WHERE tenant_id=$1::uuid AND (definition#>>'{target,device}')::uuid=$2")
        .bind(c.tenant.to_string()).bind(registration.device.into_uuid()).fetch_one(&c.operator).await?;
    let mut publication: rss_mdm_agent_wire::da::Publication = serde_json::from_value(old)?;
    let expected_revision = publication.revision;
    publication.revision += 1;
    publication.version = Uuid::new_v4();
    publication.enabled = true;
    let login = wire::LoginConfiguration {
        authentication: wire::AuthenticationMode::SecureEnclave,
        password_provider: None,
        login: wire::LoginPolicy::Local,
        unlock: wire::LoginPolicy::Local,
        filevault: wire::LoginPolicy::Local,
        offline_grace_seconds: None,
        registration_grace_seconds: None,
        maintenance_accounts: Vec::new(),
    };
    publication.configuration = access::AccessConfiguration {
        mac: Some(login.clone()),
        windows: access::AccessWindowsConfiguration::Disabled,
        self_enrollment: false,
        enabled: true,
        role: Some(access::AccessRole::Standard),
    };
    publication.managed_fields = vec![da::ConfigurationField::Mac];
    super::configuration::publish_protected(
        c,
        m,
        &pg::configuration::Change {
            operation_id: Uuid::new_v4(),
            expected_revision,
            publication: publication.clone(),
        },
    )
    .await?;
    super::configuration::reject_account_change(c, m, &registration.device, &publication).await?;
    // The real DA export freezes every public native generator input and bound identity.

    let exported: da::SignedConfiguration = material::success(
        client
            .post(format!("{management}/configurations"))
            .bearer_auth(&token)
            .json(&da::Export {
                operation_id: Uuid::new_v4(),
                policy: publication.id,
                version: publication.version,
                delivery: da::DeliveryPermission::Da,
                lifetime_seconds: 600,
            })
            .send()
            .await?,
    )
    .await?;

    let managed: da::SignedConfiguration = material::success(
        client
            .post(format!("{management}/configurations"))
            .bearer_auth(&token)
            .json(&da::Export {
                operation_id: Uuid::new_v4(),
                policy: publication.id,
                version: publication.version,
                delivery: da::DeliveryPermission::ManagedMandatory,
                lifetime_seconds: 600,
            })
            .send()
            .await?,
    )
    .await?;
    let installed: da::ConfigurationTrust = material::success(
        peer.get(format!("{base}/configuration-trust"))
            .send()
            .await?,
    )
    .await?;
    material::verify(&exported, &installed)?;

    let rendered = rss_mdm_apple_mdm::platform_sso::from_da_configuration(&exported.decode()?)?;
    let mut expected = rt.profile(Uuid::parse_str(&c.tenant.to_string())?, &login)?;
    rss_mdm_apple_mdm::da::bind(&mut expected)?;
    assert_eq!(
        serde_json::to_value(rendered)?,
        serde_json::to_value(expected)?
    );

    Box::pin(super::exports::verify(
        client,
        &management,
        &token,
        &exported,
        &installed,
    ))
    .await?;

    let mut wrong_tenant = installed.clone();
    wrong_tenant.tenant = Uuid::new_v4();
    assert!(rss_mdm_task_trust::configuration::verify(&exported, &wrong_tenant, now()).is_err());
    assert!(
        rss_mdm_task_trust::configuration::verify(
            &exported,
            &installed,
            exported.decode()?.expires_at
        )
        .is_err()
    );
    let account = access::AccessAccount::Macos {
        generated_uid: Uuid::new_v4(),
    };
    let configuration = rt.qualification_configuration()?;
    let mut observation = Observation {
        tenant: Uuid::parse_str(&c.tenant.to_string())?,
        installation: registration.service_id,
        device: registration.device,

        authority: business::authority_id(),
        sequence: 10,
        issued_at: now() - 1,
        expires_at: now() + 600,
        revoked: false,
        policy: publication.id,
        policy_version: publication.version,
        configuration: Some(rss_mdm_device_access::deployment::ConfigurationDeployment {
            applied: None,
            artifact: managed.decode()?.operation_id,
            digest: managed.digest.clone(),
            native_digest: managed.decode()?.native.digest,
            delivery: da::DeliveryPermission::ManagedMandatory,
            state: da::SourceState::Present,
        }),
        deployment: Deployment::Macos {
            configuration: configuration.configuration,
            application_id: configuration.application_id,
            application_version: configuration.application_version,
            application_installed: true,
            profile_identifier: configuration.profile_identifier,
            profile_uuid: rt
                .profile(Uuid::parse_str(&c.tenant.to_string())?, &login)?
                .uuid,
            profile_matched: true,
            architecture: "aarch64".into(),
            os_version: [26, 4, 0, 0],
            user_helper: true,
            system_broker: true,
        },
        local_session: Some(access::AccessLocalSession {
            account: account.clone(),
            session_id: Uuid::new_v4(),
        }),
        applications: Vec::new(),
    };
    let evidence = format!("{base}/deployment-evidence");
    material::empty(
        client
            .post(&evidence)
            .json(&business::signed(&observation)?)
            .send()
            .await?,
    )
    .await?;

    Box::pin(super::configuration::verify_sources(
        c,
        m,
        client,
        base,
        &token,
        principal,
        &mut publication,
        &mut observation,
        &exported,
    ))
    .await?;

    let employee = material::seed_administrator(c, Some(&registration.device)).await?;
    let id = Uuid::new_v4();
    let change = pg::device_access::Change {
        operation_id: Uuid::new_v4(),
        expected_revision: 0,
        action: pg::device_access::Action::Put {
            person: rss_mdm_device_access::Person {
                instance: Uuid::parse_str(&c.inputs.installation.instance_id)?,
                principal: employee,
            },
            intent: rss_mdm_device_access::AccountIntent::Existing {
                account: account.clone(),
            },
            policy: publication.id,
        },
    };
    let fingerprints = std::collections::BTreeMap::new();
    let (actor, secret) = Box::pin(business::login(c, principal))
        .await
        .context("platform proof cookie login")?;
    let proof = Box::pin(business::operation_proof(
        c,
        &secret,
        change.step_up_context(&actor, &registration.device, id, &fingerprints)?,
    ))
    .await?;
    let binding = Box::pin(b.service.change_device_access(
        &actor,
        &registration.device,
        id,
        &change,
        Some(&proof),
        &fingerprints,
        b.admission.as_ref(),
        &business::audit(c),
    ))
    .await?;
    let device = Key::new()?;
    let user = Key::new()?;
    register(
        peer,
        base,
        &registration.device,
        wire::Kind::Device,
        None,
        &device,
    )
    .await?;
    let source = register(
        peer,
        base,
        &registration.device,
        wire::Kind::User,
        Some(&binding),
        &user,
    )
    .await?;
    let status_url = format!("{base}/platform-sso/status?bindingId={id}");
    let before: wire::Status = material::success(peer.get(&status_url).send().await?).await?;
    assert!(
        before.user_registered && !before.login_ready,
        "registration is not application evidence"
    );
    observation.sequence += 1;
    let (operation, employee_cookie) =
        Box::pin(repair_binding(c, client, &binding, employee)).await?;
    let directory: access::AccessDirectory = material::success(
        peer.get(format!("{base}/device-access"))
            .header(
                "x-rss-user-session",
                employee_cookie
                    .split_once('=')
                    .context("employee session")?
                    .1,
            )
            .send()
            .await?,
    )
    .await?;
    assert_eq!(directory.device_id, registration.device);
    let desired = directory
        .bindings
        .iter()
        .find(|item| item.id == id)
        .context("device-visible Mac target")?;
    assert_eq!(desired.operation_id, operation);
    assert_eq!(desired.revision, binding.revision + 1);
    observation.applications.push(access::AccessResult {
        binding_id: desired.id,
        binding_generation: desired.binding_generation,
        revision: desired.revision,
        definition_digest: desired.definition_digest,
        effect: access::AccessEffect::Applied {
            account,
            role: access::AccessRole::Standard,
            windows: None,
            mac: Some(access::AccessMacFacts {
                secure_token: access::AccessObservation::Present,
                volume_owner: access::AccessObservation::Present,
                filevault_unlock: access::AccessObservation::Present,
                platform_sso: Some(access::AccessMacPlatformSsoFacts {
                    configuration: access::AccessObservation::Present,
                    device_registered: access::AccessObservation::Present,
                    user_registered: access::AccessObservation::Present,
                    user_source_id: source.source_id,
                    user_source_version: source.source_version,
                }),
            }),
        },
    });
    let mut incomplete = observation.clone();
    if let access::AccessEffect::Applied { mac: Some(mac), .. } =
        &mut incomplete.applications[0].effect
    {
        mac.secure_token = access::AccessObservation::Unknown;
    }
    assert!(
        client
            .post(&evidence)
            .json(&business::signed(&incomplete)?)
            .send()
            .await?
            .status()
            .is_client_error(),
        "native source cannot bypass Secure Token readiness"
    );
    let mut stale = observation.clone();
    stale.applications[0].revision += 1;
    assert!(
        client
            .post(&evidence)
            .json(&business::signed(&stale)?)
            .send()
            .await?
            .status()
            .is_client_error(),
        "application evidence is bound to the exact desired revision"
    );
    material::empty(
        client
            .post(&evidence)
            .json(&business::signed(&observation)?)
            .send()
            .await?,
    )
    .await?;
    let ready: wire::Status = material::success(peer.get(&status_url).send().await?).await?;
    assert!(ready.device_registered && ready.user_registered && ready.login_ready);
    let no_tasks: (i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM rss_da.agent_delivery WHERE tenant_id=$1 AND da_device=$2),
                (SELECT count(*) FROM rss_da.access_runs WHERE tenant_id=$1 AND binding_id=$3),
                (SELECT count(*) FROM rss_da.results WHERE tenant_id=$1 AND binding=$3)",
    )
    .bind(binding.tenant)
    .bind(binding.device.into_uuid())
    .bind(binding.id)
    .fetch_one(&c.operator)
    .await?;
    assert_eq!(
        no_tasks,
        (0, 0, 1),
        "the signed application has one native result and no delivery or run"
    );
    let progress: Value = material::success(
        client
            .get(format!(
                "{}/api/v1/tenants/{}/devices/{}/device-access/operations/{}/execution",
                c.browser_origin, c.tenant, registration.device, operation
            ))
            .header("cookie", &employee_cookie)
            .send()
            .await?,
    )
    .await?;
    assert!(progress["taskId"].is_null());
    assert_eq!(progress["received"], false);
    assert_eq!(progress["execution"], "succeeded");
    assert_eq!(
        progress["effect"],
        serde_json::to_value(&observation.applications[0].effect)?
    );
    let mut tx = c.seed().await?;
    let expired: bool = sqlx::query_scalar(
        "SELECT rss_da.binding_application_current(document,$2) FROM rss_da.bindings WHERE id=$1",
    )
    .bind(binding.id)
    .bind(observation.expires_at)
    .fetch_one(&mut *tx)
    .await?;
    assert!(!expired, "expiry removes native application qualification");
    let stored =
        pg::device_access::storage::get_in(&mut tx, observation.tenant, binding.id).await?;
    assert!(stored.deployment_application.is_some());
    assert!(
        serde_json::to_value(stored.status()?)?
            .get("deploymentApplication")
            .is_none()
    );
    assert!(
        serde_json::to_value(pg::device_access::directory::view(stored))?
            .get("deploymentApplication")
            .is_none()
    );
    let mut removed = rt.qualification_configuration()?;
    removed.authorities.clear();
    let qualified: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT FROM rss_da.platform_session_qualifications($1,$2,$3))",
    )
    .bind(source.source_id)
    .bind(serde_json::to_value(removed)?)
    .bind(now())
    .fetch_one(&mut *tx)
    .await?;
    assert!(
        !qualified,
        "removing the configured authority rejects persisted application evidence"
    );
    tx.rollback().await?;
    let projection = || {
        client
            .get(format!(
                "{}/api/v1/tenants/{}/apple/platform-sso/status",
                c.browser_origin, c.tenant
            ))
            .query(&[
                ("deviceId", registration.device.to_string()),
                ("bindingId", id.to_string()),
            ])
            .bearer_auth(&token)
            .send()
    };
    let view: Value = material::success(projection().await?).await?;
    assert_eq!(view["login"], "ready");
    assert_eq!(view["deployment"], "trusted");
    assert_eq!(view["userRegistration"], "current");
    assert_eq!(
        view["evidence"][0]["authority"],
        json!(business::authority_id())
    );
    assert!(view.get("userSource").is_none());
    let native_token = Box::pin(native_login(c, client, &b, &source, &device, &user)).await?;
    let session = Box::pin(browser_session(c, client, id, &source, &user, native_token)).await?;
    let mut revoked = observation.clone();
    revoked.sequence += 1;
    revoked.revoked = true;
    revoked.applications.clear();
    material::empty(
        client
            .post(&evidence)
            .json(&business::signed(&revoked)?)
            .send()
            .await?,
    )
    .await?;
    let view: Value = material::success(projection().await?).await?;
    assert_eq!(view["deployment"], "revoked");
    assert_ne!(view["login"], "ready");
    let diagnostic =
        super::configuration::diagnostic(client, &management, &token, &registration.device).await?;
    assert_eq!(diagnostic["resolution"]["blocked"], "withdrawn");
    assert!(
        Box::pin(native_login(c, client, &b, &source, &device, &user))
            .await
            .is_err(),
        "revoked evidence rejects a fresh native login"
    );
    assert!(
        c.authority
            .inspect_session(c.execution(), session, deadline())
            .await
            .is_err(),
        "evidence revocation invalidates the current Identity session"
    );
    assert!(
        c.authority
            .begin_platform_login(
                c.execution(),
                id,
                rss_identity_postgres::platform::PlatformPurpose::BrowserLogin,
                crypto::random()?,
                rss_identity_postgres::AttemptSource::parse("revoked-da-evidence")?,
                deadline()
            )
            .await
            .is_err()
    );
    observation.sequence = revoked.sequence + 1;
    material::empty(
        client
            .post(&evidence)
            .json(&business::signed(&observation)?)
            .send()
            .await?,
    )
    .await?;
    let native_token = Box::pin(native_login(c, client, &b, &source, &device, &user)).await?;
    let session = Box::pin(browser_session(c, client, id, &source, &user, native_token)).await?;
    Box::pin(super::configuration::verify_override(
        c,
        m,
        client,
        &token,
        &observation,
        &publication,
        base,
    ))
    .await?;
    Ok(session)
}

async fn repair_binding(
    c: &Context,
    client: &reqwest::Client,
    b: &pg::device_access::Binding,
    principal: Uuid,
) -> Result<(Uuid, String)> {
    let operation = Uuid::new_v4();
    let (cookie, csrf) = credentials::login(c, client, principal).await?;
    let resource = format!(
        "{}/api/v1/tenants/{}/devices/{}/device-access/bindings/{}",
        c.browser_origin, c.tenant, b.device, b.id
    );
    let mut browser =
        enterprise::Browser::new(c, client, resource.clone(), cookie.clone(), csrf.clone());
    browser.register().await?;
    let input = json!({"operationId":operation,"expectedRevision":b.revision,"action":{"kind":"repair_binding"}});
    let grant = browser.grant(&input).await?;
    material::empty(
        client
            .put(resource)
            .header("cookie", format!("{cookie}; {grant}"))
            .header("origin", &c.browser_origin)
            .header("x-csrf-token", &csrf)
            .header("x-identity-request", "1")
            .json(&input)
            .send()
            .await?,
    )
    .await?;
    Ok((operation, cookie))
}
