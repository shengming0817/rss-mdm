//! The independent DA certificate and signed native facts reach the real PSSO/Identity owners.
use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use openssl::{
    ec::{EcGroup, EcKey},
    nid::Nid,
    pkey::{PKey, Private},
};
use ring::signature::KeyPair;
use rss_identity_core::session::{BearerSecret, SessionSecret};
use rss_mdm_agent_wire::{da, platform_sso as wire, runtime as access};
use rss_mdm_device_access::deployment::{Deployment, Observation};
use rss_mdm_device_access_postgres::{
    self as pg,
    platform_sso::{self as psso, crypto},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

pub fn deadline() -> rss_transactional_messaging::policy::OperationDeadline {
    rss_transactional_messaging::policy::OperationDeadline::from_remaining(Duration::from_secs(10))
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
pub fn runtime(c: &Context) -> Result<Arc<psso::Runtime>> {
    Ok(Arc::new(
        psso::Runtime::new(
            wire::Configuration {
                team_id: "ABCDEFGHIJ".into(),
                extension_id: "com.example.da.extension".into(),
                application_id: "com.example.da".into(),
                application_version: "1.0".into(),
                client_id: Uuid::new_v4(),
            },
            "https://localhost",
            Uuid::parse_str(&c.tenant.to_string())?,
            "active".into(),
            [("active".into(), Key::new()?.signer)].into(),
        )?
        .with_deployment_authorities(vec![pg::evidence::Authority {
            id: business::authority_id(),
            public_key: business::key().public_key().as_ref().try_into()?,
        }])?,
    ))
}
async fn post(
    c: &Context,
    b: &rss_mdm_device_access_http::Business,
    path: &str,
    content_type: &str,
    body: String,
) -> Result<(axum::http::StatusCode, String)> {
    let router = rss_mdm_device_access_http::platform_sso::browser_routes()
        .bind_with(Some(&b.platform), Arc::clone)
        .layer(axum::Extension(business::audit(c)))
        .into_axum();
    let response = router
        .oneshot(
            axum::http::Request::post(path)
                .header("host", "localhost")
                .header("content-type", content_type)
                .body(axum::body::Body::from(body))?,
        )
        .await?;
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 131072).await?;
    Ok((status, String::from_utf8(bytes.to_vec())?))
}
async fn register(
    peer: &reqwest::Client,
    base: &str,
    registration: Uuid,
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
            iss: registration,
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
    b: &rss_mdm_device_access_http::Business,
    source: &wire::RegistrationReceipt,
    device: &Key,
    user: &Key,
) -> Result<String> {
    let rt = b.platform.context.runtime()?;
    let path = format!("/api/v1/apple/platform-sso/{}", c.tenant);
    let (status, response) = post(
        c,
        b,
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
            "iss":source.source_id,"sub":source.source_id,"aud":rt.endpoints.issuer,
            "iat":now(),"exp":now()+120,"scope":wire::SCOPE,
            "nonce":client_nonce,"request_nonce":nonce["nonce"],
        }),
    )?;
    let assertion = device.signer.sign(
        wire::LOGIN_TYPE,
        &json!({
            "iss":rt.configuration.client_id,"client_id":rt.configuration.client_id,
            "aud":rt.endpoints.token,"sub":source.source_id,"username":source.source_id,
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
        b,
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
    binding: Uuid,
    source: &wire::RegistrationReceipt,
    user: &Key,
    token: String,
) -> Result<SessionSecret> {
    let browser = crypto::random()?;
    let challenge = Box::pin(c.authority.begin_platform_login(
        c.tenant,
        binding,
        rss_identity_postgres::platform::PlatformPurpose::BrowserLogin,
        browser.clone(),
        rss_identity_postgres::AttemptSource::parse("independent-da-psso")?,
        deadline(),
    ))
    .await?;
    let proof = user.signer.sign(
        wire::BRIDGE_TYPE,
        &serde_json::to_value(wire::BrowserClaims {
            iss: source.source_id,
            aud: psso::browser_audience("https://localhost"),
            nonce: challenge.nonce.clone(),
            source_version: source.source_version,
            access_token: token,
            iat: now(),
            exp: now() + 120,
        })?,
    )?;
    let result = Box::pin(c.authority.complete_platform_login(
        c.tenant,
        challenge.id,
        challenge.nonce,
        browser,
        proof.into_bytes(),
        deadline(),
    ))
    .await?;
    assert!(result.assertion.is_none());
    let secret = SessionSecret::parse(result.session.secret().expose().into())?;
    Box::pin(c.authority.inspect_session(
        c.tenant,
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
    let b = business::assemble(c, m)?;
    let rt = b.platform.context.runtime()?;
    let token = material::administrator(c).await?;
    let principal = c
        .authority
        .inspect_bearer(c.tenant, BearerSecret::parse(token.clone())?, deadline())
        .await?
        .account()
        .principal
        .as_uuid();
    let (actor, secret) = Box::pin(business::login(c, principal)).await?;
    let old: Value = sqlx::query_scalar("SELECT definition FROM rss_da.policies WHERE tenant_id=$1::uuid AND definition#>>'{target,device}'=$2")
        .bind(c.tenant.to_string()).bind(&registration.device).fetch_one(&c.operator).await?;
    let mut publication: rss_mdm_policy_postgres::device_access::Publication =
        serde_json::from_value(old)?;
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
            .post(format!("{base}/configurations"))
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
            .post(format!("{base}/configurations"))
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
    let mut expected = rt.profile(&login)?;
    rss_mdm_apple_mdm::da::bind(&mut expected)?;
    assert_eq!(
        serde_json::to_value(rendered)?,
        serde_json::to_value(expected)?
    );
    super::exports::verify(&client, &base, &token, &exported, &installed).await?;
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
        device: registration.device.clone(),
        registration: registration.registration,
        generation: registration.generation as i64,
        authority: business::authority_id(),
        sequence: 10,
        issued_at: now() - 1,
        expires_at: now() + 600,
        revoked: false,
        policy: publication.id,
        policy_version: publication.version,
        configuration: Some(rss_mdm_device_access::deployment::ConfigurationDeployment {
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
            profile_uuid: rt.profile(&login)?.uuid,
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
    super::configuration::verify_sources(
        c,
        m,
        client,
        base,
        &token,
        &actor,
        &mut publication,
        &mut observation,
        &exported,
    )
    .await?;
    let id = Uuid::new_v4();
    let change = pg::device_access::Change {
        operation_id: Uuid::new_v4(),
        expected_revision: 0,
        action: pg::device_access::Action::Put {
            person: rss_mdm_device_access::Person {
                instance: Uuid::parse_str(&c.inputs.installation.instance_id)?,
                principal,
            },
            intent: rss_mdm_device_access::AccountIntent::Existing {
                account: account.clone(),
            },
            policy: publication.id,
        },
    };
    let fingerprints = std::collections::BTreeMap::new();
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
        registration.registration,
        wire::Kind::Device,
        None,
        &device,
    )
    .await?;
    let source = register(
        peer,
        base,
        registration.registration,
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
    observation.applications.push(access::AccessResult {
        binding_id: binding.id,
        binding_generation: binding.generation,
        revision: binding.revision,
        definition_digest: binding.definition_digest()?,
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
    let no_tasks: (i64,i64,i64) = sqlx::query_as("SELECT (SELECT count(*) FROM rss_da.agent_delivery),(SELECT count(*) FROM rss_da.access_runs),(SELECT count(*) FROM rss_da.results)").fetch_one(&c.operator).await?;
    assert_eq!(
        no_tasks,
        (0, 0, 0),
        "native evidence synthesizes no Agent delivery, run or ACK"
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
        serde_json::to_value(stored.status())?
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
    let native_token = Box::pin(native_login(c, &b, &source, &device, &user)).await?;
    let session = Box::pin(browser_session(c, id, &source, &user, native_token)).await?;
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
    let diagnostic =
        super::configuration::diagnostic(client, base, &token, &registration.device).await?;
    assert_eq!(diagnostic["resolution"]["blocked"], "withdrawn");
    assert!(
        Box::pin(native_login(c, &b, &source, &device, &user))
            .await
            .is_err(),
        "revoked evidence rejects a fresh native login"
    );
    assert!(
        c.authority
            .inspect_session(c.tenant, session, deadline())
            .await
            .is_err(),
        "evidence revocation invalidates the current Identity session"
    );
    assert!(
        c.authority
            .begin_platform_login(
                c.tenant,
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
    let native_token = Box::pin(native_login(c, &b, &source, &device, &user)).await?;
    Box::pin(browser_session(c, id, &source, &user, native_token)).await
}
