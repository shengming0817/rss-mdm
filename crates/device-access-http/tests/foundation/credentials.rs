//! Begin with an active registration, selected policy, bound Windows account and legally escrowed current version.
use super::*;
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use rss_identity_core::session::{BearerSecret, SessionSecret};
use rss_mdm_agent_wire::{da, runtime as w};
use rss_mdm_device_access_postgres::{self as pg, device_access as access};
use rss_mdm_recovery_credentials::{
    self as recovery,
    tasks::device::{Action, Event, Request, State, Status},
};
use serde_json::{Value, json};
const SID: &str = "S-1-5-21-1-2-3-1001";
fn envelope(
    task: &w::CredentialTaskSpec,
    subject: &w::CredentialSubject,
    secret: &str,
) -> Result<w::CredentialEscrow> {
    let aad = task.material_aad(subject, task.expected[0].revision)?;
    let mut key = [0; 32];
    let mut nonce = [0; 12];
    openssl::rand::rand_bytes(&mut key)?;
    openssl::rand::rand_bytes(&mut nonce)?;
    let cipher = ring::aead::LessSafeKey::new(
        ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, &key)
            .map_err(|_| anyhow::anyhow!("escrow test AES key"))?,
    );
    let mut ciphertext = secret.as_bytes().to_vec();
    cipher
        .seal_in_place_append_tag(
            ring::aead::Nonce::assume_unique_for_key(nonce),
            ring::aead::Aad::from(aad),
            &mut ciphertext,
        )
        .map_err(|_| anyhow::anyhow!("escrow test encryption"))?;
    let public =
        openssl::pkey::PKey::public_key_from_der(&STANDARD.decode(&task.recipient.public_key)?)?;
    let mut encrypt = openssl::encrypt::Encrypter::new(&public)?;
    encrypt.set_rsa_padding(openssl::rsa::Padding::PKCS1_OAEP)?;
    encrypt.set_rsa_oaep_md(openssl::hash::MessageDigest::sha256())?;
    encrypt.set_rsa_mgf1_md(openssl::hash::MessageDigest::sha256())?;
    let mut wrapped = vec![0; encrypt.encrypt_len(&key)?];
    let len = encrypt.encrypt(&key, &mut wrapped)?;
    wrapped.truncate(len);
    Ok(w::CredentialEscrow {
        definition_digest: task.definition_digest,
        materials: vec![w::CredentialEnvelope {
            subject: subject.clone(),
            expected_revision: task.expected[0].revision,
            wrapped_key: STANDARD.encode(wrapped),
            nonce,
            ciphertext: STANDARD.encode(ciphertext),
        }],
    })
}

pub struct Pending {
    pub request: Request,
    pub principal: Uuid,
    pub receipt: w::CredentialReceipt,
}
pub async fn verify(
    c: &Context,
    m: &material::Material,
    client: &reqwest::Client,
    peer: &reqwest::Client,
    base: &str,
    registration: &da::Registration,
) -> Result<Pending> {
    let tenant = registration.tenant;
    let bearer = material::administrator(c).await?;
    let principal = c
        .authority
        .inspect_bearer(
            c.execution(),
            BearerSecret::parse(bearer.clone())?,
            platform::deadline(),
        )
        .await?
        .account()
        .principal
        .as_uuid();
    let url = format!(
        "{}/api/v1/tenants/{tenant}/devices/{}/device-access",
        c.browser_origin, registration.device
    );
    let account = w::AccessAccount::Windows {
        sid: SID.into(),
        authority: w::AccessWindowsAuthority::Local,
    };
    let configuration = w::AccessConfiguration {
        mac: None,
        windows: w::AccessWindowsConfiguration::RssFactor {
            accounts: vec![w::AccessWindowsKind::Local],
        },
        self_enrollment: false,
        enabled: true,
        role: None,
    };
    let publication = rss_mdm_policy_postgres::device_access::Publication {
        managed_fields: vec![],
        id: Uuid::new_v4(),
        revision: 1,
        version: Uuid::new_v4(),
        target: rss_mdm_policy_postgres::device_access::Target::Device {
            device: registration.device,
        },
        enabled: true,
        configuration: configuration.clone(),
    };
    let mut binding = access::Binding {
        operation_id: Uuid::new_v4(),
        account_disposition: w::AccessAccountDisposition::Keep,
        id: Uuid::new_v4(),
        tenant,
        device: registration.device,

        person: rss_mdm_device_access::Person {
            instance: registration.service_id,
            principal,
        },
        origin: access::Origin::SelfEnrollment,
        generation: 3,
        factor_generation: 4,
        revision: 1,
        state: rss_mdm_device_access::State::Pending,
        intent: rss_mdm_device_access::AccountIntent::Existing {
            account: account.clone(),
        },
        account: Some(account.clone()),
        policy: publication.id,
        policy_version: publication.version,
        configuration,
        received_revision: None,
        applied_revision: None,
        deployment_application: None,
        effect: None,
        applied_windows: None,
        created_by_rss: false,
    };
    let mut tx = c.seed().await?;
    rss_mdm_policy_postgres::device_access::publish_on(
        &mut tx,
        tenant,
        &publication,
        0,
        serde_json::json!({"kind":"system"}),
        now(),
    )
    .await?;
    access::storage::insert_in(&mut tx, &binding).await?;

    let config: rss_da_app::config::Config = rss_da_app::config::load(&m.directory.join("host-runtime.json"))?;
    let protection = config.recovery.unwrap().open()?;
    let recipient = recovery::Recipient::from_pem(
        &std::fs::read(m.directory.join("recovery.pem"))?,
        &std::fs::read(m.directory.join("recovery.key"))?,
    )?;
    recovery::Protection::select_on(DA, &mut tx, tenant, recipient.id()).await?;
    let qualification = pg::recovery::eligibility::AccessEligibility { admission: None };
    let custody = recovery::Custody::new(DA, Some(&qualification));
    let anchor = recovery::Binding {
        device: registration.device,
        subject: recovery::Subject::RssLogin {
            binding: binding.id,
            binding_generation: binding.generation,
            sid: SID.into(),
        },
    };
    let first = Uuid::new_v4();
    let coordinates =
        recovery::storage::reserve_in(custody, &mut tx, tenant, &anchor, first, 0).await?;
    let original = URL_SAFE_NO_PAD.encode([81; 32]);
    recovery::storage::ingest_in(
        custody,
        &mut tx,
        &protection.keys,
        &coordinates,
        first,
        original.as_bytes(),
    )
    .await?;
    recovery::storage::verify_in(custody, &mut tx, &coordinates, first).await?;
    let receipt = w::CredentialReceipt {
        subject: serde_json::from_value(serde_json::to_value(&anchor.subject)?)?,
        material: coordinates.material,
        version: coordinates.version,
    };
    binding.state = rss_mdm_device_access::State::Active;
    binding.received_revision = Some(binding.revision);
    binding.applied_revision = Some(binding.revision);
    binding.applied_windows = Some(w::AccessWindowsFacts::RssFactor(w::AccessRssFacts {
        factor_generation: binding.factor_generation,
        recovery: receipt.clone(),
    }));
    binding.effect = Some(w::AccessEffect::Applied {
        account,
        role: w::AccessRole::Standard,
        mac: None,
        windows: binding.applied_windows.clone(),
    });
    access::storage::save_in(&mut tx, &binding, binding.revision).await?;
    tx.commit().await?;
    let page: Value = material::success(
        client
            .get(format!("{url}/materials"))
            .bearer_auth(&bearer)
            .send()
            .await?,
    )
    .await?;
    assert_eq!(page["items"][0]["id"], json!(receipt.material));
    assert!(!page.to_string().contains(&original));
    let session = client
        .post(format!(
            "{}/api/v1/identity/tenants/{tenant}/login",
            c.browser_origin
        ))
        .header("origin", &c.browser_origin)
        .header("x-identity-request", "1")
        .json(
            &json!({"login":format!("da-{principal}"),"password":"foundation-only-valid-password"}),
        )
        .send()
        .await?
        .error_for_status()?;
    let cookie = session
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .filter_map(|v| v.split(';').next())
        .find(|v| v.starts_with("__Host-identity-session="))
        .context("session cookie")?
        .to_owned();
    let session_secret = SessionSecret::parse(cookie.split_once('=').unwrap().1.to_owned())?;
    let csrf = session.json::<Value>().await?["csrfToken"]
        .as_str()
        .context("csrf")?
        .to_owned();
    let actor = c
        .sessions
        .authenticate(
            c.execution(),
            &c.authorization,
            rss_mdm_authorization_service::credential::RequestCredential::Cookie(
                SessionSecret::parse(session_secret.expose().into())?,
            ),
            platform::deadline(),
        )
        .await?;
    let operation = Uuid::new_v4();
    let input = recovery::DisclosureRequest {
        operation_id: operation,
        proof: None,
    };
    let grant = Box::pin(business::operation_proof(
        c,
        &session_secret,
        input.context(
            &actor,
            &registration.device,
            receipt.material,
            receipt.version,
        )?,
    ))
    .await?;
    let reveal = |id, proof: bool| {
        client
            .post(format!(
                "{url}/materials/{}/versions/{}/secret",
                receipt.material, receipt.version
            ))
            .header("origin", &c.browser_origin)
            .header("x-identity-request", "1")
            .header("x-csrf-token", &csrf)
            .header(
                "cookie",
                if proof {
                    format!("{cookie}; __Host-identity-operation={}", grant.expose())
                } else {
                    cookie.clone()
                },
            )
            .json(&json!({"operationId":id}))
            .send()
    };
    assert_eq!(reveal(Uuid::new_v4(), true).await?.status(), 401);
    for _ in 0..2 {
        let response = reveal(operation, true).await?.error_for_status()?;
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert!(response.json::<Value>().await?["secret"].as_str() == Some(original.as_str()));
    }
    assert_eq!(reveal(operation, false).await?.status(), 401);
    let native = |id, event: &Event| {
        peer.post(format!("{base}/credential-operations/{id}/events"))
            .json(event)
            .send()
    };
    let mut active_secret = original;
    for (action, finish) in [
        (Action::Verify, true),
        (Action::Rotate, true),
        (Action::Rotate, false),
    ] {
        let request = Request {
            operation_id: Uuid::new_v4(),
            binding_id: binding.id,
            binding_generation: binding.generation,
            action,
        };
        let send = || {
            client
                .post(format!("{url}/credential-operations"))
                .bearer_auth(&bearer)
                .json(&request)
                .send()
        };
        let (left, right) = tokio::join!(send(), send());
        for response in [left?, right?] {
            let accepted: Status = material::success(response).await?;
            assert_eq!(accepted.state, State::Accepted);
        }
        let spec: w::CredentialTaskSpec = material::success(
            peer.get(format!("{base}/credential-operations/next"))
                .send()
                .await?,
        )
        .await?;
        assert_eq!(spec.task_id, request.operation_id);
        let candidate = if action == Action::Verify {
            active_secret.clone()
        } else {
            URL_SAFE_NO_PAD.encode(if finish { [82; 32] } else { [83; 32] })
        };
        let event = Event::Escrow {
            attempt_id: spec.attempt_id,
            value: envelope(&spec, &spec.expected[0].subject, &candidate)?,
        };
        let progress: Status =
            material::success(native(request.operation_id, &event).await?).await?;
        assert_eq!(progress.state, State::PendingApplication);
        let ack = progress.receipt.context("durable escrow coordinates")?;
        let mut wrong = ack.clone();
        wrong.version += 1;
        assert_eq!(
            native(
                request.operation_id,
                &Event::Applied {
                    attempt_id: spec.attempt_id,
                    definition_digest: spec.definition_digest,
                    receipt: wrong
                }
            )
            .await?
            .status(),
            409
        );
        if !finish {
            return Ok(Pending {
                request,
                principal,
                receipt: ack,
            });
        }
        let confirmed: Status = material::success(
            native(
                request.operation_id,
                &Event::Applied {
                    attempt_id: spec.attempt_id,
                    definition_digest: spec.definition_digest,
                    receipt: ack,
                },
            )
            .await?,
        )
        .await?;
        assert_eq!(confirmed.state, State::Applied);
        active_secret = candidate;
    }
    unreachable!()
}
