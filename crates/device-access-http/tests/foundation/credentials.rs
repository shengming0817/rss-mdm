//! Begin with an active registration, selected policy, bound Windows account and legally escrowed current version.
use super::*;
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use rss_identity_core::session::{BearerSecret, SessionSecret};
use rss_mdm_agent_wire::da::{CredentialEvent as Event, CredentialSettlement};
use rss_mdm_agent_wire::{da, runtime as w};
use rss_mdm_device_access_postgres::device_access as access;
use rss_mdm_recovery_credentials::{
    self as recovery,
    tasks::device::{Action, Request, State, Status},
};
use serde_json::{Value, json};
#[path = "../../../../hack/test-support/da_recovery.rs"]
mod fixture;
use fixture::SID;
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

pub async fn login(
    c: &Context,
    client: &reqwest::Client,
    principal: Uuid,
) -> Result<(String, String)> {
    let tenant = c.tenant;
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
    let csrf = session.json::<Value>().await?["csrfToken"]
        .as_str()
        .context("csrf")?
        .to_owned();
    Ok((cookie, csrf))
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
    let config: rss_da_app::config::Config =
        rss_da_app::config::load(&m.directory.join("host-runtime.json"))?;
    let protection = config.recovery.unwrap().open()?;
    let recipient = recovery::Recipient::from_pem(
        &std::fs::read(m.directory.join("recovery.pem"))?,
        &std::fs::read(m.directory.join("recovery.key"))?,
    )?;
    let mut tx = c.seed().await?;
    let (binding, receipt, original) = fixture::seed(
        &mut tx,
        registration,
        principal,
        &protection,
        recipient.id(),
    )
    .await?;
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
    let (cookie, csrf) = login(c, client, principal).await?;
    let session_secret = SessionSecret::parse(cookie.split_once('=').unwrap().1.to_owned())?;
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
    let restricted = material::device_administrator(c, &registration.device).await?;
    let restricted = c
        .authority
        .inspect_bearer(
            c.execution(),
            BearerSecret::parse(restricted)?,
            platform::deadline(),
        )
        .await?
        .account()
        .principal
        .as_uuid();
    for (id, expected) in [(restricted, 403), (principal, 401)] {
        let (other, token) = login(c, client, id).await?;
        let attempt = client
            .post(format!(
                "{url}/materials/{}/versions/{}/secret",
                receipt.material, receipt.version
            ))
            .header("origin", &c.browser_origin)
            .header("x-identity-request", "1")
            .header("x-csrf-token", token)
            .header(
                "cookie",
                format!("{other}; __Host-identity-operation={}", grant.expose()),
            )
            .json(&json!({"operationId":operation}))
            .send()
            .await?;
        assert_eq!(attempt.status(), expected);
        assert!(attempt.json::<Value>().await?.get("secret").is_none());
    }
    let mut versions = Vec::new();
    for kind in ["verify_rss_login", "rotate_rss_login"] {
        let version = Uuid::new_v4();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let policy = json!({"id":Uuid::new_v4(),"version":version,"revision":1,"device":registration.device,
            "operation":{"kind":kind,"binding":binding.id,"bindingGeneration":binding.generation,"sid":SID},
            "enabled":true,"notBefore":now-1,"expiresAt":now+3600,"runLifetimeSeconds":1800});
        let path = format!("{url}/credential-policies");
        for _ in 0..2 {
            let read: Value = material::success(
                client
                    .post(&path)
                    .bearer_auth(&bearer)
                    .json(&policy)
                    .send()
                    .await?,
            )
            .await?;
            assert_eq!(read, policy);
        }
        let read: Value = material::success(
            client
                .get(format!("{path}/{version}"))
                .bearer_auth(&bearer)
                .send()
                .await?,
        )
        .await?;
        assert_eq!(read, policy);
        versions.push(version);
    }
    let versions: [Uuid; 2] = versions.try_into().expect("verify and rotate policies");
    Box::pin(reconcile(
        c, client, peer, base, &url, &binding, &bearer, &original, versions,
    ))
    .await?;
    let native = |id, event: &Event| {
        peer.post(format!("{base}/credential-operations/{id}/events"))
            .json(event)
            .send()
    };
    let original_for_replay = original.clone();
    let mut active_secret = original;
    for (action, finish) in [
        (Action::Verify, true),
        (Action::Rotate, true),
        (Action::Rotate, false),
    ] {
        let request = Request {
            policy_version: versions[usize::from(action == Action::Rotate)],
            operation_id: Uuid::new_v4(),
            binding_id: binding.id,
            binding_generation: binding.generation,
            replaces: None,
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
            peer.post(format!("{base}/credential-operations/next"))
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
        let progress: CredentialSettlement =
            material::success(native(request.operation_id, &event).await?).await?;
        assert_eq!(progress.state, State::PendingApplication);
        if action == Action::Rotate && active_secret == original_for_replay {
            let response = reveal(operation, true).await?;
            assert_eq!(response.status(), 409);
            assert!(response.json::<Value>().await?.get("secret").is_none());
        }
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
        let confirmed: CredentialSettlement = material::success(
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

#[allow(
    clippy::too_many_arguments,
    reason = "the two authenticated transports and the original eligible binding are shared with the live host proof"
)]
async fn reconcile(
    c: &Context,
    client: &reqwest::Client,
    peer: &reqwest::Client,
    base: &str,
    url: &str,
    binding: &access::Binding,
    guardian: &str,
    original: &str,
    versions: [Uuid; 2],
) -> Result<()> {
    let path = format!("{url}/credential-operations");
    let first = material::administrator(c).await?;
    let second = material::administrator(c).await?;
    let revoked = |raw: String| async move {
        let principal = c
            .authority
            .inspect_bearer(
                c.execution(),
                BearerSecret::parse(raw)?,
                platform::deadline(),
            )
            .await?
            .account()
            .principal
            .as_uuid();
        let rows=sqlx::query("DELETE FROM rss_da.authorization_rules WHERE tenant_id=$1::uuid AND document::text LIKE '%' || $2 || '%'").bind(c.tenant.to_string()).bind(principal.to_string()).execute(&c.operator).await?.rows_affected();
        anyhow::ensure!(rows == 1);
        Ok::<_, anyhow::Error>(())
    };
    let request = |action, replaces| Request {
        policy_version: versions[usize::from(action == Action::Rotate)],
        operation_id: Uuid::new_v4(),
        binding_id: binding.id,
        binding_generation: binding.generation,
        action,
        replaces,
    };
    let post =
        |token: &str, input: &Request| client.post(&path).bearer_auth(token).json(input).send();
    let get = |id| {
        client
            .get(format!("{path}/{id}"))
            .bearer_auth(guardian)
            .send()
    };
    let next = || {
        peer.post(format!("{base}/credential-operations/next"))
            .send()
    };
    let event = |id, input: &Event| {
        peer.post(format!("{base}/credential-operations/{id}/events"))
            .json(input)
            .send()
    };
    let policy_path = format!("{url}/credential-policies");
    let mut policy: Value = material::success(
        client
            .get(format!("{policy_path}/{}", versions[1]))
            .bearer_auth(guardian)
            .send()
            .await?,
    )
    .await?;
    let temporary = Uuid::new_v4();
    policy["id"] = json!(Uuid::new_v4());
    policy["version"] = json!(temporary);
    let publish = |v: &Value| {
        client
            .post(&policy_path)
            .bearer_auth(guardian)
            .json(v)
            .send()
    };
    let _: Value = material::success(publish(&policy).await?).await?;
    let mut unclaimed = request(Action::Rotate, None);
    unclaimed.policy_version = temporary;
    let mut denied = unclaimed.clone();
    denied.policy_version = Uuid::new_v4();
    assert_eq!(post(&first, &denied).await?.status(), 403);
    denied.policy_version = versions[usize::from(denied.action != Action::Rotate)];
    assert_eq!(post(&first, &denied).await?.status(), 403);
    material::success::<Status>(post(&first, &unclaimed).await?).await?;
    policy["version"] = json!(Uuid::new_v4());
    policy["revision"] = json!(2);
    policy["enabled"] = json!(false);
    let _: Value = material::success(publish(&policy).await?).await?;
    assert_eq!(next().await?.status(), 403);
    revoked(first).await?;
    assert_eq!(next().await?.status(), 403);
    let rotate = request(Action::Rotate, Some(unclaimed.operation_id));
    material::success::<Status>(post(&second, &rotate).await?).await?;
    assert_eq!(
        material::success::<Status>(get(unclaimed.operation_id).await?)
            .await?
            .state,
        State::Superseded
    );
    let task: w::CredentialTaskSpec = material::success(next().await?).await?;
    let candidate = URL_SAFE_NO_PAD.encode([87; 32]);
    let escrow = Event::Escrow {
        attempt_id: task.attempt_id,
        value: envelope(&task, &task.expected[0].subject, &candidate)?,
    };
    let result: CredentialSettlement =
        material::success(event(rotate.operation_id, &escrow).await?).await?;
    let previous = result.receipt.context("candidate retained")?;
    revoked(second).await?;
    let old_apply = Event::Applied {
        attempt_id: task.attempt_id,
        definition_digest: task.definition_digest,
        receipt: previous.clone(),
    };
    assert_eq!(event(rotate.operation_id, &old_apply).await?.status(), 403);
    assert_eq!(
        post(
            guardian,
            &request(Action::Rotate, Some(rotate.operation_id))
        )
        .await?
        .status(),
        409
    );
    let verify = request(Action::Verify, Some(rotate.operation_id));
    let accepted: Status = material::success(post(guardian, &verify).await?).await?;
    assert_eq!(accepted.state, State::Accepted);
    let spec: w::CredentialTaskSpec = material::success(next().await?).await?;
    assert_eq!(
        spec.recovery,
        Some(w::CredentialRecovery {
            task_id: task.task_id,
            attempt_id: task.attempt_id
        })
    );
    let readback = Event::Escrow {
        attempt_id: spec.attempt_id,
        value: envelope(&spec, &spec.expected[0].subject, original)?,
    };
    let result: CredentialSettlement =
        material::success(event(verify.operation_id, &readback).await?).await?;
    let ack = Event::Applied {
        attempt_id: spec.attempt_id,
        definition_digest: spec.definition_digest,
        receipt: result.receipt.context("verified predecessor")?,
    };
    for _ in 0..2 {
        assert_eq!(
            material::success::<CredentialSettlement>(event(verify.operation_id, &ack).await?)
                .await?
                .state,
            State::Applied
        );
    }
    let result: Status = material::success(get(rotate.operation_id).await?).await?;
    assert_eq!(result.state, State::Unchanged);
    assert_eq!(result.receipt, Some(previous));
    Ok(())
}
