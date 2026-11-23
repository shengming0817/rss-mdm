//! mTLS account consumer on an installation with no Agent schema or delivery relationship.
use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rss_identity_core::session::{BearerSecret, SessionSecret};
use rss_mdm_agent_wire::{da, runtime as w};
use rss_mdm_device_access_postgres::device_access as access;
use rss_mdm_recovery_credentials::tasks::device::{Action, Request, State, Status};
use serde_json::{Value, json};

struct Manager {
    principal: Uuid,
    cookie: String,
    csrf: String,
}
impl Manager {
    async fn new(c: &Context, client: &reqwest::Client) -> Result<Self> {
        let token = material::administrator(c).await?;
        let principal = c
            .authority
            .inspect_bearer(
                c.execution(),
                BearerSecret::parse(token)?,
                platform::deadline(),
            )
            .await?
            .account()
            .principal
            .as_uuid();
        let (cookie, csrf) = credentials::login(c, client, principal).await?;
        Ok(Self {
            principal,
            cookie,
            csrf,
        })
    }
    async fn change(
        &self,
        c: &Context,
        client: &reqwest::Client,
        r: &da::Registration,
        binding: Uuid,
        change: access::Change,
        action: Value,
    ) -> Result<()> {
        let session = SessionSecret::parse(self.cookie.split_once('=').unwrap().1.to_owned())?;
        let p = c
            .sessions
            .authenticate(
                c.execution(),
                &c.authorization,
                rss_mdm_authorization_service::credential::RequestCredential::Cookie(
                    SessionSecret::parse(session.expose().to_owned())?,
                ),
                platform::deadline(),
            )
            .await?;
        let proof = Box::pin(business::operation_proof(
            c,
            &session,
            change.step_up_context(&p, &r.device, binding, &Default::default())?,
        ))
        .await?;
        let result:Value=material::success(client.put(format!("{}/api/v1/tenants/{}/devices/{}/device-access/bindings/{binding}",c.browser_origin,c.tenant,r.device))
            .header("cookie",format!("{}; __Host-identity-operation={}",self.cookie,proof.expose())).header("origin",&c.browser_origin)
            .header("x-csrf-token",&self.csrf).header("x-identity-request","1")
            .json(&json!({"operationId":change.operation_id,"expectedRevision":change.expected_revision,"action":action})).send().await?).await?;
        assert_eq!(result["operationId"], json!(change.operation_id));
        Ok(())
    }
}
async fn observe(
    peer: &reqwest::Client,
    base: &str,
    offer: &da::AccountOffer,
    event: da::AccountObservation,
) -> Result<da::AccountSettlement> {
    let event = da::AccountEvent {
        event_id: Uuid::new_v4(),
        attempt_id: offer.attempt_id,
        definition_digest: offer.definition_digest,
        event,
    };
    let send = || {
        peer.post(format!(
            "{base}/account-operations/{}/events",
            offer.task_id
        ))
        .json(&event)
        .send()
    };
    let first: da::AccountSettlement = material::success(send().await?).await?;
    let retry: da::AccountSettlement = material::success(send().await?).await?;
    assert_eq!(retry.permit, first.permit);
    assert_eq!(retry.receipt, first.receipt);
    assert_eq!(retry.event_id, event.event_id);
    Ok(first)
}
pub(super) async fn verify(
    c: &Context,
    m: &material::Material,
    client: &reqwest::Client,
    base: &str,
    token: &str,
    wrong: &reqwest::Client,
) -> Result<()> {
    let (r, peer) = activate_grant(
        m,
        client,
        client
            .post(format!("{}/grants", c.management_base()))
            .bearer_auth(token),
        base,
        2,
    )
    .await?;
    let admin = Manager::new(c, client).await?;
    let management = format!(
        "{}/api/v1/tenants/{}/devices/{}/device-access",
        c.browser_origin, c.tenant, r.device
    );
    let mut tx = c.seed().await?;
    let independent:bool=sqlx::query_scalar("SELECT to_regclass('mdm_agent.bindings') IS NULL AND NOT EXISTS(SELECT FROM rss_da.agent_delivery WHERE da_device=$1)").bind(r.device.into_uuid()).fetch_one(&mut *tx).await?;
    assert!(independent);
    let recipient = rss_mdm_recovery_credentials::Recipient::from_pem(
        &std::fs::read(m.directory.join("recovery.pem"))?,
        &std::fs::read(m.directory.join("recovery.key"))?,
    )?;
    rss_mdm_recovery_credentials::Protection::select_on(DA, &mut tx, r.tenant, recipient.id())
        .await?;
    let policy = rss_mdm_policy_postgres::device_access::Publication {
        id: Uuid::new_v4(),
        version: Uuid::new_v4(),
        revision: 1,
        managed_fields: vec![],
        enabled: true,
        target: rss_mdm_policy_postgres::device_access::Target::Device { device: r.device },
        configuration: w::AccessConfiguration {
            self_enrollment: false,
            enabled: true,
            role: None,
            mac: None,
            windows: w::AccessWindowsConfiguration::RssFactor {
                accounts: vec![w::AccessWindowsKind::Local],
            },
        },
    };
    rss_mdm_policy_postgres::device_access::publish_on(
        &mut tx,
        r.tenant,
        &policy,
        0,
        json!({"kind":"system"}),
        now(),
    )
    .await?;
    tx.commit().await?;
    let account = w::AccessAccount::Windows {
        sid: "S-1-5-21-2-3-4-1002".into(),
        authority: w::AccessWindowsAuthority::Local,
    };
    let binding = Uuid::new_v4();
    let op = Uuid::new_v4();
    let intent = rss_mdm_device_access::AccountIntent::Existing {
        account: account.clone(),
    };
    let change = access::Change {
        operation_id: op,
        expected_revision: 0,
        action: access::Action::Put {
            person: rss_mdm_device_access::Person {
                instance: r.service_id,
                principal: admin.principal,
            },
            intent: intent.clone(),
            policy: policy.id,
        },
    };
    Box::pin(admin.change(c,client,&r,binding,change,json!({"kind":"put","instance":r.service_id,"principal":admin.principal,"account":intent,"policy":policy.id}))).await?;
    let progress = |operation: Uuid, cookie: &str| {
        client
            .get(format!("{management}/operations/{operation}/execution"))
            .header("cookie", cookie)
            .send()
    };
    let read: Value = material::success(progress(op, &admin.cookie).await?).await?;
    assert_eq!(read["received"], false);
    let next = || peer.post(format!("{base}/account-operations/next")).send();
    let offer: da::AccountOffer = material::success(next().await?).await?;
    assert_eq!(offer.operation_id, op);
    assert_eq!(
        offer,
        material::success::<da::AccountOffer>(next().await?).await?
    );
    assert_eq!(
        wrong
            .post(format!(
                "{base}/account-operations/{}/events",
                offer.task_id
            ))
            .json(&da::AccountEvent {
                event_id: Uuid::new_v4(),
                attempt_id: offer.attempt_id,
                definition_digest: offer.definition_digest,
                event: da::AccountObservation::Received
            })
            .send()
            .await?
            .status(),
        404
    );
    let task = observe(&peer, base, &offer, da::AccountObservation::Received)
        .await?
        .permit
        .context("current Start")?;
    task.validate()?;
    let read: Value = material::success(progress(op, &admin.cookie).await?).await?;
    assert_eq!(read["received"], true);
    assert!(read["effect"].is_null());
    let subject = w::CredentialSubject::RssLogin {
        binding,
        binding_generation: task.binding_generation,
        sid: "S-1-5-21-2-3-4-1002".into(),
    };
    let Some(w::AccessWindowsPlan::Initialize {
        recipient,
        expected_revision,
    }) = &task.windows
    else {
        anyhow::bail!("missing initialization")
    };
    let original = URL_SAFE_NO_PAD.encode([68; 32]);
    let payload = credentials::seal(
        task.definition_digest,
        &recipient.public_key,
        &subject,
        *expected_revision,
        &task.material_aad(&subject, *expected_revision)?,
        &original,
    )?;
    let receipt = observe(&peer, base, &offer, da::AccountObservation::Escrow(payload))
        .await?
        .receipt
        .context("first custody")?;
    let report = w::AccessResult {
        binding_id: binding,
        binding_generation: task.binding_generation,
        revision: task.revision,
        definition_digest: task.definition_digest,
        effect: w::AccessEffect::Applied {
            account,
            role: w::AccessRole::Standard,
            mac: None,
            windows: Some(w::AccessWindowsFacts::RssFactor(w::AccessRssFacts {
                factor_generation: task.factor_generation,
                recovery: receipt.clone(),
            })),
        },
    };
    let mut unknown = report.clone();
    unknown.effect = w::AccessEffect::Unknown;
    observe(&peer, base, &offer, da::AccountObservation::Result(unknown)).await?;
    let uncertain: Value = material::success(progress(op, &admin.cookie).await?).await?;
    assert_eq!(uncertain["execution"], "unknown");
    assert_eq!(
        material::success::<da::AccountOffer>(next().await?).await?,
        offer
    );
    observe(
        &peer,
        base,
        &offer,
        da::AccountObservation::Result(report.clone()),
    )
    .await?;
    let read: Value = material::success(progress(op, &admin.cookie).await?).await?;
    assert_eq!(read["execution"], "succeeded");
    for action in [Action::Verify, Action::Rotate] {
        let v = Uuid::new_v4();
        let now = now();
        let kind = if action == Action::Rotate {
            "rotate_rss_login"
        } else {
            "verify_rss_login"
        };
        let _:Value=material::success(client.post(format!("{management}/credential-policies")).bearer_auth(token).json(&json!({"id":Uuid::new_v4(),"version":v,"revision":1,"device":r.device,"operation":{"kind":kind,"binding":binding,"bindingGeneration":1,"sid":"S-1-5-21-2-3-4-1002"},"enabled":true,"notBefore":now-1,"expiresAt":now+3600,"runLifetimeSeconds":600})).send().await?).await?;
        let request = Request {
            operation_id: Uuid::new_v4(),
            policy_version: v,
            action,
            binding_id: binding,
            binding_generation: 1,
            replaces: None,
        };
        let _: Status = material::success(
            client
                .post(format!("{management}/credential-operations"))
                .bearer_auth(token)
                .json(&request)
                .send()
                .await?,
        )
        .await?;
        let spec: w::CredentialTaskSpec = material::success(
            peer.post(format!("{base}/credential-operations/next"))
                .send()
                .await?,
        )
        .await?;
        let send = |e: da::CredentialEvent| {
            peer.post(format!(
                "{base}/credential-operations/{}/events",
                request.operation_id
            ))
            .json(&e)
            .send()
        };
        let received: da::CredentialSettlement = material::success(
            send(da::CredentialEvent::Received {
                attempt_id: spec.attempt_id,
                definition_digest: spec.definition_digest,
            })
            .await?,
        )
        .await?;
        assert!(received.received_at.is_some());
        assert!(received.receipt.is_none());
        let secret = if action == Action::Verify {
            original.clone()
        } else {
            URL_SAFE_NO_PAD.encode([69; 32])
        };
        let escrow: da::CredentialSettlement = material::success(
            send(da::CredentialEvent::Escrow {
                attempt_id: spec.attempt_id,
                value: credentials::envelope(&spec, &subject, &secret)?,
            })
            .await?,
        )
        .await?;
        let settled: da::CredentialSettlement = material::success(
            send(da::CredentialEvent::Applied {
                attempt_id: spec.attempt_id,
                definition_digest: spec.definition_digest,
                receipt: escrow.receipt.context("custody")?,
            })
            .await?,
        )
        .await?;
        assert_eq!(settled.state, State::Applied);
    }
    let cleanup = Manager::new(c, client).await?;
    let unlink = Uuid::new_v4();
    let change = access::Change {
        operation_id: unlink,
        expected_revision: 1,
        action: access::Action::Unbind {
            disposition: w::AccessAccountDisposition::Keep,
        },
    };
    Box::pin(cleanup.change(
        c,
        client,
        &r,
        binding,
        change,
        json!({"kind":"unbind","disposition":"keep"}),
    ))
    .await?;
    let pending: Value = material::success(progress(unlink, &cleanup.cookie).await?).await?;
    assert_eq!(pending["cleanupPending"], true);
    assert_eq!(pending["received"], false);
    let late = da::AccountEvent {
        event_id: Uuid::new_v4(),
        attempt_id: offer.attempt_id,
        definition_digest: offer.definition_digest,
        event: da::AccountObservation::Result(report),
    };
    assert_eq!(
        peer.post(format!(
            "{base}/account-operations/{}/events",
            offer.task_id
        ))
        .json(&late)
        .send()
        .await?
        .status(),
        409
    );
    let offer: da::AccountOffer = material::success(next().await?).await?;
    let permit = observe(&peer, base, &offer, da::AccountObservation::Received)
        .await?
        .permit
        .context("unlink")?;
    let result = w::AccessResult {
        binding_id: binding,
        binding_generation: permit.binding_generation,
        revision: permit.revision,
        definition_digest: permit.definition_digest,
        effect: w::AccessEffect::Unbound {
            disposition: w::AccessAccountDisposition::Keep,
        },
    };
    observe(&peer, base, &offer, da::AccountObservation::Result(result)).await?;
    let completed: Value = material::success(progress(unlink, &cleanup.cookie).await?).await?;
    assert_eq!(completed["cleanupPending"], false);
    assert_eq!(completed["execution"], "succeeded");
    let previous: Value = material::success(progress(op, &admin.cookie).await?).await?;
    assert_eq!(read, previous);
    // A queued creation has never received permission to create a SID.
    let owner = Manager::new(c, client).await?;
    let pending_binding = Uuid::new_v4();
    let creation = rss_mdm_device_access::AccountIntent::Create {
        platform: w::TaskPlatform::Windows,
        name: "queueduser".into(),
    };
    let put = access::Change {
        operation_id: Uuid::new_v4(),
        expected_revision: 0,
        action: access::Action::Put {
            person: rss_mdm_device_access::Person {
                instance: r.service_id,
                principal: owner.principal,
            },
            intent: creation.clone(),
            policy: policy.id,
        },
    };
    Box::pin(owner.change(
        c,
        client,
        &r,
        pending_binding,
        put,
        json!({"kind":"put","instance":r.service_id,
        "principal":owner.principal,"account":creation,"policy":policy.id}),
    ))
    .await?;
    let remover = Manager::new(c, client).await?;
    let cancellation = Uuid::new_v4();
    let remove = access::Change {
        operation_id: cancellation,
        expected_revision: 1,
        action: access::Action::Unbind {
            disposition: w::AccessAccountDisposition::Keep,
        },
    };
    Box::pin(remover.change(
        c,
        client,
        &r,
        pending_binding,
        remove,
        json!({"kind":"unbind","disposition":"keep"}),
    ))
    .await?;
    let cancelled: Value =
        material::success(progress(cancellation, &remover.cookie).await?).await?;
    assert_eq!(cancelled["cleanupPending"], false);
    assert_eq!(cancelled["received"], false);
    assert_eq!(
        material::success::<Option<da::AccountOffer>>(next().await?).await?,
        None
    );
    Ok(())
}
