//! Standalone Mac consumer of the mounted DA contract, with no recovery provider.
use super::*;

pub(in crate::foundation) async fn verify(
    c: &Context,
    m: &material::Material,
    runtime_file: &std::path::Path,
    base: &str,
    other_device: &reqwest::Client,
) -> Result<()> {
    let mut config = rss_da_app::config::load(runtime_file)?;
    config.recovery = None;
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let host = tokio::spawn(rss_da_app::host::serve(config, async move {
        stopped.await.map_err(std::io::Error::other)
    }));
    let result = Box::pin(scenario(c, m, base, other_device)).await;
    let _ = stop.send(());
    tokio::time::timeout(Duration::from_secs(50), host).await???;
    result
}

async fn assign(
    c: &Context,
    client: &reqwest::Client,
    r: &da::Registration,
    admin: &Manager,
    binding: Uuid,
    policy: Uuid,
    name: &str,
) -> Result<Uuid> {
    let person = rss_mdm_device_access::Person {
        instance: r.service_id,
        principal: admin.principal,
    };
    let intent = rss_mdm_device_access::AccountIntent::Create {
        platform: w::TaskPlatform::Macos,
        name: name.into(),
    };
    let op = Uuid::new_v4();
    let body = json!({"kind":"put","instance":person.instance,"principal":person.principal,"account":intent,"policy":policy});
    admin
        .change(
            c,
            client,
            r,
            binding,
            access::Change {
                operation_id: op,
                expected_revision: 0,
                action: access::Action::Put {
                    person,
                    intent,
                    policy,
                },
            },
            body,
        )
        .await?;
    Ok(op)
}

async fn unlink(
    c: &Context,
    client: &reqwest::Client,
    r: &da::Registration,
    admin: &Manager,
    binding: Uuid,
) -> Result<Uuid> {
    let id = Uuid::new_v4();
    admin
        .change(
            c,
            client,
            r,
            binding,
            access::Change {
                operation_id: id,
                expected_revision: 1,
                action: access::Action::Unbind {
                    disposition: w::AccessAccountDisposition::Keep,
                },
            },
            json!({"kind":"unbind","disposition":"keep"}),
        )
        .await?;
    Ok(id)
}

fn report(t: &w::AccessTaskSpec, effect: w::AccessEffect) -> da::AccountObservation {
    da::AccountObservation::Result(w::AccessResult {
        binding_id: t.binding_id,
        binding_generation: t.binding_generation,
        revision: t.revision,
        definition_digest: t.definition_digest,
        effect,
    })
}

async fn scenario(
    c: &Context,
    m: &material::Material,
    base: &str,
    other_device: &reqwest::Client,
) -> Result<()> {
    let client = m.client(None)?;
    let trust = format!("{base}/pki/trust?tenantId={}", c.tenant);
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if client
                .get(&trust)
                .send()
                .await
                .is_ok_and(|r| r.status().is_success())
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .context("start the DA host without custody")?;
    let token = material::administrator(c).await?;
    let (r, peer) = activate_grant(
        m,
        &client,
        client
            .post(format!("{}/grants", c.management_base()))
            .bearer_auth(token),
        base,
        2,
    )
    .await?;
    let mut tx = c.seed().await?;
    let standalone:bool=sqlx::query_scalar("SELECT to_regclass('mdm_agent.bindings') IS NULL AND NOT EXISTS(SELECT FROM rss_da.agent_delivery WHERE da_device=$1)").bind(r.device.into_uuid()).fetch_one(&mut *tx).await?;
    assert!(standalone);
    let mut policy = da::Publication {
        id: Uuid::new_v4(),
        version: Uuid::new_v4(),
        revision: 1,
        enabled: true,
        target: da::Target::Device { device: r.device },
        managed_fields: vec![],
        configuration: w::AccessConfiguration {
            mac: Some(Default::default()),
            role: None,
            enabled: true,
            self_enrollment: false,
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
    let a = Box::pin(Manager::new(c, &client)).await?;
    let b = Box::pin(Manager::new(c, &client)).await?;
    let id_a = Uuid::new_v4();
    let id_b = Uuid::new_v4();
    let (left, right) = tokio::join!(
        Box::pin(assign(c, &client, &r, &a, id_a, policy.id, "LocalUser")),
        Box::pin(assign(c, &client, &r, &b, id_b, policy.id, "localuser"))
    );
    let (owner, binding, op, error) = match (left, right) {
        (Ok(op), Err(error)) => (&a, id_a, op, error),
        (Err(error), Ok(op)) => (&b, id_b, op, error),
        other => anyhow::bail!("unexpected concurrent create outcomes {other:?}"),
    };
    assert!(error.to_string().contains("HTTP 409"), "{error:#}");
    let next = || peer.post(format!("{base}/account-operations/next")).send();
    let offer: da::AccountOffer = material::success(next().await?).await?;
    assert_eq!(offer, material::success(next().await?).await?);
    assert_eq!((offer.operation_id, offer.binding_id), (op, binding));
    let url = format!("{base}/account-operations/{}/events", offer.task_id);
    let ack = da::AccountEvent {
        event_id: Uuid::new_v4(),
        attempt_id: offer.attempt_id,
        definition_digest: offer.definition_digest,
        event: da::AccountObservation::Received,
    };
    assert_eq!(
        other_device.post(&url).json(&ack).send().await?.status(),
        404
    );
    for incorrect in [
        da::AccountEvent {
            attempt_id: Uuid::new_v4(),
            ..ack.clone()
        },
        da::AccountEvent {
            definition_digest: [9; 32],
            ..ack.clone()
        },
    ] {
        assert_eq!(peer.post(&url).json(&incorrect).send().await?.status(), 409);
    }
    let t = material::success::<da::AccountSettlement>(peer.post(&url).json(&ack).send().await?)
        .await?
        .permit
        .context("Mac Start")?;
    assert_eq!(
        (
            t.tenant_id,
            t.device_id,
            t.principal_id,
            t.binding_generation,
            t.revision
        ),
        (r.tenant, r.device, owner.principal, 1, 1)
    );
    assert_eq!(
        (t.platform, t.architecture, t.permit),
        (
            w::TaskPlatform::Macos,
            w::TaskArchitecture::Aarch64,
            w::TaskPermit::Start
        )
    );
    assert!(matches!(t.action, w::AccessAction::Create { .. }) && t.windows.is_none());
    let progress = |id, admin: &Manager| {
        client
            .get(format!(
                "{}/api/v1/tenants/{}/devices/{}/device-access/operations/{id}/execution",
                c.browser_origin, r.tenant, r.device
            ))
            .header("cookie", &admin.cookie)
            .send()
    };
    let received: Value = material::success(progress(op, owner).await?).await?;
    assert_eq!(received["received"], true);
    assert!(received["effect"].is_null());
    observe(&peer, base, &offer, report(&t, w::AccessEffect::Unknown)).await?;
    let uncertain: Value = material::success(progress(op, owner).await?).await?;
    assert_eq!(uncertain["execution"], "unknown");
    assert_eq!(offer, material::success(next().await?).await?);
    let cleanup = unlink(c, &client, &r, owner, binding).await?;
    let replay: da::AccountSettlement =
        material::success(peer.post(&url).json(&ack).send().await?).await?;
    assert!(replay.permit.is_none());
    let other = Box::pin(Manager::new(c, &client)).await?;
    let blocked = assign(
        c,
        &client,
        &r,
        &other,
        Uuid::new_v4(),
        policy.id,
        "LOCALUSER",
    )
    .await
    .unwrap_err();
    assert!(blocked.to_string().contains("HTTP 409"), "{blocked:#}");
    let uid = Uuid::new_v4();
    let created = |uid, role| w::AccessEffect::MacAccountCreated {
        generated_uid: uid,
        role,
        secure_token: w::AccessObservation::Unknown,
        volume_owner: w::AccessObservation::Absent,
        filevault_unlock: w::AccessObservation::NeedsAdministrator,
    };
    let evidence = da::AccountEvent {
        event_id: Uuid::new_v4(),
        event: report(&t, created(uid, w::AccessRole::Standard)),
        ..ack.clone()
    };
    let business_before = business::counts(c).await?.2;
    assert!(
        peer.post(&url)
            .json(&evidence)
            .send()
            .await?
            .status()
            .is_success()
    );
    let lost: da::AccountSettlement =
        material::success(peer.post(&url).json(&evidence).send().await?).await?;
    assert_eq!(lost.event_id, evidence.event_id);
    assert_eq!(business::counts(c).await?.2, business_before + 1);
    let changed = da::AccountEvent {
        event: report(&t, created(Uuid::new_v4(), w::AccessRole::Standard)),
        ..evidence
    };
    assert_eq!(peer.post(&url).json(&changed).send().await?.status(), 409);
    let settled: Value = material::success(progress(op, owner).await?).await?;
    assert_eq!(settled["execution"], "succeeded");
    assert_eq!(settled["effect"]["generatedUid"], json!(uid));
    assert_eq!(settled["effect"]["volumeOwner"], "absent");
    let n:i64=sqlx::query_scalar("SELECT count(*) FROM rss_da.results WHERE task=$1 AND document#>>'{effect,state}'='mac_account_created'").bind(t.task_id).fetch_one(&c.operator).await?;
    assert_eq!(n, 1);
    let clean_offer: da::AccountOffer = material::success(next().await?).await?;
    assert_eq!(clean_offer.operation_id, cleanup);
    let clean = observe(&peer, base, &clean_offer, da::AccountObservation::Received)
        .await?
        .permit
        .context("cleanup for late Created")?;
    assert!(
        matches!(clean.action,w::AccessAction::Unbind{account:w::AccessAccount::Macos{generated_uid},..} if generated_uid==uid)
    );
    observe(
        &peer,
        base,
        &clean_offer,
        report(
            &clean,
            w::AccessEffect::Unbound {
                disposition: w::AccessAccountDisposition::Keep,
            },
        ),
    )
    .await?;
    let finished: Value = material::success(progress(cleanup, owner).await?).await?;
    assert_eq!(finished["cleanupPending"], false);
    // A known creation with wrong privilege stays observable without enabling login.
    let id = Uuid::new_v4();
    let op = assign(c, &client, &r, &other, id, policy.id, "LocalUser").await?;
    let offer: da::AccountOffer = material::success(next().await?).await?;
    let t = observe(&peer, base, &offer, da::AccountObservation::Received)
        .await?
        .permit
        .context("new create")?;
    let uid = Uuid::new_v4();
    observe(
        &peer,
        base,
        &offer,
        report(&t, created(uid, w::AccessRole::Administrator)),
    )
    .await?;
    let known: Value = material::success(progress(op, &other).await?).await?;
    assert_eq!(known["execution"], "failed");
    assert_eq!(known["effect"]["generatedUid"], json!(uid));
    let binding: Value = sqlx::query_scalar("SELECT document FROM rss_da.bindings WHERE id=$1")
        .bind(id)
        .fetch_one(&c.operator)
        .await?;
    assert_eq!(binding["account"]["generatedUid"], json!(uid));
    assert!(binding["appliedRevision"].is_null());
    assert_eq!(binding["state"], "pending");
    let denying = Box::pin(Manager::new(c, &client)).await?;
    let id = Uuid::new_v4();
    let op = assign(c, &client, &r, &denying, id, policy.id, "collision").await?;
    let offer: da::AccountOffer = material::success(next().await?).await?;
    let t = observe(&peer, base, &offer, da::AccountObservation::Received)
        .await?
        .permit
        .context("attempt before policy revision")?;
    policy.version = Uuid::new_v4();
    policy.revision += 1;
    let mut tx = c.seed().await?;
    rss_mdm_policy_postgres::device_access::publish_on(
        &mut tx,
        r.tenant,
        &policy,
        1,
        json!({"kind":"system"}),
        now(),
    )
    .await?;
    tx.commit().await?;
    let stale = peer
        .post(format!(
            "{base}/account-operations/{}/events",
            offer.task_id
        ))
        .json(&da::AccountEvent {
            event_id: Uuid::new_v4(),
            attempt_id: offer.attempt_id,
            definition_digest: offer.definition_digest,
            event: da::AccountObservation::Received,
        })
        .send()
        .await?;
    assert_eq!(stale.status(), 403);
    observe(
        &peer,
        base,
        &offer,
        report(
            &t,
            w::AccessEffect::Failed {
                reason: w::AccessFailure::NameConflict,
            },
        ),
    )
    .await?;
    let denied: Value = material::success(progress(op, &denying).await?).await?;
    assert_eq!(denied["effect"]["reason"], "name_conflict");
    let unlink_op = unlink(c, &client, &r, &denying, id).await?;
    let done: Value = material::success(progress(unlink_op, &denying).await?).await?;
    assert_eq!(done["cleanupPending"], false);
    Ok(())
}
