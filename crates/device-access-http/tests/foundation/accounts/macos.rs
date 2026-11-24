//! Standalone Mac consumer of the mounted DA contract, with no recovery provider.
use super::*;

pub(in crate::foundation) async fn verify(
    c: &Context,
    m: &material::Material,
    runtime_file: &std::path::Path,
    base: &str,
    other_device: &reqwest::Client,
) -> Result<()> {
    let mut config: rss_da_app::config::Config = rss_da_app::config::load(runtime_file)?;
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

fn report(t: &w::AccessTaskSpec, effect: impl Into<da::AccountEffect>) -> da::AccountObservation {
    da::AccountObservation::Result(w::AccessResult {
        binding_id: t.binding_id,
        binding_generation: t.binding_generation,
        revision: t.revision,
        definition_digest: t.definition_digest,
        effect: effect.into(),
    })
}

// Exercise the shared Applied projection without fabricating a PSSO deployment receipt.
async fn reject_premature_application(
    c: &Context,
    t: &w::AccessTaskSpec,
    uid: Uuid,
    role: w::AccessRole,
) -> Result<()> {
    let effect = w::AccessEffect::Applied {
        account: w::AccessAccount::Macos { generated_uid: uid },
        role,
        mac: Some(w::AccessMacFacts {
            secure_token: w::AccessObservation::Present,
            volume_owner: w::AccessObservation::Present,
            filevault_unlock: w::AccessObservation::Present,
            platform_sso: None,
        }),
        windows: None,
    };
    let da::AccountObservation::Result(result) = report(t, effect.clone()) else {
        unreachable!()
    };
    let mut tx = c.seed().await?;
    assert!(matches!(
        access::storage::result_in(
            &mut tx,
            t.tenant_id,
            t.task_id,
            t.attempt_id,
            Uuid::new_v4(),
            &result.with_effect(effect),
            true
        )
        .await,
        Err(rss_mdm_device_access_postgres::Error::Conflict)
    ));
    tx.rollback().await?;
    Ok(())
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
    let poll = |platform| {
        peer.post(format!("{base}/account-operations/next"))
            .query(&da::AccountClaim { platform })
            .send()
    };
    let next = || poll(w::TaskPlatform::Macos);
    assert!(
        material::success::<Option<da::AccountOffer>>(
            peer.post(format!("{base}/account-operations/next"))
                .send()
                .await?
        )
        .await?
        .is_none()
    );
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
    let mut foreign = c.access.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(Uuid::new_v4().to_string())
        .execute(&mut *foreign)
        .await?;
    let visible: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT FROM rss_da.access_runs WHERE id=$1)")
            .bind(offer.task_id)
            .fetch_one(&mut *foreign)
            .await?;
    assert!(!visible);
    foreign.rollback().await?;
    // The same live TLS peer must not act on a run frozen for another registration epoch.
    let target: Value = sqlx::query_scalar("SELECT da_target FROM rss_da.access_runs WHERE id=$1")
        .bind(offer.task_id)
        .fetch_one(&c.operator)
        .await?;
    sqlx::query("UPDATE rss_da.access_runs SET da_target=jsonb_set(da_target,'{epoch}',to_jsonb($2::uuid)) WHERE id=$1")
        .bind(offer.task_id).bind(Uuid::new_v4()).execute(&c.operator).await?;
    assert!(
        material::success::<Option<da::AccountOffer>>(next().await?)
            .await?
            .is_none()
    );
    assert_eq!(peer.post(&url).json(&ack).send().await?.status(), 403);
    sqlx::query("UPDATE rss_da.access_runs SET da_target=$2 WHERE id=$1")
        .bind(offer.task_id)
        .bind(target)
        .execute(&c.operator)
        .await?;
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
    assert!(
        matches!(&t.action, w::AccessAction::Create { name, configuration } if name == if binding == id_a { "LocalUser" } else { "localuser" } && configuration == &policy.configuration)
    );
    assert!(
        matches!(t.authorization,w::TaskAuthorization::Policy {policy_id,policy_version} if (policy_id,policy_version)==(policy.id,policy.version))
    );
    assert!(t.windows.is_none());
    reject_premature_application(c, &t, Uuid::new_v4(), w::AccessRole::Standard).await?;
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
    let active: da::AccountSettlement =
        material::success(peer.post(&url).json(&ack).send().await?).await?;
    assert_eq!(active.permit.as_ref(), Some(&t));
    let cleanup = unlink(c, &client, &r, owner, binding).await?;
    let replay: da::AccountSettlement =
        material::success(peer.post(&url).json(&ack).send().await?).await?;
    assert!(replay.permit.is_none());
    observe(&peer, base, &offer, report(&t, w::AccessEffect::Unknown)).await?;
    let uncertain: Value = material::success(progress(op, owner).await?).await?;
    assert_eq!(uncertain["execution"], "unknown");
    assert_eq!(offer, material::success(next().await?).await?);
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
    // The UID is still unknown to the original operation. A separate binding was established
    // before its delayed journal arrived. Preserve the report but withhold cleanup authority.
    let existing_owner = Box::pin(Manager::new(c, &client)).await?;
    let existing_id = Uuid::new_v4();
    let created = |uid, role| da::AccountEffect::MacAccountCreated {
        generated_uid: uid,
        role,
        secure_token: w::AccessObservation::Unknown,
        volume_owner: w::AccessObservation::Absent,
        filevault_unlock: w::AccessObservation::NeedsAdministrator,
    };
    let known = Box::pin(assign(
        c,
        &client,
        &r,
        &existing_owner,
        existing_id,
        policy.id,
        "currentuser",
    ))
    .await?;
    let second: da::AccountOffer = material::success(next().await?).await?;
    assert_eq!(second.operation_id, known);
    let second_start = observe(&peer, base, &second, da::AccountObservation::Received)
        .await?
        .permit
        .context("second direct creation")?;
    observe(
        &peer,
        base,
        &second,
        report(&second_start, created(uid, w::AccessRole::Standard)),
    )
    .await?;
    let evidence = da::AccountEvent {
        event_id: Uuid::new_v4(),
        event: report(&t, created(uid, w::AccessRole::Standard)),
        ..ack.clone()
    };
    let before = business::counts(c).await?;
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
    let after = business::counts(c).await?;
    assert_eq!((after.2, after.3), (before.2 + 1, before.3 + 1));
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
    assert!(
        material::success::<Option<da::AccountOffer>>(next().await?)
            .await?
            .is_none()
    );
    let other_cleanup = Uuid::new_v4();
    Box::pin(existing_owner.change(
        c,
        &client,
        &r,
        existing_id,
        access::Change {
            operation_id: other_cleanup,
            expected_revision: 1,
            action: access::Action::Unbind {
                disposition: w::AccessAccountDisposition::Disable,
            },
        },
        json!({"kind":"unbind","disposition":"disable"}),
    ))
    .await?;
    let denied: Value = material::success(progress(other_cleanup, &existing_owner).await?).await?;
    assert_eq!(denied["execution"], "failed");
    assert_eq!(denied["cleanupPending"], true);

    let clean_offer: da::AccountOffer = material::success(next().await?).await?;
    assert_eq!(clean_offer.operation_id, cleanup);
    let clean = observe(&peer, base, &clean_offer, da::AccountObservation::Received)
        .await?
        .permit
        .context("cleanup for late Created")?;
    assert!(
        matches!(clean.action,w::AccessAction::Unbind{account:w::AccessAccount::Macos{generated_uid},disposition:w::AccessAccountDisposition::Keep} if generated_uid==uid)
    );
    // The original cleanup is now permitted. A later Create with a different name
    // cannot acquire the same UID until that disposition is complete.
    let competing = Uuid::new_v4();
    let competing_op = Box::pin(assign(
        c,
        &client,
        &r,
        &other,
        competing,
        policy.id,
        "differentname",
    ))
    .await?;
    let contender: da::AccountOffer = material::success(next().await?).await?;
    assert_eq!(contender.operation_id, competing_op);
    let start = observe(&peer, base, &contender, da::AccountObservation::Received)
        .await?
        .permit
        .context("competing create")?;
    observe(
        &peer,
        base,
        &contender,
        report(&start, created(uid, w::AccessRole::Standard)),
    )
    .await?;
    let conflict: Value = material::success(progress(competing_op, &other).await?).await?;
    assert_eq!(conflict["execution"], "failed");
    assert_eq!(conflict["effect"]["generatedUid"], json!(uid));
    let unclaimed: bool =
        sqlx::query_scalar("SELECT account IS NULL FROM rss_da.bindings WHERE id=$1")
            .bind(competing)
            .fetch_one(&c.operator)
            .await?;
    assert!(unclaimed);
    let redundant = Box::pin(unlink(c, &client, &r, &other, competing)).await?;
    let redundant: Value = material::success(progress(redundant, &other).await?).await?;
    assert_eq!(redundant["cleanupPending"], false);
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
    assert!(
        material::success::<Option<da::AccountOffer>>(next().await?)
            .await?
            .is_none()
    );
    let unfulfilled: Value =
        material::success(progress(other_cleanup, &existing_owner).await?).await?;
    assert_eq!(unfulfilled["cleanupPending"], true);
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
    reject_premature_application(c, &t, uid, w::AccessRole::Administrator).await?;
    let denying = Box::pin(Manager::new(c, &client)).await?;
    let id = Uuid::new_v4();
    let op = assign(c, &client, &r, &denying, id, policy.id, "collision").await?;
    let offer: da::AccountOffer = material::success(next().await?).await?;
    let grant = observe(&peer, base, &offer, da::AccountObservation::Received).await?;
    let t = grant.permit.context("attempt before policy revision")?;
    let replay_ack = da::AccountEvent {
        event_id: grant.event_id,
        attempt_id: offer.attempt_id,
        definition_digest: offer.definition_digest,
        event: da::AccountObservation::Received,
    };
    let target = format!("{base}/account-operations/{}/events", offer.task_id);
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
    let withdrawn: da::AccountSettlement =
        material::success(peer.post(&target).json(&replay_ack).send().await?).await?;
    assert!(withdrawn.permit.is_none());
    assert_eq!(withdrawn.issued_expires_at, Some(t.expires_at));
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
    let unstarted_id = Uuid::new_v4();
    Box::pin(assign(
        c,
        &client,
        &r,
        &denying,
        unstarted_id,
        policy.id,
        "offline",
    ))
    .await?;
    let original: da::AccountOffer = material::success(next().await?).await?;
    let original_permit = observe(&peer, base, &original, da::AccountObservation::Received).await?;
    let expiry = expire_permit(c, original.task_id, original_permit.event_id).await?;
    let mut tx = c.seed().await?;
    policy.revision += 1;
    policy.version = Uuid::new_v4();
    rss_mdm_policy_postgres::device_access::publish_on(
        &mut tx,
        r.tenant,
        &policy,
        2,
        json!({"kind":"system"}),
        now(),
    )
    .await?;
    tx.commit().await?;
    let closed = observe(
        &peer,
        base,
        &original,
        da::AccountObservation::NotStarted { expires_at: expiry },
    )
    .await?;
    assert!(closed.permit.is_none() && closed.issued_expires_at.is_none());
    assert!(
        material::success::<Option<da::AccountOffer>>(next().await?)
            .await?
            .is_none()
    );
    let person = rss_mdm_device_access::Person {
        instance: r.service_id,
        principal: denying.principal,
    };
    let intent = rss_mdm_device_access::AccountIntent::Create {
        platform: w::TaskPlatform::Macos,
        name: "offline".into(),
    };
    let body = json!({"kind":"put","instance":person.instance,"principal":person.principal,"account":intent,"policy":policy.id});
    let revised = Uuid::new_v4();
    Box::pin(denying.change(
        c,
        &client,
        &r,
        unstarted_id,
        access::Change {
            operation_id: revised,
            expected_revision: 1,
            action: access::Action::Put {
                person,
                intent,
                policy: policy.id,
            },
        },
        body,
    ))
    .await?;
    let replacement: da::AccountOffer = material::success(next().await?).await?;
    assert_eq!(replacement.operation_id, revised);
    assert_ne!(replacement.attempt_id, original.attempt_id);
    Ok(())
}
