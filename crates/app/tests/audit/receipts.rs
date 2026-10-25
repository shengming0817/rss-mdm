use super::*;

async fn exercise(pool: &PgPool) -> Result<()> {
    let timer = crate::lifecycle::RuntimeTimer;
    let cancel = tokio_util::sync::CancellationToken::new();
    let deadline = Deadline::from_timeout(&timer, Duration::from_secs(10))?;
    let control = {
        let cutoff = deadline;
        SourceControl::new(&timer, cutoff, cutoff, &cancel)
    };
    let mode = Integrity::Plain;
    let tenant = TenantId::parse(&Uuid::new_v4().to_string())?;
    let store = new_store(pool.clone(), mode, tenant).await?;
    let request = RequestAudit::new(tenant.to_string(), "audit_recovery_test");
    request.set_principal("fixture-principal", crate::test_support::INSTANCE);
    let fact = Fact::business(
        &request,
        "stable-operation",
        b"request-A",
        200,
        "success",
        None,
    )?;
    let first = store
        .write(tenant, &control, (&store, &fact), |(store, fact), tx| {
            Box::pin(async move { store.append(tx, fact, false).await })
        })
        .await;
    ensure!(state(first) == "committed");
    let original = bytes(pool, tenant).await?;
    ensure!(original.len() == 1);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let replay = store
        .write(tenant, &control, (&store, &fact), |(store, fact), tx| {
            Box::pin(async move { store.append(tx, fact, true).await })
        })
        .await;
    ensure!(state(replay) == "committed");
    ensure!(bytes(pool, tenant).await? == original);
    // An absent business receipt cannot acquire a pre-existing audit fact.
    let inconsistent = store
        .write(tenant, &control, (&store, &fact), |(store, fact), tx| {
            Box::pin(async move { store.append(tx, fact, false).await })
        })
        .await;
    ensure!(inconsistent.fold(
        |_| false,
        |_| false,
        |e| matches!(e, TransactionError::Operation(Error::Receipt)),
        |_| false,
        |_| false,
        |_| false
    ));
    let changed = Fact::business(
        &request,
        "stable-operation",
        b"request-B",
        200,
        "success",
        None,
    )?;
    let conflict = store
        .write(tenant, &control, (&store, &changed), |(store, fact), tx| {
            Box::pin(async move { store.append(tx, fact, true).await })
        })
        .await;
    ensure!(conflict.fold(
        |_| false,
        |_| false,
        |e| matches!(e, TransactionError::Operation(Error::Receipt)),
        |_| false,
        |_| false,
        |_| false
    ));
    let missing = Fact::business(
        &request,
        "missing-operation",
        b"request-A",
        200,
        "success",
        None,
    )?;
    let missing = store
        .write(tenant, &control, (&store, &missing), |(store, fact), tx| {
            Box::pin(async move { store.append(tx, fact, true).await })
        })
        .await;
    ensure!(missing.fold(
        |_| false,
        |_| false,
        |e| matches!(e, TransactionError::Operation(Error::Receipt)),
        |_| false,
        |_| false,
        |_| false
    ));
    let rollback = Fact::business(
        &request,
        "rolled-back-operation",
        b"request-A",
        200,
        "success",
        None,
    )?;
    let rollback = store
        .write(
            tenant,
            &control,
            (&store, &rollback),
            |(store, fact), tx| {
                Box::pin(async move {
                    store.append(tx, fact, false).await?;
                    Err::<(), _>(Error::Receipt)
                })
            },
        )
        .await;
    ensure!(rollback.fold(
        |_| false,
        |_| false,
        |e| matches!(e, TransactionError::Operation(Error::Receipt)),
        |_| false,
        |_| false,
        |_| false
    ));
    ensure!(bytes(pool, tenant).await? == original);
    request.finalize(None);
    Ok(())
}

async fn retirement_batch(pool: &PgPool) -> Result<()> {
    let timer = crate::lifecycle::RuntimeTimer;
    let cancel = tokio_util::sync::CancellationToken::new();
    let tenant = TenantId::parse(&Uuid::new_v4().to_string())?;
    let store = new_store(pool.clone(), Integrity::Plain, tenant).await?;
    let request = RequestAudit::new(tenant.to_string(), "collection_finish");
    request.identify_service("service:collection-finalizer");
    let facts = (0..2)
        .map(|index| {
            Fact::business(
                &request,
                &format!("collection-{index}:finish"),
                b"retired",
                200,
                "success",
                None,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut original = None;
    for replayed in [false, true] {
        let control = {
            let cutoff = Deadline::from_timeout(&timer, Duration::from_secs(30))?;
            SourceControl::new(&timer, cutoff, cutoff, &cancel)
        };
        let attempt = store
            .write(tenant, &control, (&store, &facts), |(store, facts), tx| {
                Box::pin(async move {
                    for fact in facts.iter() {
                        store.append(tx, fact, replayed).await?;
                    }
                    Ok::<_, Error>(())
                })
            })
            .await;
        let outcome = state(attempt);
        ensure!(
            outcome == "committed",
            "retirement batch replay={replayed}: {outcome}"
        );
        let frozen = bytes(pool, tenant).await?;
        ensure!(frozen.len() == 2);
        if let Some(original) = &original {
            ensure!(&frozen == original);
        } else {
            original = Some(frozen);
        }
    }
    request.finalize(None);
    Ok(())
}

#[tokio::test]
#[ignore = "MODULE=audit.receipts: installed runtime roles, replay and atomicity"]
async fn receipts_and_retirement() -> Result<()> {
    for role in ROLES {
        let pool = pool(role).await?;
        exercise(&pool).await?;
        if role == "mdm_access" {
            retirement_batch(&pool).await?;
        }
        pool.close().await;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "MODULE=audit.receipts: source capacity rolls back business writes and projection restores admission"]
async fn backlog_reserve_and_projection_release_are_atomic() -> Result<()> {
    use rss_mdm_audit_integration::BacklogLimits;
    use rss_transactional_messaging::policy::OperationDeadline;
    let pool = pool("mdm_access").await?;
    let tenant = TenantId::parse(crate::test_support::case::tenant())?;
    let store = new_store_with_limits(
        pool.clone(),
        Integrity::Plain,
        tenant,
        BacklogLimits::new(2, 1_000_000)?,
    )
    .await?;
    let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(30));
    let request = RequestAudit::new(tenant.to_string(), "capacity_test");
    let normal = Fact::business(&request, "normal", b"normal", 200, "success", None)?;
    let denied = Fact::business(&request, "denied", b"denied", 403, "denied", None)?;
    let excess = Fact::business(&request, "excess", b"excess", 403, "denied", None)?;
    let write = store
        .write(
            tenant,
            &budget.source_control(),
            (&store, &normal),
            |(store, fact), tx| Box::pin(async move { store.append(tx, fact, false).await }),
        )
        .await;
    ensure!(state(write) == "committed");
    let before = store
        .backlog(
            tenant,
            OperationDeadline::from_remaining(Duration::from_secs(5)),
        )
        .await?;
    ensure!(before.events == 1 && before.source_bytes > 0 && before.admission_closed);
    let rejected = Fact::business(&request, "blocked", b"blocked", 200, "success", None)?;
    let blocked = store
        .write(
            tenant,
            &budget.source_control(),
            (&store, &rejected),
            |(store, fact), tx| {
                Box::pin(async move { recovery::crash_write(store, tx, fact).await })
            },
        )
        .await;
    ensure!(blocked.fold(
        |_| false,
        |_| false,
        |error| matches!(error, TransactionError::Operation(Error::BacklogFull)),
        |_| false,
        |_| false,
        |_| false
    ));
    let device_count = crate::planning::test_support::sql(&format!(
        "SELECT count(*) FROM mdm_access.devices WHERE tenant_id='{tenant}' AND id='crash-device'"
    ));
    ensure!(
        device_count == "0",
        "capacity rejection committed business mutation"
    );
    for (fact, expected) in [(&denied, "committed"), (&excess, "rolled_back")] {
        let result = store
            .write(
                tenant,
                &budget.source_control(),
                (&store, fact),
                |(store, fact), tx| Box::pin(async move { store.append(tx, fact, false).await }),
            )
            .await;
        if expected == "committed" {
            ensure!(state(result) == expected);
        } else {
            ensure!(result.fold(
                |_| false,
                |_| false,
                |error| matches!(error, TransactionError::Operation(Error::ReserveExhausted)),
                |_| false,
                |_| false,
                |_| false
            ));
        }
    }
    let full = store
        .backlog(
            tenant,
            OperationDeadline::from_remaining(Duration::from_secs(5)),
        )
        .await?;
    ensure!(full.events == 1 && full.source_bytes == before.source_bytes);
    ensure!(full.reserved_events == 1 && full.reserved_source_bytes > 0 && full.reserve_exhausted);
    // A saturated business source cannot consume request-completion capacity.
    let failed_request = RequestAudit::new(tenant.to_string(), "exhausted_business_reserve");
    ensure!(
        rss_mdm_audit_integration::completion::complete(
            &store,
            &failed_request,
            503,
            Some(rss_mdm_audit_integration::completion::ResponseFailure::AuditReserveExhausted),
        )
        .await
        .is_none(),
        "business reserve exhaustion suppressed independent request settlement"
    );
    let persisted = bytes(&pool, tenant)
        .await?
        .into_iter()
        .map(|value| serde_json::from_slice::<serde_json::Value>(&value))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(persisted.iter().any(|fact| fact["source"] == "mdm.request"
        && fact["request"] == failed_request.request_id().to_string()
        && fact["outcome"] == "failed"));
    let another = RequestAudit::new(tenant.to_string(), "capacity_read");
    ensure!(matches!(
        store
            .settle_request(&another, 200, "success", &budget.source_control())
            .await,
        Err(Error::BacklogFull)
    ));
    store
        .settle_request(&another, 403, "denied", &budget.source_control())
        .await?;
    another.finalize(None);
    let both = store
        .backlog(
            tenant,
            OperationDeadline::from_remaining(Duration::from_secs(5)),
        )
        .await?;
    ensure!(both.events == 2 && both.reserved_events == 2 && both.max_events == 2);
    ensure!(bytes(&pool, tenant).await?.len() == 4);
    crate::audit_test_support::projection::drain(tenant, Integrity::Plain).await?;
    let empty = store
        .backlog(
            tenant,
            OperationDeadline::from_remaining(Duration::from_secs(5)),
        )
        .await?;
    ensure!(
        (
            empty.events,
            empty.source_bytes,
            empty.reserved_events,
            empty.reserved_source_bytes
        ) == (0, 0, 0, 0)
    );
    ensure!(!empty.admission_closed && !empty.reserve_exhausted && empty.oldest_seconds.is_none());
    let resumed = store
        .write(
            tenant,
            &budget.source_control(),
            (&store, &rejected),
            |(store, fact), tx| {
                Box::pin(async move { recovery::crash_write(store, tx, fact).await })
            },
        )
        .await;
    ensure!(state(resumed) == "committed");
    ensure!(
        crate::planning::test_support::sql(&format!(
            "SELECT count(*) FROM mdm_access.devices WHERE tenant_id='{tenant}' AND id='crash-device'"
        )) == "1"
    );
    request.finalize(None);
    pool.close().await;
    Ok(())
}
