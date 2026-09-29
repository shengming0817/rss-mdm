use super::*;

async fn exercise(pool: &PgPool, ledger: bool) -> Result<()> {
    let timer = crate::lifecycle::RuntimeTimer;
    let cancel = tokio_util::sync::CancellationToken::new();
    let deadline = Deadline::from_timeout(&timer, Duration::from_secs(10))?;
    let control = {
        let cutoff = deadline;
        Control::new(&timer, cutoff, cutoff, &cancel)
    };
    let mode = integrity(ledger)?;
    let store = AuditStore::new(pool.clone(), mode, &control).await?;
    let tenant = TenantId::parse(&Uuid::new_v4().to_string())?;
    let request = RequestAudit::new(tenant.to_string(), "audit_recovery_test");
    request.set_principal("fixture-principal", "fixture-instance");
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
    ensure!(state(inconsistent) == "rolled_back");
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
    ensure!(state(conflict) == "rolled_back");
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
    ensure!(state(missing) == "rolled_back");
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
    ensure!(state(rollback) == "rolled_back");
    ensure!(bytes(pool, tenant).await? == original);
    request.finalize(None);
    Ok(())
}

async fn retirement_batch(pool: &PgPool, ledger: bool) -> Result<()> {
    let timer = crate::lifecycle::RuntimeTimer;
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = {
        let cutoff = Deadline::from_timeout(&timer, Duration::from_secs(30))?;
        Control::new(&timer, cutoff, cutoff, &cancel)
    };
    let store = AuditStore::new(pool.clone(), integrity(ledger)?, &control).await?;
    let tenant = TenantId::parse(&Uuid::new_v4().to_string())?;
    let request = RequestAudit::new(tenant.to_string(), "collection_finish");
    request.identify_service("service:collection-finalizer");
    let facts = (0..65)
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
            Control::new(&timer, cutoff, cutoff, &cancel)
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
            "retirement batch ledger={ledger} replay={replayed}: {outcome}"
        );
        let canonical = bytes(pool, tenant).await?;
        ensure!(canonical.len() == 65);
        if let Some(original) = &original {
            ensure!(&canonical == original);
        } else {
            original = Some(canonical);
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
        for ledger in [false, true] {
            exercise(&pool, ledger).await?;
            if role == "mdm_access" {
                retirement_batch(&pool, ledger).await?;
            }
        }
        pool.close().await;
    }
    Ok(())
}
