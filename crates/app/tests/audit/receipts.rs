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
        ensure!(frozen.len() == 65);
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
