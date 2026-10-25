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
    let request = RequestAudit::new(
        tenant.to_string(),
        "audit_recovery_test",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    request.set_principal("fixture-principal", crate::test_support::INSTANCE);
    let fact = Fact::business(&request, "stable-operation", 200, "success", None)?;
    let first = store
        .write(tenant, &control, (&store, &fact), |(store, fact), tx| {
            Box::pin(async move { store.append(tx, fact).await })
        })
        .await;
    ensure!(state(first) == "committed");
    let original = bytes(pool, tenant).await?;
    ensure!(original.len() == 1);
    // A new fact with the same identity but different content must abort.
    let changed = Fact::business(&request, "stable-operation", 400, "failed", None)?;
    let conflict = store
        .write(tenant, &control, (&store, &changed), |(store, fact), tx| {
            Box::pin(async move { store.append(tx, fact).await })
        })
        .await;
    ensure!(state(conflict) == "rolled_back");
    ensure!(bytes(pool, tenant).await? == original);
    let rollback = Fact::business(&request, "rolled-back-operation", 200, "success", None)?;
    let rollback = store
        .write(
            tenant,
            &control,
            (&store, &rollback),
            |(store, fact), tx| {
                Box::pin(async move {
                    store.append(tx, fact).await?;
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
    let request = RequestAudit::new(
        tenant.to_string(),
        "collection_finish",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    request.identify_service("service:collection-finalizer");
    let facts = (0..2)
        .map(|index| {
            Fact::business(
                &request,
                &format!("collection-{index}:finish"),
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
                        (if replayed {
                            Ok(())
                        } else {
                            store.append(tx, fact).await
                        })?;
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
#[ignore = "MODULE=audit.receipts: ordinary reads bypass unavailable audit; disclosures remain closed"]
async fn ordinary_and_sensitive_reads_have_distinct_failure_policies() -> Result<()> {
    use rss_mdm_audit_integration::{AuditIntent as I, SensitiveAction as S, completion};
    let (pool, runtime, store) = crate::audit_test_support::request_store().await?;
    let tenant = TenantId::parse(crate::test_support::case::tenant())?;
    let before = bytes(&pool, tenant).await?.len();
    let ordinary = RequestAudit::new(tenant.to_string(), "ordinary_read", I::Routine);
    ensure!(
        completion::complete(&store, &ordinary, 200, None)
            .await
            .is_none()
    );
    ensure!(bytes(&pool, tenant).await?.len() == before);
    runtime.close().await;
    pool.close().await;
    let ordinary = RequestAudit::new(tenant.to_string(), "ordinary_read", I::Routine);
    ensure!(
        completion::complete(&store, &ordinary, 200, None)
            .await
            .is_none()
    );
    let sensitive = RequestAudit::new(
        tenant.to_string(),
        "private_export",
        I::Sensitive(S::CertificatePrivateExport),
    );
    ensure!(matches!(
        completion::complete(&store, &sensitive, 200, None).await,
        Some(completion::Replacement::Audit(_))
    ));
    Ok(())
}
