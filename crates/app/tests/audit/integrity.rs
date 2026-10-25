use super::*;

#[tokio::test]
#[ignore = "MODULE=audit.integrity: full original-key history verification binds the captured head"]
async fn original_key_verifies_multiple_pages_and_rejects_replacement_or_wrong_head() -> Result<()>
{
    let pool = pool("mdm_access").await?;
    let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(30));
    let tenant = TenantId::parse(&Uuid::new_v4().to_string())?;
    let store = new_store(pool.clone(), integrity(true)?, tenant).await?;
    let request = RequestAudit::new(
        tenant.to_string(),
        "history_restore_test",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    let facts = (0u32..65)
        .map(|i| Fact::business(&request, &format!("restore:{i}"), 200, "success", None))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let result = store
        .write(
            tenant,
            &budget.source_control(),
            (&store, &facts),
            |(store, facts), tx| {
                Box::pin(async move {
                    for fact in *facts {
                        store.append(tx, fact).await?;
                    }
                    Ok::<_, Error>(())
                })
            },
        )
        .await;
    ensure!(state(result) == "committed");

    let terminal = crate::planning::test_support::sql(&format!(
        "SELECT count(*)=65 AND bool_and(ledger_sequence IS NOT NULL) FROM rss_audit.records WHERE tenant_id='{tenant}'"
    ));
    ensure!(terminal == "t", "final audit and ledger commit together");
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await?;
    let (seq, tag): (i64, Vec<u8>) = sqlx::query_as(
        "SELECT seq,tag FROM rss_ledger.heads WHERE tenant_id=$1::uuid AND chain_id='rss.audit.v1'",
    )
    .bind(tenant.to_string())
    .fetch_one(&mut *tx)
    .await?;
    tx.rollback().await?;
    let tag: [u8; 32] = tag
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid captured tag"))?;
    ensure!(
        store
            .verify_history_to(tenant, Some(seq as u64), &tag)
            .await?
            == 65
    );
    ensure!(
        store
            .verify_history_to(tenant, Some(seq as u64 + 1), &tag)
            .await
            .is_err()
    );
    ensure!(
        store
            .verify_history_to(tenant, Some(seq as u64), &[0; 32])
            .await
            .is_err()
    );
    let wrong = new_store(
        pool.clone(),
        Integrity::Ledger(std::sync::Arc::new(rss_ledger::Authenticator::new(
            rss_ledger::KeyId::parse("mdm-audit-fixture")?,
            vec![20; 32],
        )?)),
        tenant,
    )
    .await?;
    ensure!(
        wrong
            .verify_history_to(tenant, Some(seq as u64), &tag)
            .await
            .is_err()
    );
    request.finalize(None);
    pool.close().await;
    Ok(())
}

async fn startup_integrity(
    pool: &PgPool,
    store: &AuditStore,
    tenant: TenantId,
    control: &Control<'_, crate::lifecycle::RuntimeTimer>,
) -> Result<()> {
    store.validate_tenant(tenant, control).await?;
    let opposite = new_store(pool.clone(), integrity(true)?, tenant).await?;
    ensure!(
        matches!(
            opposite
                .validate_tenant(tenant, control)
                .await
                .unwrap_err()
                .class(),
            rss_mdm_audit_integration::ErrorClass::AuditIntegrity
        ),
        "configured integrity cannot silently switch"
    );
    Ok(())
}

async fn empty_reads_preserve_heads(
    pool: &PgPool,
    store: &AuditStore,
    tenant: TenantId,
    control: &Control<'_, crate::lifecycle::RuntimeTimer>,
) -> Result<()> {
    store.validate_tenant(tenant, control).await?;
    let read = store
        .read(tenant, control, (), |_, tx| {
            Box::pin(async move {
                let read_only: String = tx
                    .with_connection(|c| {
                        Box::pin(async move {
                            sqlx::query_scalar("SELECT current_setting('transaction_read_only')")
                                .fetch_one(c)
                                .await
                        })
                    })
                    .await?;
                if read_only != "on" {
                    return Err(Error::Admission);
                }
                Ok(())
            })
        })
        .await;
    ensure!(state(read) == "committed");
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await?;
    let heads: i64 =
        sqlx::query_scalar("SELECT count(*) FROM rss_audit.records WHERE tenant_id=$1::uuid")
            .bind(tenant.to_string())
            .fetch_one(&mut *tx)
            .await?;
    ensure!(heads == 0, "read created Audit or Ledger heads: {heads:?}");
    tx.rollback().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "MODULE=audit.integrity: mode, key, isolation and receipt corruption"]
async fn storage_integrity_is_enforced() -> Result<()> {
    for role in ROLES {
        let pool = pool(role).await?;
        let timer = crate::lifecycle::RuntimeTimer;
        let cancel = tokio_util::sync::CancellationToken::new();
        let control = {
            let cutoff = Deadline::from_timeout(&timer, Duration::from_secs(10))?;
            Control::new(&timer, cutoff, cutoff, &cancel)
        };
        let tenant = TenantId::parse(&Uuid::new_v4().to_string())?;
        let store = new_store(pool.clone(), Integrity::Plain, tenant).await?;
        empty_reads_preserve_heads(&pool, &store, tenant, &control).await?;
        let request = RequestAudit::new(
            tenant.to_string(),
            "audit_integrity_test",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        let fact = Fact::business(&request, "integrity", 200, "success", None)?;
        let source_budget =
            rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(10));
        let source_control = source_budget.source_control();
        let written = store
            .write(
                tenant,
                &source_control,
                (&store, &fact),
                |(store, fact), tx| Box::pin(async move { store.append(tx, fact).await }),
            )
            .await;
        ensure!(state(written) == "committed");

        startup_integrity(&pool, &store, tenant, &control).await?;
        request.finalize(None);
        pool.close().await;
    }
    Ok(())
}

#[path = "owner_admission.rs"]
mod owner_admission;

#[path = "query_cost.rs"]
mod query_cost;
