use super::*;

async fn rejects_snapshot_isolation(pool: &PgPool) -> Result<()> {
    let timer = crate::lifecycle::RuntimeTimer;
    let cancel = tokio_util::sync::CancellationToken::new();
    let deadline = Deadline::from_timeout(&timer, Duration::from_secs(2))?;
    let control = {
        let cutoff = deadline;
        Control::new(&timer, cutoff, cutoff, &cancel)
    };
    sqlx::query("SET default_transaction_isolation='repeatable read'")
        .execute(pool)
        .await?;
    ensure!(matches!(
        AuditStore::new(pool.clone(), Integrity::Plain, &control).await,
        Err(Error::Isolation)
    ));
    sqlx::query("SET default_transaction_isolation='read committed'")
        .execute(pool)
        .await?;
    Ok(())
}

async fn reject_damaged_receipt(
    store: &AuditStore,
    tenant: TenantId,
    fact: &Fact,
    _control: &Control<'_, crate::lifecycle::RuntimeTimer>,
) -> Result<()> {
    use sqlx::Connection;
    let options = PgConnectOptions::from_str(&std::env::var("MDM_OWNER_URL")?)?
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert(std::env::var("PG_CA_FILE")?);
    let mut owner = sqlx::PgConnection::connect_with(&options).await?;
    // Deliberate corruption by the installation owner in this disposable database.
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(tenant.to_string())
        .execute(&mut owner)
        .await?;
    let canonical: Vec<u8> =
        sqlx::query_scalar("SELECT canonical FROM mdm_audit.receipts WHERE tenant_id=$1::uuid")
            .bind(tenant.to_string())
            .fetch_one(&mut owner)
            .await?;
    for damage in [
        "UPDATE mdm_audit.receipts SET canonical=decode('01','hex') WHERE tenant_id=$1::uuid",
        "DELETE FROM mdm_audit.receipts WHERE tenant_id=$1::uuid",
    ] {
        let timer = crate::lifecycle::RuntimeTimer;
        let cancel = tokio_util::sync::CancellationToken::new();
        let deadline = Deadline::from_timeout(&timer, Duration::from_secs(10))?;
        let control = &Control::new(&timer, deadline, deadline, &cancel);
        sqlx::query("UPDATE mdm_audit.receipts SET canonical=$2 WHERE tenant_id=$1::uuid")
            .bind(tenant.to_string())
            .bind(&canonical)
            .execute(&mut owner)
            .await?;
        let normal = store
            .write(tenant, control, (store, fact), |(store, fact), tx| {
                Box::pin(async move { store.append(tx, fact, true).await })
            })
            .await;
        ensure!(state(normal) == "committed");
        sqlx::query(damage)
            .bind(tenant.to_string())
            .execute(&mut owner)
            .await?;
        let attempt = store
            .write(tenant, control, (store, fact), |(store, fact), tx| {
                Box::pin(async move { store.append(tx, fact, true).await })
            })
            .await;
        ensure!(attempt.fold(
            |_| false,
            |_| false,
            |e| matches!(e, TransactionError::Operation(Error::Receipt)),
            |_| false,
            |_| false,
            |_| false
        ));
        let records: i64 =
            sqlx::query_scalar("SELECT count(*) FROM rss_audit.records WHERE tenant_id=$1::uuid")
                .bind(tenant.to_string())
                .fetch_one(&mut owner)
                .await?;
        ensure!(records == 1);
    }
    // The opposite one-sided loss is also corruption, never permission to recreate Audit.
    let id = fact.identity();
    sqlx::query("INSERT INTO mdm_audit.receipts(tenant_id,source_id,event_id,fingerprint,canonical) VALUES($1::uuid,$2,$3,$4,$5)")
        .bind(tenant.to_string()).bind(id.source().source_id().as_str()).bind(id.event_id().as_str())
        .bind(fact.fingerprint().as_slice()).bind(&canonical).execute(&mut owner).await?;
    crate::planning::test_support::sql(&format!(
        "DELETE FROM rss_audit.records WHERE tenant_id='{tenant}'"
    ));
    let attempt = store
        .write(tenant, _control, (store, fact), |(store, fact), tx| {
            Box::pin(async move { store.append(tx, fact, true).await })
        })
        .await;
    ensure!(attempt.fold(
        |_| false,
        |_| false,
        |e| matches!(e, TransactionError::Operation(Error::Receipt)),
        |_| false,
        |_| false,
        |_| false
    ));
    let records: i64 =
        sqlx::query_scalar("SELECT count(*) FROM rss_audit.records WHERE tenant_id=$1::uuid")
            .bind(tenant.to_string())
            .fetch_one(&mut owner)
            .await?;
    ensure!(
        records == 0,
        "missing Audit must not be automatically repaired"
    );
    owner.close().await?;
    Ok(())
}

async fn startup_integrity(
    pool: &PgPool,
    store: &AuditStore,
    tenant: TenantId,
    ledger: bool,
    control: &Control<'_, crate::lifecycle::RuntimeTimer>,
) -> Result<()> {
    store.validate_tenant(tenant, control).await?;
    let opposite = AuditStore::new(pool.clone(), integrity(!ledger)?, control).await?;
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
    if ledger {
        let wrong = AuditStore::new(
            pool.clone(),
            Integrity::Ledger(std::sync::Arc::new(rss_ledger::Authenticator::new(
                rss_ledger::KeyId::parse("mdm-audit-fixture")?,
                vec![20; 32],
            )?)),
            control,
        )
        .await?;
        ensure!(
            matches!(
                wrong
                    .validate_tenant(tenant, control)
                    .await
                    .unwrap_err()
                    .class(),
                rss_mdm_audit_integration::ErrorClass::AuditIntegrity
            ),
            "same ID with wrong secret must fail before serving requests"
        );
    }
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
    let heads: (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM rss_audit.heads WHERE tenant_id=$1::uuid), \
         (SELECT count(*) FROM rss_ledger.heads WHERE tenant_id=$1::uuid)",
    )
    .bind(tenant.to_string())
    .fetch_one(&mut *tx)
    .await?;
    ensure!(
        heads == (0, 0),
        "read created Audit or Ledger heads: {heads:?}"
    );
    tx.rollback().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "MODULE=audit.integrity: mode, key, isolation and receipt corruption"]
async fn storage_integrity_is_enforced() -> Result<()> {
    for role in ROLES {
        let pool = pool(role).await?;
        rejects_snapshot_isolation(&pool).await?;
        for ledger in [false, true] {
            let timer = crate::lifecycle::RuntimeTimer;
            let cancel = tokio_util::sync::CancellationToken::new();
            let control = {
                let cutoff = Deadline::from_timeout(&timer, Duration::from_secs(10))?;
                Control::new(&timer, cutoff, cutoff, &cancel)
            };
            let store = AuditStore::new(pool.clone(), integrity(ledger)?, &control).await?;
            let tenant = TenantId::parse(&Uuid::new_v4().to_string())?;
            empty_reads_preserve_heads(&pool, &store, tenant, &control).await?;
            let request = RequestAudit::new(tenant.to_string(), "audit_integrity_test");
            let fact = Fact::business(&request, "integrity", b"initial", 200, "success", None)?;
            let written = store
                .write(tenant, &control, (&store, &fact), |(store, fact), tx| {
                    Box::pin(async move { store.append(tx, fact, false).await })
                })
                .await;
            ensure!(state(written) == "committed");
            startup_integrity(&pool, &store, tenant, ledger, &control).await?;
            reject_damaged_receipt(&store, tenant, &fact, &control).await?;
            request.finalize(None);
        }
        pool.close().await;
    }
    Ok(())
}

#[path = "owner_admission.rs"]
mod owner_admission;

#[path = "query_cost.rs"]
mod query_cost;
