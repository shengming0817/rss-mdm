use super::*;

#[tokio::test]
#[ignore = "MODULE=audit.integrity: full original-key history verification binds the captured head"]
async fn original_key_verifies_multiple_pages_and_rejects_replacement_or_wrong_head() -> Result<()>
{
    crate::planning::test_support::sql(include_str!("../../schema/identity-audit-runtime.sql"));
    let pool = pool("mdm_access").await?;
    let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(30));
    let tenant = TenantId::parse(&Uuid::new_v4().to_string())?;
    let store = new_store(pool.clone(), integrity(true)?, tenant).await?;
    let request = RequestAudit::new(tenant.to_string(), "history_restore_test");
    let facts = (0u32..65)
        .map(|i| {
            Fact::business(
                &request,
                &format!("restore:{i}"),
                &i.to_be_bytes(),
                200,
                "success",
                None,
            )
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let result = store
        .write(
            tenant,
            &budget.source_control(),
            (&store, &facts),
            |(store, facts), tx| {
                Box::pin(async move {
                    for fact in *facts {
                        store.append(tx, fact, false).await?;
                    }
                    Ok::<_, Error>(())
                })
            },
        )
        .await;
    ensure!(state(result) == "committed");
    crate::audit_test_support::projection::drain(tenant, integrity(true)?).await?;
    let terminal = crate::planning::test_support::sql(&format!(
        "SELECT count(*)=65 AND bool_and(r.projected_at IS NOT NULL AND o.status='published' AND i.disposition='succeeded' AND a.ledger_sequence IS NOT NULL) FROM mdm_audit.receipts r JOIN rss_transactional_messaging.outbox o ON(o.tenant_id,o.message_id)=(r.tenant_id,r.message_id) JOIN rss_transactional_messaging.inbox i ON(i.tenant_id,i.message_id)=(r.tenant_id,r.message_id) AND i.consumer_group='mdm.audit.v1' JOIN rss_audit.records a ON(a.tenant_id,a.source_id,a.event_id)=(r.tenant_id,r.source_id,r.event_id) WHERE r.tenant_id='{tenant}'"
    ));
    ensure!(terminal == "t", "joint projection terminal state");
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

async fn reject_damaged_receipt<T: rss_request_context::ExecutionTimer>(
    store: &AuditStore,
    tenant: TenantId,
    fact: &Fact,
    _control: &SourceControl<'_, T>,
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
    let original: Vec<u8> =
        sqlx::query_scalar("SELECT source_bytes FROM mdm_audit.receipts WHERE tenant_id=$1::uuid")
            .bind(tenant.to_string())
            .fetch_one(&mut owner)
            .await?;
    for damage in [
        "UPDATE mdm_audit.receipts SET source_bytes=decode('01','hex') WHERE tenant_id=$1::uuid",
        "DELETE FROM mdm_audit.receipts WHERE tenant_id=$1::uuid",
    ] {
        sqlx::query("UPDATE mdm_audit.receipts SET source_bytes=$2 WHERE tenant_id=$1::uuid")
            .bind(tenant.to_string())
            .bind(&original)
            .execute(&mut owner)
            .await?;
        sqlx::query(damage)
            .bind(tenant.to_string())
            .execute(&mut owner)
            .await?;
        let attempt = store
            .write(tenant, _control, (store, fact), |(store, fact), tx| {
                Box::pin(async move { store.append(tx, fact, true).await })
            })
            .await;
        ensure!(state(attempt) == "rolled_back");
        let source_messages:i64=sqlx::query_scalar("SELECT count(*) FROM rss_transactional_messaging.outbox WHERE tenant_id=$1::uuid AND domain='mdm.audit'")
            .bind(tenant.to_string()).fetch_one(&mut owner).await?;
        ensure!(source_messages == 1);
    }
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
    let opposite = new_store(pool.clone(), integrity(!ledger)?, tenant).await?;
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
        for ledger in [false] {
            let timer = crate::lifecycle::RuntimeTimer;
            let cancel = tokio_util::sync::CancellationToken::new();
            let control = {
                let cutoff = Deadline::from_timeout(&timer, Duration::from_secs(10))?;
                Control::new(&timer, cutoff, cutoff, &cancel)
            };
            let tenant = TenantId::parse(&Uuid::new_v4().to_string())?;
            let store = new_store(pool.clone(), integrity(ledger)?, tenant).await?;
            empty_reads_preserve_heads(&pool, &store, tenant, &control).await?;
            let request = RequestAudit::new(tenant.to_string(), "audit_integrity_test");
            let fact = Fact::business(&request, "integrity", b"initial", 200, "success", None)?;
            let source_budget =
                rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(10));
            let source_control = source_budget.source_control();
            let written = store
                .write(
                    tenant,
                    &source_control,
                    (&store, &fact),
                    |(store, fact), tx| {
                        Box::pin(async move { store.append(tx, fact, false).await })
                    },
                )
                .await;
            ensure!(state(written) == "committed");
            crate::audit_test_support::projection::drain(tenant, integrity(ledger)?).await?;
            startup_integrity(&pool, &store, tenant, ledger, &control).await?;
            reject_damaged_receipt(&store, tenant, &fact, &source_control).await?;
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
