use super::*;

async fn lock_then_fresh_snapshot(pool: &PgPool, ledger: bool) -> Result<()> {
    let peers = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(pool.connect_options().as_ref().clone())
        .await?;
    let timer = crate::lifecycle::RuntimeTimer;
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = Control::new(
        &timer,
        Deadline::from_timeout(&timer, Duration::from_secs(5))?,
        &cancel,
    );
    let store = AuditStore::new(peers.clone(), integrity(ledger)?, &control).await?;
    let tenant = TenantId::parse(&Uuid::new_v4().to_string())?;
    let request = RequestAudit::new(tenant.to_string(), "audit_recovery_test");
    let fact = Fact::business(&request, "overlap", b"same-request", 200, "success", None)?;
    let entered = tokio::sync::Notify::new();
    let release = tokio::sync::Notify::new();
    let original = store.execute(
        tenant,
        &control,
        (&store, &fact, &entered, &release),
        |(s, f, entered, release), tx| {
            Box::pin(async move {
                s.append(tx, f, false).await?;
                entered.notify_one();
                release.notified().await;
                Ok(())
            })
        },
    );
    let recover = async {
        entered.notified().await;
        let replay = store.execute(tenant, &control, (&store, &fact), |(s, f), tx| {
            Box::pin(async move { s.append(tx, f, true).await })
        });
        let unlock = async {
            tokio::time::timeout(Duration::from_secs(2),async {
                loop{
                    let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename=current_user AND pid<>pg_backend_pid() AND wait_event_type='Lock' AND query LIKE '%rss_audit.reserve%')").fetch_one(pool).await?;
                    if waiting {break Ok::<(),sqlx::Error>(());}
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }).await??;
            release.notify_one();
            Ok::<(), anyhow::Error>(())
        };
        let (replayed, unlocked) = tokio::join!(replay, unlock);
        unlocked?;
        ensure!(
            state(replayed) == "committed",
            "post-lock statement must see the prior committed receipt"
        );
        Ok::<(), anyhow::Error>(())
    };
    let (original, recovered) = tokio::join!(original, recover);
    ensure!(state(original) == "committed");
    recovered?;
    ensure!(bytes(pool, tenant).await?.len() == 1);
    request.finalize(None);
    peers.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "MODULE=audit.budget: real owner settlement after a bounded callback"]
async fn operation_cutoff_leaves_owner_time_to_rollback() -> Result<()> {
    let (pool, _) = crate::audit_test_support::request_store().await?;
    for ledger in [false, true] {
        let timer = crate::lifecycle::RuntimeTimer;
        let cancel = tokio_util::sync::CancellationToken::new();
        let total = Control::new(
            &timer,
            Deadline::from_timeout(&timer, Duration::from_secs(10))?,
            &cancel,
        );
        let store = AuditStore::new(pool.clone(), integrity(ledger)?, &total).await?;
        let tenant = TenantId::parse(&Uuid::new_v4().to_string())?;
        let request = RequestAudit::new(tenant.to_string(), "bounded_retirement");
        request.identify_service("service:collection-finalizer");
        let fact = Fact::business(
            &request,
            "bounded-operation",
            b"retired",
            200,
            "success",
            None,
        )?;
        let operation = rss_mdm_audit_integration::OperationBudget::new(
            &timer,
            Deadline::from_timeout(&timer, total.remaining())?,
            Deadline::from_timeout(&timer, Duration::from_secs(2))?,
            &cancel,
        );
        let reached = std::sync::atomic::AtomicBool::new(false);
        let attempt = store
            .execute_with_operation(
                tenant,
                &operation,
                (&store, &fact, &reached),
                |(store, fact, reached), tx| {
                    Box::pin(async move {
                        store.append(tx, fact, false).await?;
                        reached.store(true, std::sync::atomic::Ordering::Release);
                        std::future::pending::<Result<(), Error>>().await
                    })
                },
            )
            .await;
        ensure!(reached.load(std::sync::atomic::Ordering::Acquire));
        ensure!(state(attempt) == "rolled_back");
        ensure!(bytes(&pool, tenant).await?.is_empty());
        let mut observer = pool.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(tenant.to_string())
            .execute(&mut *observer)
            .await?;
        let receipts: i64 =
            sqlx::query_scalar("SELECT count(*) FROM mdm_audit.receipts WHERE tenant_id=$1::uuid")
                .bind(tenant.to_string())
                .fetch_one(&mut *observer)
                .await?;
        ensure!(receipts == 0);
        observer.rollback().await?;
        // The expired absolute operation cutoff cannot run even an immediately-ready callback.
        let forbidden = store
            .execute_with_operation(tenant, &operation, (), |_, _| {
                Box::pin(async {
                    panic!("expired callback ran");
                    #[allow(unreachable_code)]
                    Ok::<(), Error>(())
                })
            })
            .await;
        ensure!(state(forbidden) == "rolled_back");
        let recovery = store
            .execute(tenant, &total, (&store, &fact), |(store, fact), tx| {
                Box::pin(async move { store.append(tx, fact, false).await })
            })
            .await;
        ensure!(state(recovery) == "committed");
        ensure!(bytes(&pool, tenant).await?.len() == 1);
        lock_wait_uses_settlement_reserve(&store, &pool, tenant).await?;
        request.finalize(None);
    }
    pool.close().await;
    Ok(())
}

async fn lock_wait_uses_settlement_reserve(
    store: &AuditStore,
    pool: &PgPool,
    tenant: TenantId,
) -> Result<()> {
    let original = bytes(pool, tenant).await?;
    let peers = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(pool.connect_options().as_ref().clone())
        .await?;
    let mut holder = peers.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant.to_string())
        .execute(&mut *holder)
        .await?;
    sqlx::query("SELECT rss_audit.reserve($1::uuid)")
        .bind(tenant.to_string())
        .execute(&mut *holder)
        .await?;
    let timer = crate::lifecycle::RuntimeTimer;
    let cancel = tokio_util::sync::CancellationToken::new();
    let total = Control::new(
        &timer,
        Deadline::from_timeout(&timer, Duration::from_secs(4))?,
        &cancel,
    );
    let cutoff = Deadline::from_timeout(&timer, Duration::from_secs(1))?;
    let work = rss_mdm_audit_integration::OperationBudget::new(
        &timer,
        Deadline::from_timeout(&timer, total.remaining())?,
        cutoff,
        &cancel,
    );
    let entered = std::sync::atomic::AtomicBool::new(false);
    let attempt = store.execute_with_operation(tenant, &work, &entered, |entered, _| {
        Box::pin(async move {
            entered.store(true, std::sync::atomic::Ordering::Release);
            Ok::<(), Error>(())
        })
    });
    let release = async {
        // Release the actual PG lock after work cutoff but comfortably before total cutoff.
        tokio::time::sleep_until((cutoff.instant() + Duration::from_millis(300)).into()).await;
        holder.rollback().await
    };
    let (attempt, released) = tokio::join!(attempt, release);
    released?;
    ensure!(state(attempt) == "rolled_back");
    ensure!(!entered.load(std::sync::atomic::Ordering::Acquire));
    ensure!(bytes(pool, tenant).await? == original);
    peers.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "MODULE=audit.budget: lock acquisition precedes fresh transaction snapshot"]
async fn locking_uses_fresh_snapshot() -> Result<()> {
    for role in ROLES {
        let pool = pool(role).await?;
        for ledger in [false, true] {
            lock_then_fresh_snapshot(&pool, ledger).await?;
        }
        pool.close().await;
    }
    Ok(())
}
