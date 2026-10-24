use super::*;

#[tokio::test]
#[ignore = "MODULE=audit.budget: real owner settlement after a bounded callback"]
async fn operation_cutoff_leaves_owner_time_to_rollback() -> Result<()> {
    let pool = pool("mdm_access").await?;
    {
        let timer = crate::lifecycle::RuntimeTimer;
        let cancel = tokio_util::sync::CancellationToken::new();
        let total_cutoff = Deadline::from_timeout(&timer, Duration::from_secs(10))?;
        let total = SourceControl::new(&timer, total_cutoff, total_cutoff, &cancel);
        let tenant = TenantId::parse(&Uuid::new_v4().to_string())?;
        let store = new_store(pool.clone(), Integrity::Plain, tenant).await?;
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
        let operation = SourceControl::new(
            &timer,
            total_cutoff,
            Deadline::from_timeout(&timer, Duration::from_secs(2))?,
            &cancel,
        );
        let reached = std::sync::atomic::AtomicBool::new(false);
        let attempt = store
            .write(
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
        // The expired absolute operation cutoff cannot run even an immediately-ready callback.
        let forbidden = store
            .write(tenant, &operation, (), |_, _| {
                Box::pin(async {
                    panic!("expired callback ran");
                    #[allow(unreachable_code)]
                    Ok::<(), Error>(())
                })
            })
            .await;
        ensure!(state(forbidden) == "not_started");
        let recovery = store
            .write(tenant, &total, (&store, &fact), |(store, fact), tx| {
                Box::pin(async move { store.append(tx, fact, false).await })
            })
            .await;
        ensure!(state(recovery) == "committed");
        ensure!(bytes(&pool, tenant).await?.len() == 1);
        request.finalize(None);
    }
    pool.close().await;
    Ok(())
}
