use super::*;

async fn settlement_recovery(pool: &PgPool, ledger: bool) -> Result<()> {
    let timer = crate::lifecycle::RuntimeTimer;
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = Control::new(
        &timer,
        Deadline::from_timeout(&timer, Duration::from_secs(3))?,
        &cancel,
    );
    let operation = rss_mdm_audit_integration::OperationBudget::new(
        &timer,
        Deadline::from_timeout(&timer, control.remaining())?,
        Deadline::from_timeout(&timer, Duration::from_secs(3))?,
        &cancel,
    );
    let store = AuditStore::new(pool.clone(), integrity(ledger)?, &control).await?;
    let tenant = TenantId::parse(&Uuid::new_v4().to_string())?;
    let request = RequestAudit::new(tenant.to_string(), "audit_recovery_test");
    let fact = Fact::business(&request, "commit-ack-loss", b"A", 200, "success", None)?;
    store.inject_next_fault(rss_audit_postgres::PgFault::CommitUnknownAfterAck);
    let attempt = store
        .execute_with_operation(tenant, &operation, (&store, &fact), |(s, f), tx| {
            Box::pin(async move { s.append(tx, f, false).await })
        })
        .await;
    ensure!(state(attempt) == "unknown");
    let original = bytes(pool, tenant).await?;
    ensure!(original.len() == 1);
    let attempt = store
        .execute_with_operation(tenant, &operation, (&store, &fact), |(s, f), tx| {
            Box::pin(async move { s.append(tx, f, true).await })
        })
        .await;
    ensure!(state(attempt) == "committed");
    ensure!(bytes(pool, tenant).await? == original);
    let failed = Fact::business(&request, "rollback-ack-loss", b"B", 200, "success", None)?;
    store.inject_next_fault(rss_audit_postgres::PgFault::RollbackFailedAfterAck);
    let attempt = store
        .execute_with_operation(tenant, &operation, (&store, &failed), |(s, f), tx| {
            Box::pin(async move {
                s.append(tx, f, false).await?;
                Err::<(), _>(Error::Receipt)
            })
        })
        .await;
    ensure!(state(attempt) == "rollback_failed");
    ensure!(bytes(pool, tenant).await? == original);
    request.finalize(None);
    Ok(())
}

pub(super) async fn crash_write<T: rss_request_context::ExecutionTimer>(
    store: &AuditStore,
    tx: &mut rss_audit_postgres::AuditTransaction<'_, '_, '_, T>,
    fact: &Fact,
) -> Result<(), Error> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO mdm_access.devices(tenant_id,id) VALUES($1::uuid,'crash-device')",
            )
            .bind(tenant)
            .execute(c)
            .await?;
            Ok::<(), Error>(())
        })
    })
    .await?;
    store.append(tx, fact, false).await
}

async fn process_interruption(pool: &PgPool, ledger: bool) -> Result<()> {
    use tokio::io::AsyncBufReadExt;
    let tenant = TenantId::parse(&Uuid::new_v4().to_string())?;
    let mut child = tokio::process::Command::new(std::env::current_exe()?)
        .args([
            "--ignored",
            "--exact",
            "audit_integration_tests::test_support::audit_process_exit_fixture",
            "--nocapture",
        ])
        .env("MDM_AUDIT_CRASH_TENANT", tenant.to_string())
        .env("MDM_AUDIT_CRASH_LEDGER", if ledger { "1" } else { "0" })
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let mut output = tokio::io::BufReader::new(child.stdout.take().expect("child stdout")).lines();
    tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(line) = output.next_line().await? {
            if line.contains("MDM_AUDIT_STAGED") {
                return Ok::<(), anyhow::Error>(());
            }
        }
        anyhow::bail!("audit child exited before staging");
    })
    .await??;
    let timer = crate::lifecycle::RuntimeTimer;
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = Control::new(
        &timer,
        Deadline::from_timeout(&timer, Duration::from_secs(3))?,
        &cancel,
    );
    let store = AuditStore::new(pool.clone(), integrity(ledger)?, &control).await?;
    let short = Control::new(
        &timer,
        Deadline::from_timeout(&timer, Duration::from_millis(50))?,
        &cancel,
    );
    let attempted = std::sync::atomic::AtomicBool::new(false);
    let locked = store
        .execute(tenant, &short, &attempted, |attempted, _| {
            Box::pin(async move {
                attempted.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok::<(), Error>(())
            })
        })
        .await;
    ensure!(
        state(locked) != "committed" && !attempted.load(std::sync::atomic::Ordering::SeqCst),
        "absence before old transaction ends is not recovery authority"
    );
    child.kill().await?;
    child.wait().await?;
    let request = RequestAudit::new(tenant.to_string(), "audit_recovery_test");
    let fact = Fact::business(
        &request,
        "process-interruption",
        b"crash-device",
        200,
        "success",
        None,
    )?;
    let recovered = store
        .execute(tenant, &control, (&store, &fact), |(store, fact), tx| {
            Box::pin(async move { crash_write(store, tx, fact).await })
        })
        .await;
    ensure!(state(recovered) == "committed");
    ensure!(bytes(pool, tenant).await?.len() == 1);
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await?;
    let devices: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM mdm_access.devices WHERE tenant_id=$1::uuid AND id='crash-device'",
    )
    .bind(tenant.to_string())
    .fetch_one(&mut *tx)
    .await?;
    ensure!(devices == 1);
    tx.rollback().await?;
    request.finalize(None);
    Ok(())
}

#[tokio::test]
#[ignore = "MODULE=audit.recovery: unknown commit and process interruption"]
async fn recovery_preserves_single_receipt() -> Result<()> {
    for role in ROLES {
        let pool = pool(role).await?;
        for ledger in [false, true] {
            settlement_recovery(&pool, ledger).await?;
            if role == "mdm_access" {
                process_interruption(&pool, ledger).await?;
            }
        }
        pool.close().await;
    }
    Ok(())
}
