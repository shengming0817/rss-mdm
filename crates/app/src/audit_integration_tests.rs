//! Real component and product receipt composition against the installer-owned schema.
use anyhow::{Result, ensure};
use rss_audit_postgres::{Committed, Control, Integrity, TransactionError};
use rss_mdm_audit_integration::{AuditStore, Error, Fact, RequestAudit};
use rss_request_context::{Deadline, TenantId};
use rss_transactional_messaging::transaction::LocalTxAttempt;
use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions, PgSslMode},
};
use std::{str::FromStr, time::Duration};
use uuid::Uuid;

#[tokio::test]
#[ignore = "make t2: installed Audit/Ledger, four runtime roles and exact product receipts"]
async fn installed_audit_receipts_replay_and_atomicity() -> Result<()> {
    for role in [
        "mdm_access",
        "mdm_management_runtime",
        "mdm_command_runtime",
        "mdm_software_driver",
    ] {
        let password = if role == "mdm_access" {
            "access-fixture"
        } else {
            "runtime-fixture"
        };
        let options = PgConnectOptions::from_str(&std::env::var("MDM_OWNER_URL")?)?
            .username(role)
            .password(password)
            .ssl_mode(PgSslMode::VerifyFull)
            .ssl_root_cert(std::env::var("PG_CA_FILE")?);
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await?;
        rejects_snapshot_isolation(&pool).await?;
        for ledger in [false, true] {
            exercise(&pool, ledger).await?;
            if role == "mdm_access" {
                process_interruption(&pool, ledger).await?;
                retirement_batch(&pool, ledger).await?;
            }
        }
        pool.close().await;
    }
    Ok(())
}
async fn exercise(pool: &PgPool, ledger: bool) -> Result<()> {
    let timer = crate::lifecycle::RuntimeTimer;
    let cancel = tokio_util::sync::CancellationToken::new();
    let deadline = Deadline::from_timeout(&timer, Duration::from_secs(10))?;
    let control = Control::new(&timer, deadline, &cancel);
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
        .execute(tenant, &control, (&store, &fact), |(store, fact), tx| {
            Box::pin(async move { store.append(tx, fact, false).await })
        })
        .await;
    ensure!(state(first) == "committed");
    let original = bytes(pool, tenant).await?;
    ensure!(original.len() == 1);
    let replay = store
        .execute(tenant, &control, (&store, &fact), |(store, fact), tx| {
            Box::pin(async move { store.append(tx, fact, true).await })
        })
        .await;
    ensure!(state(replay) == "committed");
    ensure!(bytes(pool, tenant).await? == original);
    // An absent business receipt cannot acquire a pre-existing audit fact.
    let inconsistent = store
        .execute(tenant, &control, (&store, &fact), |(store, fact), tx| {
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
        .execute(tenant, &control, (&store, &changed), |(store, fact), tx| {
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
        .execute(tenant, &control, (&store, &missing), |(store, fact), tx| {
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
        .execute(
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
    startup_integrity(pool, &store, tenant, ledger, &control).await?;
    settlement_recovery(pool, ledger).await?;
    lock_then_fresh_snapshot(pool, ledger).await?;
    reject_damaged_receipt(&store, tenant, &fact, &control).await?;
    request.finalize(None);
    Ok(())
}
fn state(attempt: LocalTxAttempt<Committed<()>, TransactionError<Error>>) -> &'static str {
    attempt.fold(
        |_| "committed",
        |_| "not_started",
        |_| "rolled_back",
        |_| "rollback_failed",
        |_| "unknown",
        |_| "fenced",
    )
}
async fn bytes(pool: &PgPool, tenant: TenantId) -> Result<Vec<Vec<u8>>> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await?;
    let bytes = sqlx::query_scalar(
        "SELECT canonical FROM rss_audit.records WHERE tenant_id=$1::uuid ORDER BY position",
    )
    .bind(tenant.to_string())
    .fetch_all(&mut *tx)
    .await?;
    let receipts: i64 =
        sqlx::query_scalar("SELECT count(*) FROM mdm_audit.receipts WHERE tenant_id=$1::uuid")
            .bind(tenant.to_string())
            .fetch_one(&mut *tx)
            .await?;
    ensure!(receipts == bytes.len() as i64);
    let ledger_entries: i64 =
        sqlx::query_scalar("SELECT count(*) FROM rss_ledger.entries WHERE tenant_id=$1::uuid")
            .bind(tenant.to_string())
            .fetch_one(&mut *tx)
            .await?;
    let linked: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_audit.records WHERE tenant_id=$1::uuid AND ledger_sequence IS NOT NULL")
        .bind(tenant.to_string()).fetch_one(&mut *tx).await?;
    ensure!(ledger_entries == linked);
    tx.rollback().await?;
    Ok(bytes)
}

pub(crate) async fn request_store() -> Result<(PgPool, std::sync::Arc<AuditStore>)> {
    let options = PgConnectOptions::from_str(&std::env::var("MDM_OWNER_URL")?)?
        .username("mdm_access")
        .password("access-fixture")
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert(std::env::var("PG_CA_FILE")?);
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await?;
    let timer = crate::lifecycle::RuntimeTimer;
    let cancel = tokio_util::sync::CancellationToken::new();
    let deadline = Deadline::from_timeout(&timer, Duration::from_secs(2))?;
    let control = Control::new(&timer, deadline, &cancel);
    let store = AuditStore::new(pool.clone(), Integrity::Plain, &control).await?;
    Ok((pool, std::sync::Arc::new(store)))
}

async fn rejects_snapshot_isolation(pool: &PgPool) -> Result<()> {
    let timer = crate::lifecycle::RuntimeTimer;
    let cancel = tokio_util::sync::CancellationToken::new();
    let deadline = Deadline::from_timeout(&timer, Duration::from_secs(2))?;
    let control = Control::new(&timer, deadline, &cancel);
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
    control: &Control<'_, crate::lifecycle::RuntimeTimer>,
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
    for damage in [
        "UPDATE mdm_audit.receipts SET canonical=decode('01','hex') WHERE tenant_id=$1::uuid",
        "DELETE FROM mdm_audit.receipts WHERE tenant_id=$1::uuid",
    ] {
        sqlx::query(damage)
            .bind(tenant.to_string())
            .execute(&mut owner)
            .await?;
        let attempt = store
            .execute(tenant, control, (store, fact), |(store, fact), tx| {
                Box::pin(async move { store.append(tx, fact, true).await })
            })
            .await;
        ensure!(state(attempt) == "rolled_back");
        let records: i64 =
            sqlx::query_scalar("SELECT count(*) FROM rss_audit.records WHERE tenant_id=$1::uuid")
                .bind(tenant.to_string())
                .fetch_one(&mut owner)
                .await?;
        ensure!(records == 1);
    }
    owner.close().await?;
    Ok(())
}

fn integrity(ledger: bool) -> Result<Integrity> {
    Ok(if ledger {
        Integrity::Ledger(std::sync::Arc::new(rss_ledger::Authenticator::new(
            rss_ledger::KeyId::parse("mdm-audit-fixture")?,
            vec![19; 32],
        )?))
    } else {
        Integrity::Plain
    })
}
async fn settlement_recovery(pool: &PgPool, ledger: bool) -> Result<()> {
    let timer = crate::lifecycle::RuntimeTimer;
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = Control::new(
        &timer,
        Deadline::from_timeout(&timer, Duration::from_secs(3))?,
        &cancel,
    );
    let store = AuditStore::new(pool.clone(), integrity(ledger)?, &control).await?;
    let tenant = TenantId::parse(&Uuid::new_v4().to_string())?;
    let request = RequestAudit::new(tenant.to_string(), "audit_recovery_test");
    let fact = Fact::business(&request, "commit-ack-loss", b"A", 200, "success", None)?;
    store.inject_next_fault(rss_audit_postgres::PgFault::CommitUnknownAfterAck);
    let attempt = store
        .execute(tenant, &control, (&store, &fact), |(s, f), tx| {
            Box::pin(async move { s.append(tx, f, false).await })
        })
        .await;
    ensure!(state(attempt) == "unknown");
    let original = bytes(pool, tenant).await?;
    ensure!(original.len() == 1);
    let attempt = store
        .execute(tenant, &control, (&store, &fact), |(s, f), tx| {
            Box::pin(async move { s.append(tx, f, true).await })
        })
        .await;
    ensure!(state(attempt) == "committed");
    ensure!(bytes(pool, tenant).await? == original);
    let failed = Fact::business(&request, "rollback-ack-loss", b"B", 200, "success", None)?;
    store.inject_next_fault(rss_audit_postgres::PgFault::RollbackFailedAfterAck);
    let attempt = store
        .execute(tenant, &control, (&store, &failed), |(s, f), tx| {
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
        opposite.validate_tenant(tenant, control).await.is_err(),
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
            wrong.validate_tenant(tenant, control).await.is_err(),
            "same ID with wrong secret must fail before serving requests"
        );
    }
    Ok(())
}

async fn crash_write<T: rss_request_context::ExecutionTimer>(
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
            "audit_integration_tests::audit_process_exit_fixture",
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
#[ignore = "child process owned and killed by installed Audit recovery T2"]
async fn audit_process_exit_fixture() -> Result<()> {
    let tenant = TenantId::parse(&std::env::var("MDM_AUDIT_CRASH_TENANT")?)?;
    let ledger = std::env::var("MDM_AUDIT_CRASH_LEDGER")? == "1";
    let options = PgConnectOptions::from_str(&std::env::var("MDM_OWNER_URL")?)?
        .username("mdm_access")
        .password("access-fixture")
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert(std::env::var("PG_CA_FILE")?);
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await?;
    let timer = crate::lifecycle::RuntimeTimer;
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = Control::new(
        &timer,
        Deadline::from_timeout(&timer, Duration::from_secs(30))?,
        &cancel,
    );
    let store = AuditStore::new(pool, integrity(ledger)?, &control).await?;
    let request = RequestAudit::new(tenant.to_string(), "audit_recovery_test");
    let fact = Fact::business(
        &request,
        "process-interruption",
        b"crash-device",
        200,
        "success",
        None,
    )?;
    let attempt = store
        .execute(tenant, &control, (&store, &fact), |(store, fact), tx| {
            Box::pin(async move {
                crash_write(store, tx, fact).await?;
                println!("MDM_AUDIT_STAGED");
                use std::io::Write;
                std::io::stdout().flush().expect("ready marker");
                std::future::pending::<Result<(), Error>>().await
            })
        })
        .await;
    anyhow::bail!("crash fixture unexpectedly settled: {}", state(attempt));
}

// Exercise the real retirement backlog size under the product's owner budget in
// both modes; each event retains a separate identity and exact recovery receipt.
async fn retirement_batch(pool: &PgPool, ledger: bool) -> Result<()> {
    assert_eq!(
        crate::registration_lifecycle::TRANSACTION_BUDGET,
        Duration::from_secs(6)
    );
    let timer = crate::lifecycle::RuntimeTimer;
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = Control::new(
        &timer,
        Deadline::from_timeout(&timer, Duration::from_secs(6))?,
        &cancel,
    );
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
        let control = Control::new(
            &timer,
            Deadline::from_timeout(&timer, Duration::from_secs(6))?,
            &cancel,
        );
        let attempt = store
            .execute(tenant, &control, (&store, &facts), |(store, facts), tx| {
                Box::pin(async move {
                    for fact in facts.iter() {
                        store.append(tx, fact, replayed).await?;
                    }
                    Ok::<_, Error>(())
                })
            })
            .await;
        ensure!(
            state(attempt) == "committed",
            "retirement batch mode ledger={ledger} replay={replayed}"
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
