use super::*;
use anyhow::{Context, Result, ensure};
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use rss_runtime::{LifecycleScope, ScopeExit, TotalDrainBudget};
use sqlx::{
    Connection, PgConnection,
    postgres::{PgConnectOptions, PgSslMode},
};
use std::str::FromStr;
use tower::ServiceExt;
const TENANT: &str = "11111111-1111-4111-8111-111111111111";

#[tokio::test]
#[ignore = "make t2 SUITE=identity: installed same-database Identity/Audit worker"]
async fn http_events_deliver_replay_and_fail_closed() -> Result<()> {
    for ledger in [false, true] {
        exercise(ledger).await?;
    }
    Ok(())
}
#[allow(
    clippy::cognitive_complexity,
    reason = "sequential real-PG failure/recovery matrix preserves ownership and cleanup assertions; production code remains checked"
)]
async fn exercise(ledger: bool) -> Result<()> {
    let fixture = std::path::PathBuf::from(std::env::var("MDM_TEST_CONFIG")?);
    let root = fixture.parent().unwrap();
    let database = format!("audit_worker_{}", uuid::Uuid::new_v4().simple());
    let admin_options = PgConnectOptions::from_str(&std::env::var("MDM_ADMIN_URL")?)?
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert(std::env::var("PG_CA_FILE")?);
    let mut administrator = PgConnection::connect_with(&admin_options).await?;
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "CREATE DATABASE {database} OWNER mdm_owner"
    )))
    .execute(&mut administrator)
    .await?;
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "GRANT CREATE ON DATABASE {database} TO mdm_audit_owner,mdm_ledger_owner"
    )))
    .execute(&mut administrator)
    .await?;
    let options = PgConnectOptions::from_str(&std::env::var("MDM_OWNER_URL")?)?
        .database(&database)
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert(std::env::var("PG_CA_FILE")?);
    let installation = crate::migration::Installation {
        audit_mode: if ledger {
            crate::migration::AuditMode::Ledger
        } else {
            crate::migration::AuditMode::Plain
        },
        instance_id: crate::identity_fixture::INSTANCE.into(),
        target: [1; 16],
        lineage: [2; 16],
        epoch: 1,
        tenants: vec![TENANT.into()],
    };
    crate::migration::migrate(&options, &installation).await?;
    let mut value: serde_json::Value = serde_json::from_slice(&std::fs::read(&fixture)?)?;
    for pointer in [
        "/identity/database/name",
        "/identity/audit_worker/name",
        "/access_database/name",
        "/runtime_database/name",
        "/execution/database/name",
        "/flow/storage/database/name",
    ] {
        *value.pointer_mut(pointer).unwrap() = database.clone().into();
    }
    if ledger {
        use std::os::unix::fs::PermissionsExt;
        let key = root.join("worker-ledger-key");
        std::fs::write(&key, [23u8; 32])?;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600))?;
        value["audit"] =
            serde_json::json!({"mode":"ledger", "key_id":"worker-fixture", "key_file":key});
    }
    let config: Config = serde_json::from_value(value.clone())?;
    let mut maintenance = value["identity"]["database"].clone();
    maintenance["user"] = "mdm_identity_maintenance".into();
    maintenance["password_file"] = root
        .join("mdm_identity_maintenance-password")
        .to_string_lossy()
        .to_string()
        .into();
    crate::maintenance::run(serde_json::from_value(serde_json::json!({
        "database":maintenance, "installation":installation, "tenant_id":TENANT,
        "principal_id":crate::identity_fixture::ADMIN, "login":"admin", "password_file":root.join("account-password")
    }))?, true).await?;
    let mut identity_resources = Vec::new();
    let identity = crate::identity::Identity::connect(
        &config,
        Arc::new(
            crate::authorization::identity_management::IdentityManagementPolicy::new(
                TENANT,
                crate::identity_fixture::INSTANCE,
                config.identity_management.clone(),
            )?,
        ),
        |r| identity_resources.push(r),
    )
    .await?;
    let request = Request::builder()
        .method("POST")
        .uri(format!("/api/v2/tenants/{TENANT}/login"))
        .header("host", "mdm.example.test")
        .header("origin", "https://mdm.example.test")
        .header("x-identity-request", "1")
        .header("content-type", "application/json")
        .extension(rss_identity_http_axum::ClientAddress("127.0.0.1".parse()?))
        .body(Body::from(serde_json::to_vec(
            &serde_json::json!({"login":"admin","password":crate::identity_fixture::PASSWORD}),
        )?))?;
    let response = identity.routes().oneshot(request).await?;
    ensure!(
        response.status() == StatusCode::OK,
        "login failed: {}",
        response.status()
    );
    drop(response);
    let observer = PgPoolOptions::new()
        .max_connections(3)
        .connect_with(admin_options.clone().database(&database))
        .await?;
    verify_ledger_privileges(&config, &observer, &options, &installation, ledger).await?;
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_audit.records")
        .fetch_one(&observer)
        .await?;
    ensure!(before == 0);
    run_worker(&config, &observer, 2, true).await?;
    let original: Vec<Vec<u8>> =
        sqlx::query_scalar("SELECT canonical FROM rss_audit.records ORDER BY position")
            .fetch_all(&observer)
            .await?;
    ensure!(original.len() == 2);
    let linked: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM rss_audit.records WHERE ledger_sequence IS NOT NULL",
    )
    .fetch_one(&observer)
    .await?;
    let entries: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_ledger.entries")
        .fetch_one(&observer)
        .await?;
    ensure!(linked == if ledger { 2 } else { 0 });
    ensure!(entries == linked);
    // Disposable fault injection: source acknowledgement loss must retain bytes and IDs.
    manipulate(
        &observer,
        "UPDATE rss_transactional_messaging.outbox SET status='pending' WHERE status='published'",
    )
    .await?;
    run_worker(&config, &observer, 2, false).await?;
    let replay: Vec<Vec<u8>> =
        sqlx::query_scalar("SELECT canonical FROM rss_audit.records ORDER BY position")
            .fetch_all(&observer)
            .await?;
    ensure!(original == replay);
    fatal_worker(&config, &observer, false).await?;
    fatal_worker(&config, &observer, true).await?;
    if ledger {
        for (revoke, grant) in [
            (
                "REVOKE SELECT ON rss_ledger.entries FROM mdm_identity_audit",
                "GRANT SELECT ON rss_ledger.entries TO mdm_identity_audit",
            ),
            (
                "REVOKE EXECUTE ON FUNCTION rss_ledger.prepare_append(uuid,text,text,smallint) FROM mdm_identity_audit",
                "GRANT EXECUTE ON FUNCTION rss_ledger.prepare_append(uuid,text,text,smallint) TO mdm_identity_audit",
            ),
        ] {
            sqlx::raw_sql(revoke).execute(&observer).await?;
            rejected(&config).await?; // empty/published Outbox must not bypass Ledger admission
            sqlx::raw_sql(grant).execute(&observer).await?;
        }
    }
    // Excess privileges are not silently repaired by construction or installation replay.
    sqlx::raw_sql("GRANT SELECT ON identity_authority.accounts TO mdm_identity_audit")
        .execute(&observer)
        .await?;
    rejected(&config).await?;
    ensure!(
        crate::migration::migrate(&options, &installation)
            .await
            .is_err()
    );
    sqlx::raw_sql("REVOKE SELECT ON identity_authority.accounts FROM mdm_identity_audit")
        .execute(&observer)
        .await?;
    sqlx::raw_sql("REVOKE SELECT ON rss_audit.records FROM mdm_identity_audit")
        .execute(&observer)
        .await?;
    rejected(&config).await?;
    sqlx::raw_sql("GRANT SELECT ON rss_audit.records TO mdm_identity_audit")
        .execute(&observer)
        .await?;
    manipulate(&observer, "UPDATE rss_transactional_messaging.outbox SET status='dead_letter' WHERE status='published'").await?;
    rejected(&config).await?;
    drop(identity);
    for resource in identity_resources.into_iter().rev() {
        resource.shutdown().await?;
    }
    observer.close().await;
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!("DROP DATABASE {database}")))
        .execute(&mut administrator)
        .await?;
    administrator.close().await?;
    Ok(())
}
#[allow(
    clippy::cognitive_complexity,
    reason = "real PostgreSQL privilege matrix keeps grant/reject/revoke cases together"
)]
async fn verify_ledger_privileges(
    config: &Config,
    observer: &PgPool,
    options: &PgConnectOptions,
    installation: &crate::migration::Installation,
    ledger: bool,
) -> Result<()> {
    let mut worker_connection =
        PgConnection::connect_with(&config.identity.audit_worker.options()?).await?;
    verify_profile(&mut worker_connection, config.audit.mode())
        .await
        .context("worker privilege baseline")?;
    worker_connection.close().await?;
    for (grant, revoke) in [
        (
            "GRANT CREATE ON SCHEMA rss_ledger TO mdm_identity_audit",
            "REVOKE CREATE ON SCHEMA rss_ledger FROM mdm_identity_audit",
        ),
        (
            "GRANT INSERT ON rss_ledger.entries TO mdm_identity_audit",
            "REVOKE INSERT ON rss_ledger.entries FROM mdm_identity_audit",
        ),
        (
            "GRANT UPDATE(tag) ON rss_ledger.entries TO mdm_identity_audit",
            "REVOKE UPDATE(tag) ON rss_ledger.entries FROM mdm_identity_audit",
        ),
        (
            "CREATE ROLE audit_set_only NOLOGIN; GRANT audit_set_only TO mdm_identity_audit WITH INHERIT FALSE; GRANT DELETE ON rss_ledger.entries TO audit_set_only",
            "REVOKE DELETE ON rss_ledger.entries FROM audit_set_only; REVOKE audit_set_only FROM mdm_identity_audit; DROP ROLE audit_set_only",
        ),
        (
            "GRANT INSERT ON rss_ledger.entries TO PUBLIC",
            "REVOKE INSERT ON rss_ledger.entries FROM PUBLIC",
        ),
        (
            "CREATE FUNCTION rss_ledger.unexpected() RETURNS integer LANGUAGE sql AS 'SELECT 1'",
            "DROP FUNCTION rss_ledger.unexpected()",
        ),
    ] {
        sqlx::raw_sql(grant).execute(observer).await?;
        rejected(config)
            .await
            .with_context(|| format!("worker accepted {grant}"))?;
        ensure!(
            crate::migration::migrate(options, installation)
                .await
                .is_err(),
            "installer accepted {grant}"
        );
        sqlx::raw_sql(revoke).execute(observer).await?;
    }
    if !ledger {
        for (grant, revoke) in [
            (
                "GRANT USAGE ON SCHEMA rss_ledger TO mdm_identity_audit",
                "REVOKE USAGE ON SCHEMA rss_ledger FROM mdm_identity_audit",
            ),
            (
                "GRANT SELECT ON rss_ledger.entries TO mdm_identity_audit",
                "REVOKE SELECT ON rss_ledger.entries FROM mdm_identity_audit",
            ),
            (
                "GRANT EXECUTE ON FUNCTION rss_ledger.prepare_append(uuid,text,text,smallint) TO mdm_identity_audit",
                "REVOKE EXECUTE ON FUNCTION rss_ledger.prepare_append(uuid,text,text,smallint) FROM mdm_identity_audit",
            ),
        ] {
            sqlx::raw_sql(grant).execute(observer).await?;
            rejected(config).await?;
            ensure!(
                crate::migration::migrate(options, installation)
                    .await
                    .is_err()
            );
            sqlx::raw_sql(revoke).execute(observer).await?;
        }
    }
    crate::migration::migrate(options, installation).await?;
    let mut transaction = observer.begin().await?;
    sqlx::raw_sql("SET LOCAL ROLE mdm_command_runtime; SET LOCAL search_path=pg_catalog")
        .execute(&mut *transaction)
        .await?;
    let actual: String = sqlx::query_scalar(include_str!("../execution/dependencies.sql"))
        .fetch_one(&mut *transaction)
        .await?;
    ensure!(
        serde_json::from_str::<serde_json::Value>(&actual)?
            == serde_json::from_str::<serde_json::Value>(include_str!(
                "../execution/dependencies.json"
            ))?,
        "command dependency admission must support both audit modes"
    );
    transaction.rollback().await?;
    Ok(())
}
async fn rejected(config: &Config) -> Result<()> {
    let mut resources = Vec::new();
    let result = Worker::open(config, Arc::default(), |r| resources.push(r)).await;
    ensure!(result.is_err());
    for resource in resources.into_iter().rev() {
        resource.shutdown().await?;
    }
    Ok(())
}
async fn run_worker(
    config: &Config,
    observer: &PgPool,
    expected: i64,
    transient: bool,
) -> Result<()> {
    let readiness = Arc::new(Readiness::default());
    let mut resources = Vec::new();
    let worker = Worker::open(config, readiness.clone(), |r| resources.push(r)).await?;
    ensure!(!readiness.ready());
    let mut scope = LifecycleScope::<(), std::io::Error, std::io::Error>::try_new(
        TotalDrainBudget::new(Duration::from_secs(40))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let signal = async {
        let check = async {
            wait_delivered(observer, &readiness, expected).await?;
            if transient {
                let mut holder = observer.begin().await?;
                sqlx::query(
                    "LOCK TABLE rss_transactional_messaging.outbox IN ACCESS EXCLUSIVE MODE",
                )
                .execute(&mut *holder)
                .await?;
                while readiness.ready() {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                holder.rollback().await?;
                wait_delivered(observer, &readiness, expected).await?;
            }
            Ok::<(), anyhow::Error>(())
        };
        tokio::time::timeout(Duration::from_secs(30), check)
            .await
            .map_err(std::io::Error::other)?
            .map_err(std::io::Error::other)
    };
    let outcome = scope
        .drive(
            |mut startup| {
                Box::pin(async move {
                    for resource in resources {
                        startup.stage_resource(resource);
                    }
                    let mut launch = startup.commit();
                    launch.stage_deferred_task_with_token(worker.registration().critical());
                    launch.finish();
                    std::future::pending().await
                })
            },
            signal,
        )
        .await?;
    if let ScopeExit::StopRequested(Err(error)) = outcome.exit() {
        return Err(anyhow::anyhow!("worker verification: {error}"));
    }
    ensure!(matches!(outcome.exit(), ScopeExit::StopRequested(Ok(()))));
    ensure!(outcome.shutdown().is_ok());
    ensure!(!readiness.ready());
    Ok(())
}
async fn wait_delivered(pool: &PgPool, readiness: &Readiness, expected: i64) -> Result<()> {
    loop {
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_audit.records")
            .fetch_one(pool)
            .await?;
        let pending: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM rss_transactional_messaging.outbox WHERE status <> 'published'",
        )
        .fetch_one(pool)
        .await?;
        if count == expected && pending == 0 && readiness.ready() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn manipulate(pool: &PgPool, statement: &str) -> Result<()> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('rss.storage_target',repeat('01',16),true),set_config('rss.storage_lineage',repeat('02',16),true),set_config('rss.execution_epoch','1',true)").bind(TENANT).execute(&mut *tx).await?;
    sqlx::raw_sql(sqlx::AssertSqlSafe(statement))
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

async fn fatal_worker(config: &Config, observer: &PgPool, fence: bool) -> Result<()> {
    let readiness = Arc::new(Readiness::default());
    let mut resources = Vec::new();
    let worker = Worker::open(config, readiness.clone(), |r| resources.push(r)).await?;
    let mut scope = LifecycleScope::<(), std::io::Error, std::io::Error>::try_new(
        TotalDrainBudget::new(Duration::from_secs(40))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let revoke = async {
        while !readiness.ready() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let change = if fence {
            "UPDATE rss_transactional_messaging.tenant_epoch SET epoch=2"
        } else {
            "REVOKE EXECUTE ON FUNCTION rss_transactional_messaging.claim_outbox(uuid,text,integer,bigint) FROM mdm_identity_audit"
        };
        sqlx::raw_sql(change)
            .execute(observer)
            .await
            .map_err(|_| std::io::Error::other("fixture revoke/fence"))?;
        std::future::pending::<Result<(), std::io::Error>>().await
    };
    let outcome = tokio::time::timeout(
        Duration::from_secs(20),
        scope.drive(
            |mut startup| {
                Box::pin(async move {
                    for resource in resources {
                        startup.stage_resource(resource);
                    }
                    let mut launch = startup.commit();
                    launch.stage_deferred_task_with_token(worker.registration().critical());
                    launch.finish();
                    std::future::pending().await
                })
            },
            revoke,
        ),
    )
    .await??;
    ensure!(
        matches!(outcome.exit(), ScopeExit::CriticalTaskExited(exit) if exit.name() == "identity-audit")
    );
    ensure!(!readiness.ready());
    if fence {
        sqlx::query("UPDATE rss_transactional_messaging.tenant_epoch SET epoch=1")
            .execute(observer)
            .await?;
    }
    let mut owner = observer.acquire().await?;
    rss_identity_postgres::audit::grant_worker(&mut owner, ROLE).await?;
    Ok(())
}

#[test]
fn fenced_progress_is_terminal_even_when_other_events_succeeded() {
    assert_eq!(should_wait(1, 0, 1), Err(AuditDeliveryError::OwnershipLost));
    assert_eq!(should_wait(1, 1, 0), Ok(true));
    assert_eq!(should_wait(1, 0, 0), Ok(false));
    assert_eq!(should_wait(0, 0, 0), Ok(true));
}

#[test]
fn retry_backoff_empty_polls_do_not_restore_health() {
    let readiness = Readiness::default();
    readiness.progress(0, 0);
    assert!(readiness.healthy.load(Ordering::Acquire));
    readiness.progress(1, 1);
    readiness.transient_failure();
    for _ in 0..3 {
        readiness.progress(0, 0);
        assert!(!readiness.healthy.load(Ordering::Acquire));
    }
    readiness.progress(1, 0);
    assert!(readiness.healthy.load(Ordering::Acquire));
}

#[test]
fn empty_success_recovers_claim_failure_without_a_pending_retry() {
    let readiness = Readiness::default();
    readiness.progress(0, 0);
    readiness.transient_failure();
    assert!(!readiness.healthy.load(Ordering::Acquire));
    readiness.progress(0, 0);
    assert!(readiness.healthy.load(Ordering::Acquire));
}
