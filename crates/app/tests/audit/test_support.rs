use super::*;
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
    let control = {
        let cutoff = Deadline::from_timeout(&timer, Duration::from_secs(30))?;
        Control::new(&timer, cutoff, cutoff, &cancel)
    };
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
        .write(tenant, &control, (&store, &fact), |(store, fact), tx| {
            Box::pin(async move {
                recovery::crash_write(store, tx, fact).await?;
                println!("MDM_AUDIT_STAGED");
                use std::io::Write;
                std::io::stdout().flush().expect("ready marker");
                std::future::pending::<Result<(), Error>>().await
            })
        })
        .await;
    anyhow::bail!("crash fixture unexpectedly settled: {}", state(attempt));
}
