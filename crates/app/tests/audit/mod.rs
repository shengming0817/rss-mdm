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

mod test_support;

// Exercise batch correctness independently of product performance policy in
// both modes; each event retains a separate identity and exact recovery receipt.

mod budget;
mod integrity;
mod receipts;
mod recovery;

const ROLES: [&str; 4] = [
    "mdm_access",
    "mdm_flow_runtime",
    "mdm_command_runtime",
    "mdm_software_driver",
];
async fn pool(role: &str) -> Result<PgPool> {
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
    Ok(PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await?)
}
