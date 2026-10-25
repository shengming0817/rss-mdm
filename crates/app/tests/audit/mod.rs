//! Real component and product receipt composition against the installer-owned schema.
use anyhow::{Result, ensure};
use rss_audit_postgres::{Control, Integrity};
use rss_mdm_audit_integration::{AuditStore, Error, Fact, RequestAudit};
use rss_mdm_audit_integration::{TransactionError, budget::SourceControl};
use rss_request_context::{Deadline, TenantId};
use rss_transactional_messaging::transaction::LocalTxAttempt;
use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions, PgSslMode},
};
use std::{str::FromStr, time::Duration};
use uuid::Uuid;

fn state<R, E>(attempt: LocalTxAttempt<R, E>) -> &'static str {
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
        "SELECT source_bytes FROM mdm_audit.receipts WHERE tenant_id=$1::uuid ORDER BY source_id,event_id",
    ).bind(tenant.to_string()).fetch_all(&mut *tx).await?;
    let missing: i64 = sqlx::query_scalar("SELECT count(*) FROM mdm_audit.receipts r LEFT JOIN rss_transactional_messaging.outbox o ON o.tenant_id=r.tenant_id AND o.message_id=r.message_id AND o.domain='mdm.audit' WHERE r.tenant_id=$1::uuid AND o.message_id IS NULL")
        .bind(tenant.to_string()).fetch_one(&mut *tx).await?;
    ensure!(
        missing == 0,
        "source receipt and Outbox must commit together"
    );
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

pub(crate) async fn new_store(
    pool: PgPool,
    integrity: Integrity,
    tenant: TenantId,
) -> Result<AuditStore> {
    new_store_with_limits(pool, integrity, tenant, Default::default()).await
}

async fn new_store_with_limits(
    pool: PgPool,
    integrity: Integrity,
    tenant: TenantId,
    limits: rss_mdm_audit_integration::BacklogLimits,
) -> Result<AuditStore> {
    // Random tenants isolate receipt and integrity observations in the existing fixture DB.
    use sqlx::Connection;
    let options = PgConnectOptions::from_str(&std::env::var("MDM_OWNER_URL")?)?
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert(std::env::var("PG_CA_FILE")?);
    let mut owner = sqlx::PgConnection::connect_with(&options).await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(tenant.to_string())
        .execute(&mut owner)
        .await?;
    sqlx::query("INSERT INTO rss_transactional_messaging.tenant_epoch(tenant_id,epoch) VALUES($1::uuid,1) ON CONFLICT DO NOTHING")
        .bind(tenant.to_string()).execute(&mut owner).await?;
    owner.close().await?;
    let runtime = crate::audit_test_support::source_runtime(&pool, tenant).await?;
    let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5));
    Ok(AuditStore::new(pool, integrity, runtime, tenant, limits, &budget.control()).await?)
}
