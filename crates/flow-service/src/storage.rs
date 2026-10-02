//! Host storage identity, capability contract checks and shared cursor secret.
use crate::{Error, Failure, transaction::*};
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::{PgRuntime, PgTransaction};
use serde_json::Value;
// Immutable tenant secret shared by all instances. A retry always reads the
// committed winner, including when the original initialization commit was unknown.
pub async fn cursor_key(
    runtime: &PgRuntime,
    tenant: TenantId,
) -> std::result::Result<Vec<u8>, Error> {
    let mut candidate = vec![0; 32];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut candidate)
        .map_err(|_| Error::Unavailable(Failure::FlowAdmission))?;
    for _ in 0..3 {
        let result=runtime.local_tx_with_context(tenant,deadline(),&candidate,|candidate,tx| Box::pin(async move {
            let tenant=tx.tenant_id().to_string();
            let candidate=candidate.to_vec();
            tx.with_connection(move |c| Box::pin(async move {
                if let Some(key)=sqlx::query_scalar::<_,Vec<u8>>("SELECT secret FROM mdm_flow.cursor_keys WHERE tenant_id=$1::uuid").bind(&tenant).fetch_optional(&mut *c).await? { return Ok(key); }
                sqlx::query("INSERT INTO mdm_flow.cursor_keys(tenant_id,secret) VALUES($1::uuid,$2) ON CONFLICT DO NOTHING").bind(&tenant).bind(candidate).execute(&mut *c).await?;
                sqlx::query_scalar("SELECT secret FROM mdm_flow.cursor_keys WHERE tenant_id=$1::uuid").bind(tenant).fetch_one(c).await
            })).await
        })).await.fold(Some, |_|None, |_|None, |_|None, |_|None, |_|None);
        if let Some(key) = result {
            return Ok(key);
        }
    }
    Err(Error::Unavailable(Failure::FlowAdmission))
}

pub const CATALOG_SQL: &str = include_str!("storage/catalog.sql");

pub const CATALOG_JSON: &str = include_str!("storage/catalog.json");

/// Compare one capability's canonical storage contract on the caller's borrowed transaction.
pub(crate) async fn verify_contract(
    tx: &mut PgTransaction<'_>,
    query: &'static str,
    expected: &'static str,
    admission: &'static str,
    failure: Failure,
) -> Result<()> {
    let (valid, raw) = tx
        .with_connection(move |c| {
            Box::pin(async move {
                let valid = sqlx::query_scalar::<_, bool>(admission)
                    .fetch_one(&mut *c)
                    .await?;
                let raw = sqlx::query_scalar::<_, String>(query).fetch_one(c).await?;
                Ok((valid, raw))
            })
        })
        .await?;
    let actual: Value =
        serde_json::from_str(&raw).map_err(|_| Error::Unavailable(failure.clone()))?;
    let expected: Value = serde_json::from_str(expected).expect("canonical owner catalog");
    if !valid || actual != expected {
        return Err(Error::Unavailable(failure).into());
    }
    Ok(())
}
