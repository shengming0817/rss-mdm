//! Host storage identity, capability contract checks and shared cursor secret.
use crate::{Error, Failure, transaction::*};
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::{PgRuntime, PgTransaction};
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

/// Verify the capability's runtime authority on the borrowed transaction.
pub(crate) async fn verify_contract(
    tx: &mut PgTransaction<'_>,
    admission: &'static str,
    failure: Failure,
) -> Result<()> {
    let valid = tx
        .with_connection(move |c| {
            Box::pin(async move {
                crate::verify_authority(c).await?;
                sqlx::query_scalar::<_, bool>(admission).fetch_one(c).await
            })
        })
        .await?;
    if !valid {
        return Err(Error::Unavailable(failure).into());
    }
    Ok(())
}
