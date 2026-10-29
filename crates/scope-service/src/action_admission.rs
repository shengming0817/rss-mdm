//! Transaction-bound current authorization and owner locks for action requests.
use crate::transaction::*;
use rss_transactional_messaging_postgres::PgTransaction;
pub(crate) async fn current(
    tx: &mut PgTransaction<'_>,
    proof: &crate::authorization::context::AuthorizedPrincipal,
) -> Result<crate::authorization::Snapshot> {
    if proof.tenant_id() != tx.tenant_id().to_string() {
        return Err(crate::Error::Forbidden.into());
    }
    let tenant = proof.tenant_id().to_owned();
    let instance = proof.instance_id().to_owned();
    let snapshot = tx
        .with_connection(move |c| {
            Box::pin(async move {
                // Native writers already hold these fences when revalidating authority.
                // Policy publication must take the same order before its authorization lock.
                crate::authorization::lock_shared_on(c, &tenant, &instance)
                    .await
                    .map_err(|_| sqlx::Error::Protocol("authorization lock".into()))?;
                Ok(crate::authorization::snapshot_on(c, &tenant, &instance).await)
            })
        })
        .await??;
    Ok(snapshot)
}
