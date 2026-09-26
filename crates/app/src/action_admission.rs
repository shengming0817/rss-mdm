//! Transaction-bound current authorization and owner locks for action requests.
use crate::transaction::*;
use rss_transactional_messaging_postgres::PgTransaction;
pub(crate) async fn lock(tx: &mut PgTransaction<'_>, device: &str) -> Result<()> {
    let key = format!("{}:{device}", tx.tenant_id());
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2465))")
                .bind(key)
                .execute(c)
                .await?;
            Ok(())
        })
    })
    .await?;
    Ok(())
}
pub(crate) async fn now(tx: &mut PgTransaction<'_>) -> Result<i64> {
    Ok(tx
        .with_connection(|c| {
            Box::pin(async move {
                sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                    .fetch_one(c)
                    .await
            })
        })
        .await?)
}
pub(crate) async fn authorized(
    tx: &mut PgTransaction<'_>,
    proof: &crate::authorization::context::AuthorizedPrincipal,
    device: &str,
    permission: crate::authorization::Permission,
) -> Result<crate::authorization::Snapshot> {
    let snapshot = current(tx, proof).await?;
    snapshot.require(proof, permission, Some(device))?;
    Ok(snapshot)
}
pub(crate) async fn current(
    tx: &mut PgTransaction<'_>,
    proof: &crate::authorization::context::AuthorizedPrincipal,
) -> Result<crate::authorization::Snapshot> {
    let tenant = proof.tenant_id().to_owned();
    let instance = proof.instance_id().to_owned();
    let snapshot = tx
        .with_connection(move |c| {
            Box::pin(async move {
                crate::authorization::lock_on(c, &tenant, &instance)
                    .await
                    .map_err(|_| sqlx::Error::Protocol("authorization lock".into()))?;
                Ok(crate::authorization::snapshot_on(c, &tenant, &instance).await)
            })
        })
        .await??;
    Ok(snapshot)
}
