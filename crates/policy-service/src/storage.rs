//! Host storage identity, capability contract checks and shared cursor secret.
use crate::{Error, Failure, transaction::*};
use rss_transactional_messaging_postgres::PgTransaction;
/// Verify the capability's runtime authority on the borrowed transaction.
pub(crate) async fn verify_contract(
    tx: &mut PgTransaction<'_>,
    admission: &'static str,
    failure: Failure,
) -> Result<()> {
    let valid = tx
        .with_connection(move |c| {
            Box::pin(async move {
                rss_mdm_policy_postgres::verify_authority(c).await?;
                sqlx::query_scalar::<_, bool>(admission).fetch_one(c).await
            })
        })
        .await?;
    if !valid {
        return Err(Error::Unavailable(failure).into());
    }
    Ok(())
}
