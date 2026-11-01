//! Bind the stable comparison identity in the caller's existing transaction.
use rss_transactional_messaging_postgres::{PgError, PgTransaction};
pub async fn bind_in(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut PgTransaction<'_>,
    key_id: &str,
) -> Result<(), PgError> {
    let tenant = tx.tenant_id().to_string();
    let key_id = key_id.to_owned();
    tx.with_connection(move |c| {
        Box::pin(async move {
            let admitted: bool = sqlx::query_scalar(crate::storage_profile::sql(profile).admission)
                .fetch_one(&mut *c)
                .await?;
            if !admitted {
                return Err(sqlx::Error::Protocol("native protection admission".into()));
            }
            sqlx::query(crate::storage_profile::sql(profile).insert)
                .bind(&tenant)
                .bind(&key_id)
                .execute(&mut *c)
                .await?;
            let matches: bool = sqlx::query_scalar(crate::storage_profile::sql(profile).read)
                .bind(tenant)
                .bind(key_id)
                .fetch_one(c)
                .await?;
            if !matches {
                return Err(sqlx::Error::Protocol(
                    "native protection key mismatch".into(),
                ));
            }
            Ok(())
        })
    })
    .await
}
