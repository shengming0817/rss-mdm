//! Owner-specific trusted authorization and fencing functions.
//! Function bodies use installation SQL directly; no deparser or schema snapshot is involved.
/// Reject a missing or altered privileged kernel before exposing this capability.
pub async fn verify_authority(
    profile: rss_mdm_install_support::StorageProfile,
    connection: &mut sqlx::PgConnection,
) -> Result<(), sqlx::Error> {
    let body_1 = crate::storage_profile::sql(profile)
        .migration
        .split("$$")
        .nth(1)
        .expect("Policy authority body");
    let rejected: Option<String> =
        sqlx::query_scalar(crate::storage_profile::sql(profile).authority_admission)
            .bind(body_1)
            .fetch_optional(connection)
            .await?;
    if let Some(signature) = rejected {
        return Err(sqlx::Error::Protocol(format!(
            "trusted function rejected: {signature}"
        )));
    }
    Ok(())
}
