//! Owner-specific trusted authorization and fencing functions.
//! Function bodies use installation SQL directly; no deparser or schema snapshot is involved.
/// Reject a missing or altered privileged kernel before exposing this capability.
pub async fn verify_authority(
    profile: rss_mdm_install_support::StorageProfile,
    connection: &mut sqlx::PgConnection,
) -> Result<(), sqlx::Error> {
    let body_1 = crate::collection_sql(profile)
        .split_once(crate::storage_profile::sql(profile).authority_header_1)
        .expect("owner function")
        .1
        .split("$$")
        .nth(1)
        .expect("owner function body");
    let body_2 = crate::collection_sql(profile)
        .split_once(crate::storage_profile::sql(profile).authority_header_2)
        .expect("owner function")
        .1
        .split("$$")
        .nth(1)
        .expect("owner function body");
    let body_3 = crate::collection_metadata_sql(profile)
        .split_once(crate::storage_profile::sql(profile).authority_header_3)
        .expect("owner function")
        .1
        .split("$$")
        .nth(1)
        .expect("owner function body");
    let body_4 = crate::read_snapshot_sql(profile)
        .split_once(crate::storage_profile::sql(profile).authority_header_4)
        .expect("owner function")
        .1
        .split("$$")
        .nth(1)
        .expect("owner function body");
    let rejected: Option<String> =
        sqlx::query_scalar(crate::storage_profile::sql(profile).authority_admission)
            .bind(body_1)
            .bind(body_2)
            .bind(body_3)
            .bind(body_4)
            .fetch_optional(&mut *connection)
            .await?;
    if let Some(signature) = rejected {
        return Err(sqlx::Error::Protocol(format!(
            "trusted function rejected: {signature}"
        )));
    }
    let valid: bool = sqlx::query_scalar(crate::storage_profile::sql(profile).trigger_admission)
        .fetch_one(connection)
        .await?;
    if !valid {
        return Err(sqlx::Error::Protocol(
            "collection immutable history triggers".into(),
        ));
    }
    Ok(())
}
