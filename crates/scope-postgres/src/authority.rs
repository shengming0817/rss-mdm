//! Validate Scope's privileged functions against their sole installation source.
pub async fn verify_authority(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
) -> Result<(), sqlx::Error> {
    let admission = crate::install_sql(profile)
        .split_once(crate::storage_profile::sql(profile).authority_verify_authority_1)
        .expect("owner function")
        .1
        .split("$$")
        .nth(1)
        .expect("owner body");
    let state = crate::install_sql(profile)
        .split_once(crate::storage_profile::sql(profile).authority_verify_authority_2)
        .expect("owner function")
        .1
        .split("$$")
        .nth(1)
        .expect("owner body");
    let reference = crate::install_sql(profile)
        .split_once(crate::storage_profile::sql(profile).authority_verify_authority_3)
        .expect("owner reference function")
        .1
        .split("$$")
        .nth(1)
        .expect("owner reference body");
    let channel = crate::projections_sql(profile)
        .split_once(crate::storage_profile::sql(profile).authority_verify_authority_4)
        .expect("owner channel function")
        .1
        .split("$$")
        .nth(1)
        .expect("owner channel body");
    let rejected: Option<String> =
        sqlx::query_scalar(crate::storage_profile::sql(profile).authority_admission)
            .bind(admission)
            .bind(state)
            .bind(reference)
            .bind(channel)
            .fetch_optional(c)
            .await?;
    if rejected.is_some() {
        return Err(sqlx::Error::Protocol("Scope authority rejected".into()));
    }
    Ok(())
}
