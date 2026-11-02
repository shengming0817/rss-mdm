//! Function authority admission uses the owner's exact installation definitions.
pub async fn verify_authority(
    profile: rss_mdm_install_support::StorageProfile,
    connection: &mut sqlx::PgConnection,
) -> Result<(), sqlx::Error> {
    verify_authority_for_host(profile, connection, &[]).await
}

/// Host assembly may explicitly permit additional EXECUTE roles without changing the owner.
/// These roles are optional; body, owner, PUBLIC and grant-option checks stay unchanged.
pub async fn verify_authority_for_host(
    profile: rss_mdm_install_support::StorageProfile,
    connection: &mut sqlx::PgConnection,
    additional_roles: &[&str],
) -> Result<(), sqlx::Error> {
    let sql = crate::storage_profile::sql(profile);
    let mut bodies = sql.authority.split("$$").skip(1).step_by(2);
    let body_1 = bodies.next().expect("authority kernel");
    let body_2 = bodies.next().expect("authority predicate");
    let rejected: Option<String> = sqlx::query_scalar(sql.admission)
        .bind(body_1)
        .bind(body_2)
        .bind(additional_roles)
        .fetch_optional(connection)
        .await?;
    if let Some(signature) = rejected {
        return Err(sqlx::Error::Protocol(format!(
            "trusted function rejected: {signature}"
        )));
    }
    Ok(())
}
