//! Owner-specific trusted authorization and fencing functions.
//! Function bodies use installation SQL directly; no deparser or schema snapshot is involved.
/// Reject a missing or altered privileged kernel before exposing this capability.
pub async fn verify_authority(connection: &mut sqlx::PgConnection) -> Result<(), sqlx::Error> {
    verify_common_authority(rss_mdm_install_support::StorageProfile::Mdm, connection).await?;
    let body_1 = include_str!("../schema/device-access.sql")
        .split_once("CREATE FUNCTION mdm_access.access_binding_ready(")
        .expect("owner function")
        .1
        .split("$$")
        .nth(1)
        .expect("owner function body");
    let body_2 = crate::directory_sql(rss_mdm_install_support::StorageProfile::Mdm)
        .split_once("CREATE FUNCTION mdm_access.asset_sources_at(")
        .expect("owner function")
        .1
        .split("$$")
        .nth(1)
        .expect("owner function body");
    let access_policy = include_str!("../schema/device-access-qualification.sql")
        .split_once("CREATE FUNCTION mdm_access.access_policy(")
        .expect("owner function")
        .1
        .split("$$")
        .nth(1)
        .expect("owner function body");
    let active_binding = include_str!("../schema/device-access-qualification.sql")
        .split_once("CREATE FUNCTION mdm_access.active_access_binding(")
        .expect("owner function")
        .1
        .split("$$")
        .nth(1)
        .expect("owner function body");
    let rejected: Option<String> = sqlx::query_scalar(include_str!("authority-admission.sql"))
        .bind(body_1)
        .bind(body_2)
        .bind(access_policy)
        .bind(active_binding)
        .fetch_optional(connection)
        .await?;
    if let Some(signature) = rejected {
        return Err(sqlx::Error::Protocol(format!(
            "trusted function rejected: {signature}"
        )));
    }
    Ok(())
}

/// Verify only the common registration kernels on their admitted runtime connection.
pub async fn verify_common_authority(
    profile: rss_mdm_install_support::StorageProfile,
    connection: &mut sqlx::PgConnection,
) -> Result<(), sqlx::Error> {
    let sql = crate::storage_profile::sql(profile);
    let capture = sql
        .install
        .split_once(sql.authority_capture_header)
        .expect("owner function")
        .1
        .split("$$")
        .nth(1)
        .expect("owner body");
    let sources = sql
        .directory
        .split_once(sql.authority_sources_header)
        .expect("owner function")
        .1
        .split("$$")
        .nth(1)
        .expect("owner body");
    let members = sql
        .member_authority
        .split_once(sql.authority_members_header)
        .expect("owner function")
        .1
        .split("$$")
        .nth(1)
        .expect("owner body");
    let seed = sql
        .agent_settings_tenant_seed_sql_1
        .split_once(sql.authority_seed_header)
        .expect("owner function")
        .1
        .split("$seed$")
        .nth(1)
        .expect("owner body");
    let retire = sql
        .enrollment_retirement
        .split_once(sql.authority_retire_header)
        .expect("owner function")
        .1
        .split("$$")
        .nth(1)
        .expect("owner body");
    let rejected: Option<String> = sqlx::query_scalar(sql.common_authority_admission)
        .bind(capture)
        .bind(sources)
        .bind(members)
        .bind(seed)
        .bind(retire)
        .fetch_optional(connection)
        .await?;
    if let Some(name) = rejected {
        return Err(sqlx::Error::Protocol(format!(
            "registration authority rejected: {name}"
        )));
    }
    Ok(())
}
