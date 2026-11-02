//! Verify the exact owner bodies and ACL of the privileged retirement participants.
pub async fn verify_storage(c: &mut sqlx::PgConnection) -> Result<(), sqlx::Error> {
    verify_agent_authority(rss_mdm_install_support::StorageProfile::Mdm, c).await?;
    let native = include_str!("../schema/native.sql");
    let relations = crate::task_relations_sql(rss_mdm_install_support::StorageProfile::Mdm);
    let body_1 = native
        .split_once("CREATE FUNCTION mdm_recovery_tasks.native_status(")
        .expect("owner function")
        .1
        .split("$$")
        .nth(1)
        .expect("owner body");
    let body_2 = native
        .split_once("CREATE FUNCTION mdm_recovery_tasks.retirement_commands(")
        .expect("owner function")
        .1
        .split("$$")
        .nth(1)
        .expect("owner body");
    let body_3 = native
        .split_once("CREATE FUNCTION mdm_recovery_tasks.save_retired_command(")
        .expect("owner function")
        .1
        .split("$$")
        .nth(1)
        .expect("owner body");
    let body_4 = relations
        .split_once("CREATE FUNCTION mdm_recovery_tasks.save_retired_run(")
        .expect("owner function")
        .1
        .split("$$")
        .nth(1)
        .expect("owner body");
    let rejected: Option<String> = sqlx::query_scalar(include_str!("retirement-admission.sql"))
        .bind(body_1)
        .bind(body_2)
        .bind(body_3)
        .bind(body_4)
        .fetch_optional(c)
        .await?;
    if let Some(name) = rejected {
        return Err(sqlx::Error::Protocol(format!(
            "owner retirement authority rejected: {name}"
        )));
    }
    Ok(())
}

/// Common Agent retirement authority; native installation is not required.
pub async fn verify_agent_authority(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
) -> Result<(), sqlx::Error> {
    let sql = crate::storage_profile::sql(profile);
    let body = crate::task_relations_sql(profile)
        .split_once(sql.agent_authority_header)
        .expect("owner function")
        .1
        .split("$$")
        .nth(1)
        .expect("owner body");
    let host_roles: &[&str] = match profile {
        rss_mdm_install_support::StorageProfile::Da => &["mdm_access", "mdm_command_runtime"],
        rss_mdm_install_support::StorageProfile::Mdm => &[],
    };
    let rejected: Option<String> = sqlx::query_scalar(sql.agent_authority_admission)
        .bind(body)
        .bind(host_roles)
        .fetch_optional(c)
        .await?;
    if let Some(name) = rejected {
        return Err(sqlx::Error::Protocol(format!(
            "recovery authority rejected: {name}"
        )));
    }
    Ok(())
}
