//! Verify the exact owner bodies and ACL of the privileged retirement participants.
pub async fn verify_storage(c: &mut sqlx::PgConnection) -> Result<(), sqlx::Error> {
    let install = include_str!("../../../schema/device-access-tasks.sql");
    let body_1 = install
        .split_once("CREATE FUNCTION rss_da.save_retired_access_run(")
        .expect("owner function")
        .1
        .split("$$")
        .nth(1)
        .expect("owner body");
    let rejected: Option<String> = sqlx::query_scalar(include_str!("retirement-admission.sql"))
        .bind(body_1)
        .fetch_optional(c)
        .await?;
    if let Some(name) = rejected {
        return Err(sqlx::Error::Protocol(format!(
            "owner retirement authority rejected: {name}"
        )));
    }
    Ok(())
}
