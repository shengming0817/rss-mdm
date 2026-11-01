//! Verify the exact owner bodies and ACL of the privileged retirement participants.
pub async fn verify_storage(c: &mut sqlx::PgConnection) -> Result<(), sqlx::Error> {
    let native = include_str!("../schema/native.sql");
    let relations = include_str!("../schema/task-relations.sql");
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
