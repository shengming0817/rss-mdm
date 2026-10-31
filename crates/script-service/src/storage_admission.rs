//! Exact owner storage and privileged retirement admission.
pub async fn verify_storage(c: &mut sqlx::PgConnection) -> Result<(), sqlx::Error> {
    if !sqlx::query_scalar::<_, bool>(include_str!("storage-admission.sql"))
        .fetch_one(&mut *c)
        .await?
    {
        return Err(sqlx::Error::Protocol("task owner storage rejected".into()));
    }
    let body_1 = include_str!("../schema/task-retirement.sql")
        .split_once("CREATE FUNCTION mdm_script.save_retired_run(")
        .expect("owner function")
        .1
        .split("$$")
        .nth(1)
        .expect("function body");
    let rejected: Option<String> = sqlx::query_scalar(include_str!("retirement-admission.sql"))
        .bind(body_1)
        .fetch_optional(c)
        .await?;
    if let Some(signature) = rejected {
        return Err(sqlx::Error::Protocol(format!(
            "task retirement authority rejected: {signature}"
        )));
    }
    Ok(())
}
