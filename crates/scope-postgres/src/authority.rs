//! Validate Scope's privileged functions against their sole installation source.
pub async fn verify_authority(c: &mut sqlx::PgConnection) -> Result<(), sqlx::Error> {
    let admission = crate::INSTALL_SQL
        .split_once("CREATE FUNCTION mdm_scope.scope_admission(")
        .expect("owner function")
        .1
        .split("$$")
        .nth(1)
        .expect("owner body");
    let state = crate::INSTALL_SQL
        .split_once("CREATE FUNCTION mdm_scope.scope_state(")
        .expect("owner function")
        .1
        .split("$$")
        .nth(1)
        .expect("owner body");
    let rejected: Option<String> = sqlx::query_scalar(include_str!("authority-admission.sql"))
        .bind(admission)
        .bind(state)
        .fetch_optional(c)
        .await?;
    if rejected.is_some() {
        return Err(sqlx::Error::Protocol("Scope authority rejected".into()));
    }
    Ok(())
}
