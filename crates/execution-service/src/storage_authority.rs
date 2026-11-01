//! Owner-specific trusted authorization and fencing functions.
//! Function bodies use installation SQL directly; no deparser or schema snapshot is involved.
/// Reject a missing or altered privileged kernel before exposing this capability.
pub async fn verify_authority(connection: &mut sqlx::PgConnection) -> Result<(), sqlx::Error> {
    let recovery_key = crate::INSTALL_SQL
        .split_once("CREATE FUNCTION mdm_commands.recovery_key(")
        .expect("recovery key")
        .1
        .split("$$")
        .nth(1)
        .expect("recovery key body");
    let rejected: Option<String> = sqlx::query_scalar(include_str!("authority-admission.sql"))
        .bind(recovery_key)
        .fetch_optional(connection)
        .await?;
    if let Some(signature) = rejected {
        return Err(sqlx::Error::Protocol(format!(
            "trusted function rejected: {signature}"
        )));
    }
    Ok(())
}
