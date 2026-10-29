//! Owner-specific trusted authorization and fencing functions.
//! Function bodies use installation SQL directly; no deparser or schema snapshot is involved.
/// Reject a missing or altered privileged kernel before exposing this capability.
pub async fn verify_authority(connection: &mut sqlx::PgConnection) -> Result<(), sqlx::Error> {
    let body_1 = include_str!("../schema/device-access.sql")
        .split_once("CREATE FUNCTION mdm_access.access_binding_ready(")
        .expect("owner function")
        .1
        .split("$$")
        .nth(1)
        .expect("owner function body");
    let body_2 = include_str!("../schema/directory.sql")
        .split_once("CREATE FUNCTION mdm_access.asset_sources_at(")
        .expect("owner function")
        .1
        .split("$$")
        .nth(1)
        .expect("owner function body");
    let rejected: Option<String> = sqlx::query_scalar(include_str!("authority-admission.sql"))
        .bind(body_1)
        .bind(body_2)
        .fetch_optional(connection)
        .await?;
    if let Some(signature) = rejected {
        return Err(sqlx::Error::Protocol(format!(
            "trusted function rejected: {signature}"
        )));
    }
    Ok(())
}
