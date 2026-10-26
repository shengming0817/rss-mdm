//! Owner-specific trusted authorization and fencing functions.
//! Function bodies use installation SQL directly; no deparser or schema snapshot is involved.
/// Reject a missing or altered privileged kernel before exposing this capability.
pub async fn verify_authority(connection: &mut sqlx::PgConnection) -> Result<(), sqlx::Error> {
    let body_1 = include_str!("../schema/object-qualification.sql")
        .split_once("CREATE FUNCTION mdm_devices.object_current(")
        .expect("owner function")
        .1
        .split("$$")
        .nth(1)
        .expect("owner function body");
    let body_2 = include_str!("../schema/install.sql")
        .split_once("CREATE FUNCTION mdm_devices.association_grant_current(")
        .expect("owner function")
        .1
        .split("$$")
        .nth(1)
        .expect("owner function body");
    let body_3 = include_str!("../schema/install.sql")
        .split_once("CREATE FUNCTION mdm_devices.advance_relation_revision(")
        .expect("owner function")
        .1
        .split("$$")
        .nth(1)
        .expect("owner function body");
    let body_4 = include_str!("../schema/install.sql")
        .split_once("CREATE FUNCTION mdm_devices.capture_identity_watermark(")
        .expect("owner function")
        .1
        .split("$$")
        .nth(1)
        .expect("owner function body");
    let body_5 = include_str!("../schema/install.sql")
        .split_once("CREATE FUNCTION mdm_devices.guard_input_publication(")
        .expect("owner function")
        .1
        .split("$$")
        .nth(1)
        .expect("owner function body");
    let rejected: Option<String> = sqlx::query_scalar(include_str!("authority-admission.sql"))
        .bind(body_1)
        .bind(body_2)
        .bind(body_3)
        .bind(body_4)
        .bind(body_5)
        .fetch_optional(connection)
        .await?;
    if let Some(signature) = rejected {
        return Err(sqlx::Error::Protocol(format!(
            "trusted function rejected: {signature}"
        )));
    }
    Ok(())
}
