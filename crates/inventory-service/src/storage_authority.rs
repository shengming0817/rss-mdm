//! Owner-specific trusted authorization and fencing functions.
//! Function bodies use installation SQL directly; no deparser or schema snapshot is involved.
/// Reject a missing or altered privileged kernel before exposing this capability.
pub async fn verify_authority(connection: &mut sqlx::PgConnection) -> Result<(), sqlx::Error> {
    let body_1 = include_str!("../schema/install.sql")
        .split_once("CREATE FUNCTION mdm_access.capture_collection_history(")
        .expect("owner function")
        .1
        .split("$$")
        .nth(1)
        .expect("owner function body");
    let body_2 = include_str!("../schema/install.sql")
        .split_once("CREATE FUNCTION mdm_access.immutable_collection(")
        .expect("owner function")
        .1
        .split("$$")
        .nth(1)
        .expect("owner function body");
    let body_3 = include_str!("../schema/collection-metadata.sql")
        .split_once("CREATE FUNCTION mdm_access.capture_collection_metadata(")
        .expect("owner function")
        .1
        .split("$$")
        .nth(1)
        .expect("owner function body");
    let rejected: Option<String> = sqlx::query_scalar(include_str!("authority-admission.sql"))
        .bind(body_1)
        .bind(body_2)
        .bind(body_3)
        .fetch_optional(&mut *connection)
        .await?;
    if let Some(signature) = rejected {
        return Err(sqlx::Error::Protocol(format!(
            "trusted function rejected: {signature}"
        )));
    }
    let valid: bool = sqlx::query_scalar(include_str!("collection-trigger-admission.sql"))
        .fetch_one(connection)
        .await?;
    if !valid {
        return Err(sqlx::Error::Protocol(
            "collection immutable history triggers".into(),
        ));
    }
    Ok(())
}
