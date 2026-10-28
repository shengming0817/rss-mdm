//! Execution owns channel projection, qualification and rollout facts.
mod projection;
pub mod targets;
pub use projection::ScopeProjection;

pub mod source;

/// Access reads the published channel projection without any write capability.
pub async fn verify_access(connection: &mut sqlx::PgConnection) -> Result<(), sqlx::Error> {
    let valid: bool = sqlx::query_scalar(include_str!("admission.sql"))
        .bind(false)
        .fetch_one(connection)
        .await?;
    if !valid {
        return Err(sqlx::Error::Protocol(
            "Scope projection reader rejected".into(),
        ));
    }
    Ok(())
}
