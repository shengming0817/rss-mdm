//! Closed admission composed from capability-owned contracts.
use serde_json::{Value, json};

/// Verify a connection role and the union of its owners' exact privilege contracts.
/// Additional relations, column privileges, functions or policies fail admission.
pub async fn verify(
    connection: &mut sqlx::PgConnection,
    role: &str,
    contracts: &[&str],
) -> Result<bool, sqlx::Error> {
    let mut merged =
        json!({"tables":[],"functions":[],"external_relations":[],"verified_schemas":[]});
    for contract in contracts {
        let value: Value = serde_json::from_str(contract)
            .map_err(|_| sqlx::Error::Protocol("invalid static access contract".into()))?;
        for key in [
            "tables",
            "functions",
            "external_relations",
            "verified_schemas",
        ] {
            let entries = value[key]
                .as_array()
                .ok_or_else(|| sqlx::Error::Protocol("invalid static access contract".into()))?;
            merged[key]
                .as_array_mut()
                .expect("static arrays")
                .extend(entries.iter().cloned());
        }
    }
    // Render policy expressions independent of the connection's default search path.
    sqlx::query("SELECT set_config('search_path','pg_catalog',true)")
        .execute(&mut *connection)
        .await?;
    sqlx::query_scalar(include_str!("access-admission.sql"))
        .bind(role)
        .bind(merged)
        .fetch_one(connection)
        .await
}
