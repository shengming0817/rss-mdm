//! Policy reference facts consumed under the Scope initiating transaction.
use rss_transactional_messaging_postgres::{PgError, PgTransaction};
use uuid::Uuid;
/// Whether any current Policy refers to the Scope, including rollout stages.
pub async fn used_in(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut PgTransaction<'_>,
    scope: Uuid,
) -> Result<bool, PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
                "SELECT EXISTS(SELECT FROM ({}) facts)",
                crate::storage_profile::sql(profile).scope_reference_facts
            )))
            .bind(tenant)
            .bind(scope)
            .fetch_one(c)
            .await
        })
    })
    .await
}

/// A stable bounded page of Policies referring to a Scope or rollout stage.
pub async fn dependents_in(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut PgTransaction<'_>,
    scope: Uuid,
    after: Option<String>,
) -> Result<Vec<Uuid>, PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query_scalar(crate::storage_profile::sql(profile).scope_dependents_in_1)
                .bind(tenant)
                .bind(scope.to_string())
                .bind(after)
                .fetch_all(c)
                .await
        })
    })
    .await
}

/// Minimal current Policy coordinate and reference roles, including archived policies.
pub struct Reference {
    /// Policy identity.
    pub id: Uuid,
    /// Current immutable version identity.
    pub version: Uuid,
    /// Current authored revision.
    pub revision: i64,
    /// Whether editing is permanently unavailable.
    pub archived: bool,
    /// Exact main-scope and rollout roles.
    pub roles: Vec<String>,
}
/// Read a keyset page using the exact predicate consumed by Scope deletion.
pub async fn references_in(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut PgTransaction<'_>,
    scope: Uuid,
    after: Option<Uuid>,
    limit: usize,
) -> Result<Vec<Reference>, PgError> {
    use sqlx::Row;
    if !(1..=1001).contains(&limit) {
        return Err(sqlx::Error::Protocol("scope reference page budget".into()).into());
    }
    let sql = format!(
        "SELECT * FROM ({}) facts WHERE ($3::uuid IS NULL OR id>$3) ORDER BY id LIMIT $4",
        crate::storage_profile::sql(profile).scope_reference_facts
    );
    let tenant = tx.tenant_id().to_string();
    let rows = tx
        .with_connection(move |c| {
            Box::pin(async move {
                sqlx::query(sqlx::AssertSqlSafe(sql.as_str()))
                    .bind(tenant)
                    .bind(scope)
                    .bind(after)
                    .bind(limit as i64)
                    .fetch_all(c)
                    .await
            })
        })
        .await?;
    rows.into_iter()
        .map(|r| {
            Ok(Reference {
                id: r.try_get("id")?,
                version: r.try_get("version")?,
                revision: r.try_get("revision")?,
                archived: r.try_get::<String, _>("state")? == "archived",
                roles: r.try_get("roles")?,
            })
        })
        .collect()
}
