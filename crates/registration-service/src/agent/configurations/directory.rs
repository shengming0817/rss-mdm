//! Metadata only: no signed configuration, connections, signature or secret material.
use super::*;
use rss_mdm_query::directory::{Query, Schema};
use serde_json::Value;
pub static SCHEMA: std::sync::LazyLock<Schema> = std::sync::LazyLock::new(|| {
    Schema::derived::<Metadata>("agent_configurations", &["configurationId"], 64, 1000, &[rss_mdm_query::directory::Exclusion { path: "targets", reason: "Each target combines platform and architecture; use the typed platform/architecture selectors with same-target matching" }]).and_then(|s| s.with_selectors::<TargetSelectors>("Installation target capabilities, matched within the same target")).expect("Public directory model")
});
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Metadata {
    configuration_id: Uuid,
    state: EffectiveState,
    created_at: i64,
    expires_at: i64,
    created_by: String,
    targets: Vec<wire_config::Target>,
    quantity: wire_config::Quantity,
    reserved: u64,
    consumed: u64,
    remaining: Option<u64>,
}
fn error(e: rss_mdm_query::Error) -> Error {
    match e {
        rss_mdm_query::Error::CursorInvalidated => Error::Conflict,
        _ => Error::Malformed,
    }
}
impl Service {
    pub async fn configuration_directory(
        &self,
        p: &AuthorizedPrincipal,
        q: &Query,
        audit: &RequestAudit,
    ) -> Result<rss_mdm_query::Page<rss_mdm_query::directory::Projection<Metadata>>, Failure> {
        let profile = self.profile();

        q.require_schema(&SCHEMA).map_err(error)?;
        self.proof(p, audit)?;
        p.manage(Permission::AgentEnrollmentRead)?;
        audit.set_action(
            "agent_configuration_read",
            rss_mdm_audit_integration::AuditIntent::Routine,
        );

        let mut tx = self.store.begin(p.tenant_id()).await?;
        authorize_on(profile, &mut tx, p, Permission::AgentEnrollmentRead).await?;
        let current = rss_mdm_authorization_service::snapshot_on(
            p.authority_profile(),
            &mut tx,
            p.tenant_id(),
            p.instance_id(),
        )
        .await?;
        let binding = q
            .binding(&(p.tenant_id(), p.instance_id(), current.query_binding(p)?))
            .map_err(error)?;
        let after = q.after(&self.cursor, &binding).map_err(error)?;
        let mut sql = sqlx::QueryBuilder::new("SELECT row FROM (");
        sql.push(
            crate::storage_profile::sql(profile)
                .agent_configurations_directory_configuration_directory_1,
        )
        .push_bind(p.tenant_id().to_owned())
        .push("::uuid")
        .push(
            crate::storage_profile::sql(profile)
                .agent_configurations_directory_configuration_directory_2,
        )
        .push(") records WHERE true");
        sql.push(
            " AND EXISTS (SELECT 1 FROM jsonb_array_elements(row->'targets') target WHERE true",
        );
        rss_mdm_query_postgres::filter(&mut sql, q, &*BINDINGS).map_err(error)?;
        sql.push(")");
        rss_mdm_query_postgres::page(&mut sql, q, after.as_ref(), &*BINDINGS).map_err(error)?;
        let rows: Vec<Value> = sql
            .build_query_scalar()
            .fetch_all(&mut *tx)
            .await
            .map_err(db)?;
        let rows = rows
            .into_iter()
            .map(serde_json::from_value::<Metadata>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| Error::Corrupt)?;
        for metadata in &rows {
            if metadata.configuration_id.is_nil() || metadata.targets.is_empty() {
                return Err(Error::Corrupt.into());
            }
        }
        p.check_live()?;
        let page = q.page_typed(rows, &self.cursor, &binding).map_err(error)?;
        tx.commit().await.map_err(db)?;
        Ok(page)
    }
}

#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
enum EffectiveState {
    Available,
    Revoked,
    Expired,
}

#[derive(schemars::JsonSchema)]
#[allow(dead_code)]
struct TargetSelectors {
    platform: rss_mdm_agent_wire::runtime::TaskPlatform,
    architecture: rss_mdm_agent_wire::runtime::TaskArchitecture,
}

pub static BINDINGS: std::sync::LazyLock<rss_mdm_query_postgres::Bindings> =
    std::sync::LazyLock::new(|| {
        rss_mdm_query_postgres::Bindings::new(
            &SCHEMA,
            &[
                rss_mdm_query_postgres::Source::json("configurationId", "row#>'{configurationId}'"),
                rss_mdm_query_postgres::Source::json("state", "row#>'{state}'"),
                rss_mdm_query_postgres::Source::json("createdAt", "row#>'{createdAt}'"),
                rss_mdm_query_postgres::Source::json("expiresAt", "row#>'{expiresAt}'"),
                rss_mdm_query_postgres::Source::json("createdBy", "row#>'{createdBy}'"),
                rss_mdm_query_postgres::Source::json("quantity", "row#>'{quantity}'"),
                rss_mdm_query_postgres::Source::json("reserved", "row#>'{reserved}'"),
                rss_mdm_query_postgres::Source::json("consumed", "row#>'{consumed}'"),
                rss_mdm_query_postgres::Source::json("remaining", "row#>'{remaining}'"),
                rss_mdm_query_postgres::Source::column(
                    "platform",
                    "(target->>'platform') COLLATE \"C\"",
                ),
                rss_mdm_query_postgres::Source::column(
                    "architecture",
                    "(target->>'architecture') COLLATE \"C\"",
                ),
            ],
        )
        .expect("Complete public model storage binding")
    });
