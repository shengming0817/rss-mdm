//! Metadata only: no signed configuration, connections, signature or secret material.
use super::*;
use rss_mdm_query::directory::{Field, Kind, Query, Schema};
use serde_json::Value;
pub static SCHEMA: Schema = Schema {
    id: "agent_configurations",
    keys: &["configurationId"],
    default_limit: 64,
    max_limit: 1000,
    fields: &[
        Field::scalar("configurationId", Kind::Uuid),
        Field::scalar("state", Kind::Enum(&["available", "revoked", "expired"])),
        Field::scalar("createdAt", Kind::Integer),
        Field::scalar("expiresAt", Kind::Integer),
        Field::scalar("createdBy", Kind::Text),
        Field::filter_only("platform", Kind::EnumSet(&["windows", "macos"])),
        Field::filter_only("architecture", Kind::EnumSet(&["x86_64", "aarch64"])),
        Field::output("targets"),
        Field::output("quantity"),
        Field::output("reserved"),
        Field::output("consumed"),
        Field::output("remaining"),
    ],
};
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
fn column(name: &str) -> &'static str {
    match name {
        "configurationId" => "id::text COLLATE \"C\"",
        "state" => {
            "(CASE WHEN state='revoked' THEN 'revoked' WHEN expires_at<=statement_timestamp() THEN 'expired' ELSE 'available' END) COLLATE \"C\""
        }
        "createdAt" => "floor(extract(epoch FROM created_at))::bigint",
        "expiresAt" => "floor(extract(epoch FROM expires_at))::bigint",
        "createdBy" => "creator COLLATE \"C\"",
        "platform" => {
            "ARRAY(SELECT x->>'platform' FROM jsonb_array_elements(document->'targets') x)"
        }
        "architecture" => {
            "ARRAY(SELECT x->>'architecture' FROM jsonb_array_elements(document->'targets') x)"
        }
        _ => unreachable!("checked configuration field"),
    }
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
            profile,
            &mut tx,
            p.tenant_id(),
            p.instance_id(),
        )
        .await?;
        let binding = q
            .binding(&(p.tenant_id(), p.instance_id(), current.query_binding(p)?))
            .map_err(error)?;
        let after = q.after(&self.cursor, &binding).map_err(error)?;
        let mut sql = sqlx::QueryBuilder::new(
            crate::storage_profile::sql(profile)
                .agent_configurations_directory_configuration_directory_1,
        );
        sql.push_bind(p.tenant_id().to_owned()).push("::uuid");
        rss_mdm_query_postgres::append(&mut sql, q, after.as_ref(), column).map_err(error)?;
        // Reapply the same order after aggregation; no implicit CTE order is assumed.
        sql.push(
            crate::storage_profile::sql(profile)
                .agent_configurations_directory_configuration_directory_2,
        );
        for (i, sort) in q.sort().iter().enumerate() {
            sql.push(if i == 0 { " ORDER BY " } else { "," });
            sql.push(match sort.field.as_str() {
                "configurationId" => "c.id::text COLLATE \"C\"",
                "state" => "c.effective_state COLLATE \"C\"",
                "createdAt" => "c.created",
                "expiresAt" => "c.expiry",
                "createdBy" => "c.creator COLLATE \"C\"",
                _ => unreachable!("checked configuration order"),
            });
            sql.push(if sort.descending {
                " DESC NULLS LAST"
            } else {
                " ASC NULLS LAST"
            });
        }
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
