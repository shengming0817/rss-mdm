//! Scope authority adapter borrows Execution's original transaction connection.
use rss_mdm_execution_service::source_authority::*;
use rss_request_context::TenantId;
use serde_json::Value;
use sqlx::{PgConnection, Row};
use uuid::Uuid;

pub struct ExecutionSource;
fn admission(value: Value) -> Result<ScopeAdmission, SourceError> {
    match value["state"].as_str() {
        Some("eligible") => Ok(ScopeAdmission::Eligible {
            entry: value["entry"]
                .as_i64()
                .filter(|entry| *entry >= 0)
                .ok_or(SourceError::Invariant)?,
        }),
        Some("pending") => Ok(ScopeAdmission::Pending),
        Some("excluded") => Ok(ScopeAdmission::Excluded),
        _ => Err(SourceError::Invariant),
    }
}
impl SourceAuthority for ExecutionSource {
    fn preview_scope_on<'a>(
        &'a self,
        connection: &'a mut PgConnection,
        tenant: TenantId,
        scope: Uuid,
        after: Option<&'a str>,
    ) -> Pending<'a, ScopePreview> {
        Box::pin(async move {
            let result = sqlx::query_scalar::<_, Option<Uuid>>("SELECT resolution FROM mdm_planning.scopes WHERE tenant_id=$1::uuid AND id=$2 AND NOT deleted FOR SHARE")
                .bind(tenant.to_string()).bind(scope).fetch_optional(&mut *connection).await?
                .ok_or(SourceError::Missing)?.ok_or(SourceError::Conflict)?;
            let devices = sqlx::query_scalar("SELECT device FROM mdm_planning.scope_results WHERE tenant_id=$1::uuid AND run=$2 AND device>coalesce($3,'') COLLATE \"C\" ORDER BY device COLLATE \"C\" LIMIT 65")
                .bind(tenant.to_string()).bind(result).bind(after).fetch_all(connection).await?;
            Ok(ScopePreview { result, devices })
        })
    }
    fn assignment_devices_on<'a>(
        &'a self,
        connection: &'a mut PgConnection,
        tenant: TenantId,
        scope: Uuid,
        after: Option<&'a str>,
    ) -> Pending<'a, Vec<String>> {
        Box::pin(async move {
            // A locked immutable resolution lets Execution merge this bounded source page
            // with its own claims without observing a different Scope resolution.
            let result = sqlx::query_scalar::<_, Option<Uuid>>("SELECT resolution FROM mdm_planning.scopes WHERE tenant_id=$1::uuid AND id=$2 FOR SHARE")
                .bind(tenant.to_string()).bind(scope).fetch_optional(&mut *connection).await?.flatten();
            let Some(result) = result else {
                return Ok(Vec::new());
            };
            Ok(sqlx::query_scalar("SELECT device FROM mdm_planning.scope_results WHERE tenant_id=$1::uuid AND run=$2 AND device>coalesce($3,'') COLLATE \"C\" ORDER BY device COLLATE \"C\" LIMIT 65")
                .bind(tenant.to_string()).bind(result).bind(after).fetch_all(connection).await?)
        })
    }
    fn native_interest_on<'a>(
        &'a self,
        connection: &'a mut PgConnection,
        tenant: TenantId,
        device: &'a str,
    ) -> Pending<'a, bool> {
        Box::pin(async move {
            Ok(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_policy.policies p WHERE p.tenant_id=$1::uuid AND p.enabled AND p.definition->'action'->>'kind' IN('configuration','ensure_agent_installed') AND mdm_planning.scope_admission((p.definition->>'scope')::uuid,$2)->>'state'<>'excluded')")
                .bind(tenant.to_string()).bind(device).fetch_one(connection).await?)
        })
    }
    fn admission_on<'a>(
        &'a self,
        connection: &'a mut PgConnection,
        _tenant: TenantId,
        scope: Uuid,
        device: &'a str,
    ) -> Pending<'a, ScopeAdmission> {
        Box::pin(async move {
            admission(
                sqlx::query_scalar("SELECT mdm_planning.scope_admission($1,$2)")
                    .bind(scope)
                    .bind(device)
                    .fetch_one(connection)
                    .await?,
            )
        })
    }
    fn capture_scope_on<'a>(
        &'a self,
        connection: &'a mut PgConnection,
        tenant: TenantId,
        scope: Uuid,
    ) -> Pending<'a, ScopeSnapshot> {
        Box::pin(async move {
            let row = sqlx::query("SELECT revision,resolution,resolution_revision,mdm_planning.scope_admission(id,NULL)->>'state' AS freshness FROM mdm_planning.scopes WHERE tenant_id=$1::uuid AND id=$2 AND NOT deleted FOR SHARE")
                .bind(tenant.to_string()).bind(scope).fetch_optional(connection).await?.ok_or(SourceError::Missing)?;
            if row.try_get::<String, _>("freshness")? != "fresh" {
                return Err(SourceError::Conflict);
            }
            Ok(ScopeSnapshot {
                scope,
                result: row.try_get("resolution")?,
                definition_revision: row.try_get("revision")?,
                resolution_revision: row.try_get("resolution_revision")?,
            })
        })
    }
    fn candidates_on<'a>(
        &'a self,
        connection: &'a mut PgConnection,
        tenant: TenantId,
        device: &'a str,
        kind: CandidateKind,
        after: Uuid,
    ) -> Pending<'a, Vec<PolicyCandidate>> {
        Box::pin(async move {
            // Excluded is removed before ORDER/LIMIT; Pending remains an unresolved claim.
            let rows = sqlx::query("SELECT p.id,p.current_version,(p.definition->>'scope')::uuid AS scope,mdm_planning.scope_admission((p.definition->>'scope')::uuid,$2) AS admission FROM mdm_policy.policies p WHERE p.tenant_id=$1::uuid AND p.enabled AND p.id>$3 AND p.definition->'action'->>'kind'=$4 AND mdm_planning.scope_admission((p.definition->>'scope')::uuid,$2)->>'state'<>'excluded' ORDER BY p.id LIMIT 64")
                .bind(tenant.to_string()).bind(device).bind(after).bind(kind.as_str()).fetch_all(connection).await?;
            rows.into_iter()
                .map(|row| {
                    Ok(PolicyCandidate {
                        policy: row.try_get("id")?,
                        version: row.try_get("current_version")?,
                        scope: row.try_get("scope")?,
                        admission: admission(row.try_get("admission")?)?,
                    })
                })
                .collect()
        })
    }
    fn snapshot_devices_on<'a>(
        &'a self,
        connection: &'a mut PgConnection,
        tenant: TenantId,
        snapshot: ScopeSnapshot,
        after: Option<&'a str>,
    ) -> Pending<'a, Vec<String>> {
        Box::pin(async move {
            Ok(sqlx::query_scalar("SELECT device FROM mdm_planning.scope_results WHERE tenant_id=$1::uuid AND run=$2 AND matched AND device>coalesce($3,'') COLLATE \"C\" ORDER BY device COLLATE \"C\" LIMIT 65")
                .bind(tenant.to_string()).bind(snapshot.result).bind(after).fetch_all(connection).await?)
        })
    }
}
