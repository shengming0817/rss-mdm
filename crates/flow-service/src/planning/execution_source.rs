//! Scope authority adapter borrows Execution's original transaction connection.
use rss_mdm_execution_service::source_authority::*;
use rss_request_context::TenantId;
use serde_json::Value;
use sqlx::{PgConnection, Row};
use uuid::Uuid;

pub struct ExecutionSource;
impl SourceAuthority for ExecutionSource {
    fn preview_scope_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        scope: Uuid,
        channel: Channel,
        after: Option<&'a str>,
    ) -> Pending<'a, ScopePreview> {
        Box::pin(super::targets::devices_on(c, tenant, scope, channel, after))
    }
    fn assignment_devices_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        scope: Uuid,
        channel: Channel,
        after: Option<&'a str>,
    ) -> Pending<'a, Vec<String>> {
        Box::pin(async move {
            Ok(super::targets::devices_on(c, tenant, scope, channel, after)
                .await?
                .devices)
        })
    }
    fn assignment_objects_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        scope: Uuid,
        channel: Channel,
        after: Option<&'a str>,
    ) -> Pending<'a, Vec<AssignmentObject>> {
        Box::pin(super::targets::objects_on(c, tenant, scope, channel, after))
    }
    fn evidence_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        scope: Uuid,
        channel: Channel,
        device: &'a str,
    ) -> Pending<'a, Vec<DeviceObject>> {
        Box::pin(super::targets::evidence_on(
            c, tenant, scope, channel, device,
        ))
    }
    fn evidence_valid_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        channel: Channel,
        device: &'a str,
        evidence: &'a [DeviceObject],
    ) -> Pending<'a, bool> {
        Box::pin(super::targets::evidence_valid_on(
            c, tenant, channel, device, evidence,
        ))
    }
    fn policy_readable_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        version: Uuid,
    ) -> Pending<'a, bool> {
        Box::pin(async move {
            let value:Option<Value>=sqlx::query_scalar("SELECT read_grant FROM mdm_planning.policy_source_grants WHERE tenant_id=$1::uuid AND version=$2").bind(tenant.to_string()).bind(version).fetch_optional(&mut *c).await?;
            let Some(value) = value else {
                return Ok(false);
            };
            let grant: rss_mdm_authorization_service::UserGrant =
                serde_json::from_value(value).map_err(|_| SourceError::Invariant)?;
            let now: i64 =
                sqlx::query_scalar("SELECT extract(epoch FROM clock_timestamp())::bigint")
                    .fetch_one(&mut *c)
                    .await?;
            grant
                .valid(
                    c,
                    rss_mdm_authorization_service::Permission::InventoryRead,
                    now,
                )
                .await
                .map_err(|_| SourceError::Invariant)
        })
    }
    fn native_interest_on<'a>(
        &'a self,
        connection: &'a mut PgConnection,
        tenant: TenantId,
        device: &'a str,
    ) -> Pending<'a, bool> {
        let kinds = rss_mdm_policy::AssignmentBehavior::NativeDesired.kinds();
        Box::pin(async move {
            Ok(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_policy.policies p WHERE p.tenant_id=$1::uuid AND p.enabled AND p.definition->'action'->>'kind' = ANY($3::text[]) AND mdm_planning.scope_admission((p.definition->>'scope')::uuid,$2)->>'state'<>'excluded')")
                .bind(tenant.to_string()).bind(device).bind(kinds).fetch_one(connection).await?)
        })
    }
    fn admission_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        scope: Uuid,
        channel: Channel,
        device: &'a str,
    ) -> Pending<'a, ScopeAdmission> {
        Box::pin(super::targets::admission_on(
            c, tenant, scope, channel, device,
        ))
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
            let mut cursor = after;
            let mut result = Vec::new();
            while result.len() < 64 {
                let rows=sqlx::query("SELECT id,current_version,(definition->>'scope')::uuid AS scope FROM mdm_policy.policies WHERE tenant_id=$1::uuid AND enabled AND id>$2 AND definition->'action'->>'kind'=$3 ORDER BY id LIMIT 64").bind(tenant.to_string()).bind(cursor).bind(kind.as_str()).fetch_all(&mut *connection).await?;
                if rows.is_empty() {
                    break;
                }
                for row in rows {
                    cursor = row.try_get("id")?;
                    let version = row.try_get("current_version")?;
                    let scope = row.try_get("scope")?;
                    let admission = if self.policy_readable_on(connection, tenant, version).await? {
                        super::targets::admission_on(
                            connection,
                            tenant,
                            scope,
                            Channel::Mdm,
                            device,
                        )
                        .await?
                    } else {
                        ScopeAdmission::Pending
                    };
                    if admission != ScopeAdmission::Excluded {
                        result.push(PolicyCandidate {
                            policy: cursor,
                            version,
                            scope,
                            admission,
                        });
                        if result.len() == 64 {
                            break;
                        }
                    }
                }
            }
            Ok(result)
        })
    }
}
