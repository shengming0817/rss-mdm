//! Scope authority adapter borrows Execution's original transaction connection.
use rss_mdm_execution_service::source_authority::*;
use rss_request_context::TenantId;
use serde_json::Value;
use sqlx::{PgConnection, Row};
use uuid::Uuid;

pub struct ExecutionSource {
    pub objects: std::sync::Arc<dyn rss_mdm_inventory_service::objects::ObjectReader>,
}
impl ExecutionSource {
    pub fn new(
        objects: std::sync::Arc<dyn rss_mdm_inventory_service::objects::ObjectReader>,
    ) -> Self {
        Self { objects }
    }
}
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
        Box::pin(super::targets::objects_on(
            self.objects.as_ref(),
            c,
            tenant,
            scope,
            channel,
            after,
        ))
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
            self.objects.as_ref(),
            c,
            tenant,
            scope,
            channel,
            device,
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
            self.objects.as_ref(),
            c,
            tenant,
            channel,
            device,
            evidence,
        ))
    }
    fn policy_readable_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        version: Uuid,
    ) -> Pending<'a, bool> {
        Box::pin(async move {
            rss_mdm_inventory_postgres::lock_watermark_in(c, tenant).await?;
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
            Ok(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_policy.policies p JOIN mdm_planning.policy_assignments a ON(a.tenant_id,a.policy,a.version)=(p.tenant_id,p.id,p.current_version) WHERE p.tenant_id=$1::uuid AND p.enabled AND p.definition->'action'->>'kind'=ANY($3::text[]) AND a.channel='mdm' AND a.target->>'device'=$2 AND a.input->'admission'->>'state'<>'excluded')")
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
            self.objects.as_ref(),
            c,
            tenant,
            scope,
            channel,
            device,
        ))
    }
    fn candidates_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        device: &'a str,
        kind: CandidateKind,
        after: Uuid,
    ) -> Pending<'a, CandidatePage> {
        Box::pin(async move {
            let rows=sqlx::query("SELECT id,current_version,(definition->>'scope')::uuid AS scope FROM mdm_policy.policies WHERE tenant_id=$1::uuid AND enabled AND id>$2 AND definition->'action'->>'kind'=$3 ORDER BY id LIMIT 17").bind(tenant.to_string()).bind(after).bind(kind.as_str()).fetch_all(&mut *c).await?;
            let has_more = rows.len() > 16;
            let mut scanned_after = after;
            let mut items = Vec::new();
            for row in rows.into_iter().take(16) {
                scanned_after = row.try_get("id")?;
                let version = row.try_get("current_version")?;
                let scope = row.try_get("scope")?;
                let admission = if self.policy_readable_on(c, tenant, version).await? {
                    super::targets::admission_on(
                        self.objects.as_ref(),
                        c,
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
                    items.push(PolicyCandidate {
                        policy: scanned_after,
                        version,
                        scope,
                        admission,
                    });
                }
            }
            Ok(CandidatePage {
                items,
                scanned_after,
                has_more,
            })
        })
    }
}
