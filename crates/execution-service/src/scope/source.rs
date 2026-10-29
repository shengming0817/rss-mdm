//! Execution combines its channel facts with a narrow Policy candidate reader.
use crate::source_authority::*;
use rss_request_context::TenantId;
use serde_json::Value;
use sqlx::PgConnection;
use std::sync::Arc;
use uuid::Uuid;
pub trait PolicySource: Send + Sync {
    fn native_interest_on<'a>(
        &'a self,
        connection: &'a mut PgConnection,
        tenant: TenantId,
        device: &'a str,
    ) -> Pending<'a, bool>;
    fn configuration_candidates_batch_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        devices: &'a [String],
        after: Option<&'a (Uuid, String)>,
    ) -> Pending<'a, ConfigurationCandidates>;
    fn candidates_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        device: &'a str,
        kind: CandidateKind,
        after: Uuid,
    ) -> Pending<'a, CandidatePage>;
}
pub struct ExecutionSource {
    pub mdm_software_enabled: bool,
    pub objects: Arc<dyn rss_mdm_inventory_service::objects::ObjectReader>,
    pub policies: Arc<dyn PolicySource>,
}
impl ExecutionSource {
    pub fn new(
        objects: Arc<dyn rss_mdm_inventory_service::objects::ObjectReader>,
        policies: Arc<dyn PolicySource>,
    ) -> Self {
        Self {
            objects,
            policies,
            mdm_software_enabled: false,
        }
    }
}
impl SourceAuthority for ExecutionSource {
    fn query_coordinate_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        scope: Uuid,
    ) -> Pending<'a, String> {
        Box::pin(query_coordinate_on(c, tenant, scope))
    }
    fn effect_devices_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        device: &'a str,
    ) -> Pending<'a, Vec<String>> {
        Box::pin(async move { Ok(self.objects.effect_devices(c, tenant, device).await?) })
    }
    fn mdm_software_enabled(&self) -> bool {
        self.mdm_software_enabled
    }
    fn lifecycle_objects_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        scope: Uuid,
        after: Option<&'a str>,
        limit: usize,
    ) -> Pending<'a, Vec<DeviceAssignment>> {
        Box::pin(super::targets::lifecycle_objects_on(
            self.objects.as_ref(),
            c,
            tenant,
            scope,
            after,
            limit,
        ))
    }
    fn rollout_input_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        scopes: &'a [Uuid],
        channel: Channel,
    ) -> Pending<'a, Option<Vec<ScopeResult>>> {
        Box::pin(async move {
            let mut runs = Vec::new();
            for scope in scopes {
                let status: Value = sqlx::query_scalar("SELECT mdm_scope.scope_admission($1,NULL)")
                    .bind(scope)
                    .fetch_one(&mut *c)
                    .await?;
                if status["state"] != "fresh" {
                    return Ok(None);
                }
                let (run,revision)=sqlx::query_as::<_,(Uuid,i64)>("SELECT s.resolution,CASE WHEN $3='mdm' THEN p.mdm_revision ELSE p.agent_revision END FROM mdm_scope.scopes s JOIN mdm_commands.scope_projection_runs p ON(p.tenant_id,p.id)=(s.tenant_id,s.resolution) WHERE s.tenant_id=$1::uuid AND s.id=$2 AND NOT s.deleted").bind(tenant.to_string()).bind(scope).bind(channel.as_str()).fetch_one(&mut *c).await?;
                runs.push(ScopeResult { run, revision });
            }
            Ok(Some(runs))
        })
    }
    fn rollout_devices_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        runs: &'a [Uuid],
        channel: Channel,
        after: Option<&'a str>,
    ) -> Pending<'a, RolloutPage> {
        Box::pin(async move {
            let (root, stage) = match runs {
                [root, stage, ..] => (root, stage),
                _ => return Err(SourceError::Invariant),
            };
            let mut rows=sqlx::query_as::<_,(String,Value,bool)>("WITH page AS (SELECT * FROM mdm_commands.scope_channel_results WHERE tenant_id=$1::uuid AND run=$3 AND channel=$6 AND device>coalesce($5,'') COLLATE \"C\" ORDER BY device LIMIT 17) SELECT s.device,s.target,s.matched AND NOT s.pending AND EXISTS(SELECT 1 FROM mdm_commands.scope_channel_results r WHERE r.tenant_id=s.tenant_id AND r.run=$2 AND r.device=s.device AND r.channel=s.channel AND r.target=s.target AND r.matched AND NOT r.pending) AND NOT EXISTS(SELECT 1 FROM mdm_commands.scope_channel_results e WHERE e.tenant_id=s.tenant_id AND e.run=ANY($4) AND e.channel=s.channel AND e.device=s.device AND (e.matched OR e.pending)) FROM page s ORDER BY s.device").bind(tenant.to_string()).bind(root).bind(stage).bind(&runs[2..]).bind(after).bind(channel.as_str()).fetch_all(c).await?;
            let has_more = rows.len() > 16;
            rows.truncate(16);
            let after = rows.last().map(|r| r.0.clone());
            let scanned = rows.len() as u64;
            let targets = rows
                .into_iter()
                .filter(|r| r.2)
                .map(|r| serde_json::from_value(r.1).map_err(|_| SourceError::Invariant))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(RolloutPage {
                targets,
                after,
                has_more,
                scanned,
            })
        })
    }
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
        limit: usize,
    ) -> Pending<'a, Vec<AssignmentObject>> {
        Box::pin(super::targets::objects_on(
            self.objects.as_ref(),
            c,
            tenant,
            scope,
            channel,
            after,
            limit,
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
    fn native_interest_on<'a>(
        &'a self,
        connection: &'a mut PgConnection,
        tenant: TenantId,
        device: &'a str,
    ) -> Pending<'a, bool> {
        self.policies.native_interest_on(connection, tenant, device)
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
    fn configuration_candidates_batch_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        devices: &'a [String],
        after: Option<&'a (Uuid, String)>,
    ) -> Pending<'a, ConfigurationCandidates> {
        self.policies
            .configuration_candidates_batch_on(c, tenant, devices, after)
    }
    fn candidates_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        device: &'a str,
        kind: CandidateKind,
        after: Uuid,
    ) -> Pending<'a, CandidatePage> {
        self.policies.candidates_on(c, tenant, device, kind, after)
    }
}

/// Scope and source coordinates share the caller's transaction; no result-set scan is needed.
pub async fn query_coordinate_on(
    c: &mut PgConnection,
    tenant: TenantId,
    scope: Uuid,
) -> Result<String, SourceError> {
    let stamp: Value = sqlx::query_scalar("SELECT jsonb_build_array(s.revision,s.resolution,coalesce((SELECT revision FROM mdm.asset_clock WHERE tenant_id=s.tenant_id),0),coalesce((SELECT relation_revision FROM mdm_devices.checkpoints WHERE tenant_id=s.tenant_id),0),coalesce((SELECT query_revision FROM mdm_devices.checkpoints WHERE tenant_id=s.tenant_id),0)) FROM mdm_scope.scopes s WHERE s.tenant_id=$1::uuid AND s.id=$2 AND NOT s.deleted")
        .bind(tenant.to_string()).bind(scope).fetch_optional(c).await?.ok_or(SourceError::Missing)?;
    rss_mdm_query::cursor::fingerprint(&stamp).map_err(|_| SourceError::Invariant)
}
