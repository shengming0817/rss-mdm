//! Explicit App mappings for software's borrowed source participants.
use rss_mdm_scope_service::channels;
use rss_mdm_software_service::deployment::scope::*;
use rss_request_context::TenantId;
use sqlx::PgConnection;
use uuid::Uuid;
pub(crate) struct Source(pub std::sync::Arc<channels::ChannelTargets>);
fn error(value: channels::SourceError) -> SourceError {
    match value {
        channels::SourceError::Storage(e) => SourceError::Storage(e),
        channels::SourceError::Missing => SourceError::Missing,
        channels::SourceError::Conflict => SourceError::Conflict,
        channels::SourceError::Capacity => SourceError::Capacity,
        channels::SourceError::Invariant => SourceError::Invariant,
    }
}
fn admission(value: channels::ScopeAdmission) -> ScopeAdmission {
    match value {
        channels::ScopeAdmission::Eligible { entry } => ScopeAdmission::Eligible { entry },
        channels::ScopeAdmission::Pending => ScopeAdmission::Pending,
        channels::ScopeAdmission::Excluded => ScopeAdmission::Excluded,
    }
}
fn object(value: channels::ObjectRef) -> ObjectRef {
    match value {
        channels::ObjectRef::Endpoint(id) => ObjectRef::Endpoint(id),
        channels::ObjectRef::Association(id) => ObjectRef::Association(id),
    }
}
fn evidence(value: channels::DeviceObject) -> DeviceObject {
    DeviceObject {
        object: object(value.object),
        association_version: value.association_version,
        verified: value.verified,
        members: value.members,
    }
}
impl Sources for Source {
    fn rollout_input_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        scopes: &'a [Uuid],
        channel: Channel,
    ) -> Pending<'a, Option<Vec<ScopeResult>>> {
        Box::pin(async move {
            Ok(self
                .0
                .rollout_input_on(c, tenant, scopes, channel)
                .await
                .map_err(error)?
                .map(|v| {
                    v.into_iter()
                        .map(|v| ScopeResult {
                            run: v.run,
                            revision: v.revision,
                        })
                        .collect()
                }))
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
            let v = self
                .0
                .rollout_devices_on(c, tenant, runs, channel, after)
                .await
                .map_err(error)?;
            Ok(RolloutPage {
                targets: v.targets,
                after: v.after,
                has_more: v.has_more,
                scanned: v.scanned,
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
        Box::pin(async move {
            let v = self
                .0
                .preview_scope_on(c, tenant, scope, channel, after)
                .await
                .map_err(error)?;
            Ok(ScopePreview {
                result: v.result,
                devices: v.devices,
            })
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
        Box::pin(async move {
            Ok(self
                .0
                .assignment_objects_on(c, tenant, scope, channel, after, limit)
                .await
                .map_err(error)?
                .into_iter()
                .map(|v| AssignmentObject {
                    object: object(v.object),
                    channel: v.channel,
                    availability: match v.availability {
                        channels::Availability::Ready => Availability::Ready,
                        channels::Availability::Unavailable => Availability::Unavailable,
                    },
                    reason: v.reason,
                    target: v.target,
                    admission: admission(v.admission),
                    sources: v.sources.into_iter().map(evidence).collect(),
                    scope_result: v.scope_result,
                })
                .collect())
        })
    }
    fn evidence_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        scope: Uuid,
        channel: Channel,
        device: &'a str,
    ) -> Pending<'a, Vec<DeviceObject>> {
        Box::pin(async move {
            Ok(self
                .0
                .evidence_on(c, tenant, scope, channel, device)
                .await
                .map_err(error)?
                .into_iter()
                .map(evidence)
                .collect())
        })
    }
    fn evidence_valid_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        channel: Channel,
        device: &'a str,
        evidence: &'a [DeviceObject],
    ) -> Pending<'a, bool> {
        Box::pin(async move {
            let evidence = evidence
                .iter()
                .map(|v| channels::DeviceObject {
                    object: match &v.object {
                        ObjectRef::Endpoint(id) => channels::ObjectRef::Endpoint(id.clone()),
                        ObjectRef::Association(id) => channels::ObjectRef::Association(*id),
                    },
                    association_version: v.association_version,
                    verified: v.verified,
                    members: v.members.clone(),
                })
                .collect::<Vec<_>>();
            self.0
                .evidence_valid_on(c, tenant, channel, device, &evidence)
                .await
                .map_err(error)
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
        Box::pin(async move {
            self.0
                .admission_on(c, tenant, scope, channel, device)
                .await
                .map(admission)
                .map_err(error)
        })
    }
    fn query_coordinate_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        scope: Uuid,
    ) -> Pending<'a, String> {
        Box::pin(async move {
            self.0
                .query_coordinate_on(c, tenant, scope)
                .await
                .map_err(error)
        })
    }
    fn channel_state_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        scope: Uuid,
        channel: Channel,
        device: &'a str,
    ) -> Pending<'a, ScopeAdmission> {
        Box::pin(async move {
            channels::targets::channel_state_on(c, scope, channel, device)
                .await
                .map(admission)
                .map_err(error)
        })
    }
    fn effect_devices<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        device: &'a str,
    ) -> Pending<'a, Vec<String>> {
        Box::pin(async move { Ok(self.0.objects.effect_devices(c, tenant, device).await?) })
    }
    fn change_head<'a>(&'a self, c: &'a mut PgConnection, tenant: TenantId) -> Pending<'a, i64> {
        Box::pin(async move { Ok(self.0.objects.change_head(c, tenant).await?) })
    }
    fn changes<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        after: i64,
        through: i64,
        limit: usize,
    ) -> Pending<'a, Vec<ObjectChange>> {
        Box::pin(async move {
            Ok(self
                .0
                .objects
                .changes(c, tenant, after, through, limit)
                .await?
                .into_iter()
                .map(|v| ObjectChange {
                    position: v.position,
                    object: v.object,
                    old_devices: v.old_devices,
                    new_devices: v.new_devices,
                })
                .collect())
        })
    }
}

pub(crate) struct Inventory;
fn inventory_error(
    e: rss_mdm_inventory_service::Error,
) -> rss_mdm_software_service::deployment::Error {
    use rss_mdm_inventory_service::Error as I;
    use rss_mdm_software_service::deployment::{Error as E, Failure};
    match e {
        I::CommitUnknown => E::CommitUnknown,
        I::RollbackFailed => E::RollbackFailed,
        I::Forbidden => E::Forbidden,
        I::Unauthorized => E::Unauthorized,
        I::Conflict => E::Conflict,
        I::Malformed => E::Malformed,
        _ => E::Unavailable(Failure::PlanningStorage),
    }
}
impl rss_mdm_software_service::deployment::inventory::Inventory for Inventory {
    fn details_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        targets: &'a [(Uuid, i64, rss_mdm_inventory::ReportSource)],
        lock: bool,
    ) -> rss_mdm_software_service::deployment::inventory::Pending<
        'a,
        rss_mdm_software_service::deployment::inventory::Page,
    > {
        Box::pin(async move {
            if lock {
                rss_mdm_inventory_service::assets::channel::details_in(c, tenant, targets).await
            } else {
                rss_mdm_inventory_service::assets::channel::snapshot_details_in(c, tenant, targets)
                    .await
            }
            .map_err(inventory_error)
        })
    }
    fn capture<'a>(
        &'a self,
        audit: &'a rss_mdm_audit_integration::AuditStore,
        tenant: TenantId,
        budget: &'a rss_mdm_audit_integration::budget::AuditBudget,
    ) -> rss_mdm_software_service::deployment::inventory::Pending<'a, rss_mdm_inventory::AssetCut>
    {
        Box::pin(async move {
            rss_mdm_inventory_service::assets::cut::capture(audit, tenant, budget)
                .await
                .map_err(inventory_error)
        })
    }
}

pub(crate) struct Lifecycle;
fn device_error(e: rss_mdm_device_service::Error) -> rss_mdm_software_service::deployment::Error {
    use rss_mdm_device_service::Error as D;
    use rss_mdm_software_service::deployment::{Error as E, Failure};
    match e {
        D::CommitUnknown => E::CommitUnknown,
        D::RollbackFailed => E::RollbackFailed,
        D::Forbidden => E::Forbidden,
        D::Unauthorized => E::Unauthorized,
        D::Conflict => E::Conflict,
        D::Malformed => E::Malformed,
        _ => E::Unavailable(Failure::PlanningStorage),
    }
}
impl rss_mdm_software_service::deployment::retirement::Lifecycle for Lifecycle {
    fn execution_allowed_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: &'a str,
        device: &'a str,
        execution: Uuid,
    ) -> rss_mdm_software_service::deployment::retirement::Pending<'a, bool> {
        Box::pin(async move {
            rss_mdm_device_service::lifecycle::execution_allowed_in(c, tenant, device, execution)
                .await
                .map_err(device_error)
        })
    }
    fn execution_permissions_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: &'a str,
        targets: &'a [(Uuid, String)],
    ) -> rss_mdm_software_service::deployment::retirement::Pending<
        'a,
        std::collections::BTreeMap<Uuid, bool>,
    > {
        Box::pin(async move {
            rss_mdm_device_service::lifecycle::execution_permissions_in(c, tenant, targets)
                .await
                .map_err(device_error)
        })
    }
    fn cleanup_allowed_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: &'a str,
        retirement: Uuid,
        device: &'a str,
        execution: Option<Uuid>,
    ) -> rss_mdm_software_service::deployment::retirement::Pending<'a, bool> {
        Box::pin(async move {
            rss_mdm_device_service::lifecycle::cleanup_allowed_in(
                c, tenant, retirement, device, execution,
            )
            .await
            .map_err(device_error)
        })
    }
    fn context_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        retirement: Uuid,
    ) -> rss_mdm_software_service::deployment::retirement::Pending<
        'a,
        rss_mdm_software_service::deployment::retirement::Context,
    > {
        Box::pin(async move {
            let (v, lifetime) =
                rss_mdm_device_service::lifecycle::cleanup_context_in(c, tenant, retirement)
                    .await
                    .map_err(device_error)?;
            Ok(rss_mdm_software_service::deployment::retirement::Context {
                policy: v.policy,
                version: v.version,
                lifetime,
                origin: v.origin,
                target: evidence(v.target),
            })
        })
    }
    fn authorize_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        retirement: Uuid,
        registration: Uuid,
        execution: Uuid,
    ) -> rss_mdm_software_service::deployment::retirement::Pending<'a, ()> {
        Box::pin(async move {
            rss_mdm_device_service::lifecycle::authorize_execution_in(
                c,
                tenant,
                retirement,
                registration,
                execution,
            )
            .await
            .map_err(device_error)
        })
    }
    fn blocked_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        retirement: Uuid,
        registration: Uuid,
        reason: &'static str,
        execution: Option<Uuid>,
        unknown: bool,
    ) -> rss_mdm_software_service::deployment::retirement::Pending<'a, ()> {
        Box::pin(async move {
            rss_mdm_device_service::lifecycle::observe_in(
                c,
                tenant,
                retirement,
                registration,
                rss_mdm_device_service::lifecycle::Observation::CleanupBlocked {
                    reason,
                    execution,
                    unknown,
                },
            )
            .await
            .map_err(device_error)
        })
    }
    fn wake_in<'a>(
        &'a self,
        messaging: &'a rss_reconcile_postgres::PgMessagingStore,
        tx: &'a mut rss_transactional_messaging_postgres::PgTransaction<'_>,
        device: &'a str,
    ) -> std::pin::Pin<
        Box<dyn Future<Output = rss_mdm_software_service::deployment::Result<()>> + Send + 'a>,
    > {
        Box::pin(async move {
            rss_mdm_device_service::control::unmanage::wake_device_in(messaging, tx, device)
                .await
                .map_err(|e| {
                    use rss_mdm_device_service::control::transaction::Fault as F;
                    use rss_mdm_software_service::deployment::{
                        Error as E, Failure, transaction::Fault as O,
                    };
                    match e {
                        F::Sql(e) => O::Sql(e),
                        F::Storage(e) => O::Storage(e),
                        F::Request(_) => E::Unavailable(Failure::PlanningStorage).into(),
                    }
                })
        })
    }
}
