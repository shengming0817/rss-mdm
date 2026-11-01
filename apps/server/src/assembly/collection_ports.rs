//! Concrete channel mappings for Inventory's collection execution boundary.
use rss_mdm_inventory_service::{
    Error, Failure,
    collection::execution::{model::Target, participants::*},
};
use rss_request_context::TenantId;
use sqlx::PgConnection;
use uuid::Uuid;
pub(crate) struct Delivery {
    pub protection: std::sync::Arc<rss_mdm_native_protection::Protector>,
}
fn windows(error: rss_mdm_windows_channel::Error) -> Error {
    use rss_mdm_windows_channel::Error as W;
    match error {
        W::CommitUnknown => Error::CommitUnknown,
        W::RollbackFailed => Error::RollbackFailed,
        W::Malformed | W::CertificateRequest | W::Unsupported => Error::Malformed,
        W::Conflict | W::EnrollmentPaused => Error::Conflict,
        W::Unauthorized => Error::Unauthorized,
        W::Forbidden => Error::Forbidden,
        W::NotFound | W::Missing(_) => Error::NotFound,
        W::Configuration(_) | W::Unavailable(_) => Error::Unavailable(Failure::Protocol),
    }
}
fn apple(error: rss_mdm_apple_channel::Error) -> Error {
    use rss_mdm_apple_channel::Error as A;
    match error {
        A::CommitUnknown => Error::CommitUnknown,
        A::RollbackFailed => Error::RollbackFailed,
        A::Malformed | A::CertificateRequest | A::Unsupported => Error::Malformed,
        A::Conflict | A::EnrollmentPaused => Error::Conflict,
        A::Unauthorized => Error::Unauthorized,
        A::Forbidden => Error::Forbidden,
        A::NotFound => Error::NotFound,
        _ => Error::Unavailable(Failure::Protocol),
    }
}
impl NativeDelivery for Delivery {
    fn permissions(
        &self,
        template: &rss_mdm_resource::NativeCollectionDefinition,
    ) -> Result<Vec<rss_mdm_authorization_service::Permission>, Error> {
        if template.spec().adapter == rss_mdm_resource::NativeAdapter::WindowsRead {
            rss_mdm_windows_channel::collection_plan::permissions(template).map_err(windows)
        } else {
            Ok(vec![
                rss_mdm_authorization_service::Permission::InventoryCollect,
            ])
        }
    }
    fn eligible_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        target: &'a Target,
        template: &'a rss_mdm_resource::NativeCollectionDefinition,
    ) -> Pending<'a, bool> {
        Box::pin(async move {
            if template.spec().adapter == rss_mdm_resource::NativeAdapter::WindowsRead {
                rss_mdm_windows_channel::collection_plan::eligible_on(
                    c,
                    tenant,
                    target.registration,
                    target.generation,
                    template,
                )
                .await
                .map_err(|e| windows(e).into())
            } else {
                rss_mdm_apple_channel::collection_admission::eligible_on(
                    c,
                    tenant,
                    target.registration,
                    target.generation,
                    template,
                )
                .await
                .map_err(|e| apple(e).into())
            }
        })
    }
    fn prepare_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        id: Uuid,
        platform: rss_mdm_policy::Platform,
    ) -> Pending<'a, Vec<rss_mdm_audit_integration::Fact>> {
        Box::pin(async move {
            let (facts, wake) = match platform {
                rss_mdm_policy::Platform::Macos => {
                    use rss_mdm_apple_channel::protocol_types::AppleCollections;
                    let store = rss_mdm_apple_channel::flow_store::Store {
                        protection: self.protection.clone(),
                    };
                    (
                        store
                            .prepare_native_collection(c, tenant.to_string(), id)
                            .await
                            .map_err(apple)?,
                        "apple",
                    )
                }
                rss_mdm_policy::Platform::Windows => (vec![], "windows_push"),
            };
            sqlx::query("SELECT pg_notify('mdm_work_' || replace(current_setting('rss.tenant_id')::uuid::text,'-',''),$1)").bind(wake).execute(c).await?;
            Ok(facts)
        })
    }
}

pub(crate) struct Source(pub std::sync::Arc<rss_mdm_scope_service::channels::ChannelTargets>);
fn scope_error(
    e: rss_mdm_scope_service::channels::SourceError,
) -> rss_mdm_inventory_service::transaction::Fault {
    use rss_mdm_scope_service::channels::SourceError as S;
    match e {
        // Collection requires a configured Scope participant from its host.
        S::Unsupported => Error::Unavailable(Failure::PlanningStorage).into(),
        S::Storage(e) => e.into(),
        S::Missing => Error::NotFound.into(),
        S::Conflict => Error::Conflict.into(),
        S::Capacity => Error::Unavailable(Failure::Capacity).into(),
        S::Invariant => Error::Unavailable(Failure::PlanningStorage).into(),
    }
}
impl TargetAdmission for Source {
    fn admission_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        scope: Uuid,
        channel: rss_mdm_inventory::Channel,
        device: &'a str,
    ) -> Pending<'a, Admission> {
        Box::pin(async move {
            Ok(
                match self
                    .0
                    .admission_on(c, tenant, scope, channel, device)
                    .await
                    .map_err(scope_error)?
                {
                    rss_mdm_scope_service::channels::ScopeAdmission::Eligible { entry } => {
                        Admission::Eligible { entry }
                    }
                    rss_mdm_scope_service::channels::ScopeAdmission::Pending => Admission::Pending,
                    rss_mdm_scope_service::channels::ScopeAdmission::Excluded => {
                        Admission::Excluded
                    }
                },
            )
        })
    }
    fn evidence_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        scope: Uuid,
        channel: rss_mdm_inventory::Channel,
        device: &'a str,
    ) -> Pending<'a, Vec<rss_mdm_inventory_service::objects::DeviceObject>> {
        Box::pin(async move {
            self.0
                .evidence_on(c, tenant, scope, channel, device)
                .await
                .map_err(scope_error)
        })
    }
    fn evidence_valid_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        channel: rss_mdm_inventory::Channel,
        device: &'a str,
        evidence: &'a [rss_mdm_inventory_service::objects::DeviceObject],
    ) -> Pending<'a, bool> {
        Box::pin(async move {
            self.0
                .evidence_valid_on(c, tenant, channel, device, evidence)
                .await
                .map_err(scope_error)
        })
    }
}
