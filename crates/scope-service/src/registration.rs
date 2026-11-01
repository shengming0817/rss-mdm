//! Explicit App mappings for registration's borrowed source participants.
use crate::channels;
use rss_mdm_registration_service::participants::scope::*;
use rss_request_context::TenantId;
use sqlx::PgConnection;
use uuid::Uuid;
pub struct EnrollmentSources(pub std::sync::Arc<channels::ChannelTargets>);
fn error(value: channels::SourceError) -> SourceError {
    match value {
        channels::SourceError::Unsupported => SourceError::Unsupported,
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
impl Sources for EnrollmentSources {
    fn storage_profile(&self) -> rss_mdm_install_support::StorageProfile {
        self.0.profile()
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
}
