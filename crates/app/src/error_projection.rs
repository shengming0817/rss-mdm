//! Preserve service error ownership across host assembly.
use crate::Error;
impl From<crate::authorization::error::AuthorizationError> for Error {
    fn from(e: crate::authorization::error::AuthorizationError) -> Self {
        Self::Service(rss_mdm_flow_service::Error::from(e))
    }
}
impl From<crate::enrollment::EnrollmentError> for Error {
    fn from(e: crate::enrollment::EnrollmentError) -> Self {
        Self::Service(rss_mdm_flow_service::Error::from(e))
    }
}
impl From<crate::device::DeviceError> for Error {
    fn from(e: crate::device::DeviceError) -> Self {
        Self::Service(rss_mdm_flow_service::Error::from(e))
    }
}
impl From<crate::collection::CollectionError> for Error {
    fn from(e: crate::collection::CollectionError) -> Self {
        Self::Service(rss_mdm_flow_service::Error::from(e))
    }
}
impl From<rss_mdm_audit_integration::InvalidFact> for Error {
    fn from(e: rss_mdm_audit_integration::InvalidFact) -> Self {
        Self::Service(rss_mdm_flow_service::Error::from(e))
    }
}
impl From<rss_mdm_audit_integration::Error> for Error {
    fn from(e: rss_mdm_audit_integration::Error) -> Self {
        Self::Service(rss_mdm_flow_service::Error::from(e))
    }
}
impl From<&rss_mdm_audit_integration::Error> for Error {
    fn from(e: &rss_mdm_audit_integration::Error) -> Self {
        Self::Service(rss_mdm_flow_service::Error::from(e))
    }
}
impl From<rss_mdm_authorization_service::Error> for Error {
    fn from(e: rss_mdm_authorization_service::Error) -> Self {
        Self::Service(rss_mdm_flow_service::Error::from(e))
    }
}
impl From<rss_mdm_registration_service::Error> for Error {
    fn from(e: rss_mdm_registration_service::Error) -> Self {
        Self::Service(rss_mdm_flow_service::Error::from(e))
    }
}
impl From<rss_mdm_inventory_service::Error> for Error {
    fn from(e: rss_mdm_inventory_service::Error) -> Self {
        Self::Service(rss_mdm_flow_service::Error::from(e))
    }
}
impl From<rss_mdm_inventory_service::transaction::Fault> for Error {
    fn from(e: rss_mdm_inventory_service::transaction::Fault) -> Self {
        Self::Service(rss_mdm_flow_service::Error::from(e))
    }
}
impl From<rss_mdm_execution_service::channels::Rejection> for Error {
    fn from(e: rss_mdm_execution_service::channels::Rejection) -> Self {
        Self::Service(rss_mdm_flow_service::Error::from(e))
    }
}
impl From<rss_mdm_policy::Error> for Error {
    fn from(e: rss_mdm_policy::Error) -> Self {
        Self::Service(rss_mdm_flow_service::Error::from(e))
    }
}
impl From<rss_mdm_flow_service::planning::error::PlanningError> for Error {
    fn from(e: rss_mdm_flow_service::planning::error::PlanningError) -> Self {
        Self::Service(rss_mdm_flow_service::Error::from(e))
    }
}
impl From<rss_mdm_flow_service::resource_catalog::error::ResourceError> for Error {
    fn from(e: rss_mdm_flow_service::resource_catalog::error::ResourceError) -> Self {
        Self::Service(rss_mdm_flow_service::Error::from(e))
    }
}
impl From<rss_mdm_execution_service::missing::ExecutionError> for Error {
    fn from(e: rss_mdm_execution_service::missing::ExecutionError) -> Self {
        Self::Service(rss_mdm_flow_service::Error::from(e))
    }
}
impl From<rss_mdm_software_service::management::publication::error::PublicationError> for Error {
    fn from(e: rss_mdm_software_service::management::publication::error::PublicationError) -> Self {
        Self::Service(rss_mdm_flow_service::Error::from(e))
    }
}
impl From<rss_mdm_management_http::Error> for Error {
    fn from(e: rss_mdm_management_http::Error) -> Self {
        Self::Service(e.0)
    }
}
pub(crate) fn audit_deadline(outcome: rss_mdm_audit_integration::WriteOutcome) -> Error {
    use rss_mdm_audit_integration::WriteOutcome as W;
    use rss_mdm_flow_service::{Error as E, Failure};
    match outcome {
        W::Unknown | W::Committed => E::CommitUnknown,
        W::RollbackFailed => E::RollbackFailed,
        W::RolledBack | W::CommitNotStarted => E::Unavailable(Failure::RequestDeadline),
    }
    .into()
}
#[cfg(test)]
#[path = "../tests/error_projection/unit.rs"]
mod tests;

impl From<rss_mdm_software_service::management::Error> for Error {
    fn from(e: rss_mdm_software_service::management::Error) -> Self {
        rss_mdm_flow_service::Error::from(e).into()
    }
}
