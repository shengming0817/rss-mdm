//! One-way conversion into the HTTP wrapper.
use crate::Error;
impl From<crate::authorization::error::AuthorizationError> for Error {
    fn from(e: crate::authorization::error::AuthorizationError) -> Self {
        Self(rss_mdm_flow_service::Error::from(e))
    }
}
impl From<rss_mdm_registration_service::enrollment::EnrollmentError> for Error {
    fn from(e: rss_mdm_registration_service::enrollment::EnrollmentError) -> Self {
        Self(rss_mdm_flow_service::Error::from(e))
    }
}
impl From<crate::device::DeviceError> for Error {
    fn from(e: crate::device::DeviceError) -> Self {
        Self(rss_mdm_flow_service::Error::from(e))
    }
}
impl From<rss_mdm_inventory_service::collection::CollectionError> for Error {
    fn from(e: rss_mdm_inventory_service::collection::CollectionError) -> Self {
        Self(rss_mdm_flow_service::Error::from(e))
    }
}
impl From<rss_mdm_audit_integration::InvalidFact> for Error {
    fn from(e: rss_mdm_audit_integration::InvalidFact) -> Self {
        Self(rss_mdm_flow_service::Error::from(e))
    }
}
impl From<rss_mdm_audit_integration::Error> for Error {
    fn from(e: rss_mdm_audit_integration::Error) -> Self {
        Self(rss_mdm_flow_service::Error::from(e))
    }
}
impl From<&rss_mdm_audit_integration::Error> for Error {
    fn from(e: &rss_mdm_audit_integration::Error) -> Self {
        Self(rss_mdm_flow_service::Error::from(e))
    }
}
impl From<rss_mdm_authorization_service::Error> for Error {
    fn from(e: rss_mdm_authorization_service::Error) -> Self {
        Self(rss_mdm_flow_service::Error::from(e))
    }
}
impl From<rss_mdm_registration_service::Error> for Error {
    fn from(e: rss_mdm_registration_service::Error) -> Self {
        Self(rss_mdm_flow_service::Error::from(e))
    }
}
impl From<rss_mdm_inventory_service::Error> for Error {
    fn from(e: rss_mdm_inventory_service::Error) -> Self {
        Self(rss_mdm_flow_service::Error::from(e))
    }
}
impl From<rss_mdm_inventory_service::transaction::Fault> for Error {
    fn from(e: rss_mdm_inventory_service::transaction::Fault) -> Self {
        Self(rss_mdm_flow_service::Error::from(e))
    }
}
impl From<rss_mdm_execution_service::channels::Rejection> for Error {
    fn from(e: rss_mdm_execution_service::channels::Rejection) -> Self {
        Self(rss_mdm_flow_service::Error::from(e))
    }
}
impl From<rss_mdm_apple_mdm::Error> for Error {
    fn from(e: rss_mdm_apple_mdm::Error) -> Self {
        Self(rss_mdm_flow_service::Error::from(e))
    }
}
impl From<rss_mdm_content_service::Error> for Error {
    fn from(e: rss_mdm_content_service::Error) -> Self {
        Self(rss_mdm_flow_service::Error::from(e))
    }
}
impl From<rss_mdm_flow_service::Error> for Error {
    fn from(e: rss_mdm_flow_service::Error) -> Self {
        Self(e)
    }
}
impl From<rss_mdm_content_service::service::Error> for Error {
    fn from(e: rss_mdm_content_service::service::Error) -> Self {
        Self(rss_mdm_flow_service::Error::from(e))
    }
}
impl From<rss_mdm_flow_service::planning::error::PlanningError> for Error {
    fn from(e: rss_mdm_flow_service::planning::error::PlanningError) -> Self {
        Self(rss_mdm_flow_service::Error::from(e))
    }
}
impl From<rss_mdm_flow_service::resource_catalog::error::ResourceError> for Error {
    fn from(e: rss_mdm_flow_service::resource_catalog::error::ResourceError) -> Self {
        Self(rss_mdm_flow_service::Error::from(e))
    }
}
impl From<rss_mdm_execution_service::missing::ExecutionError> for Error {
    fn from(e: rss_mdm_execution_service::missing::ExecutionError) -> Self {
        Self(rss_mdm_flow_service::Error::from(e))
    }
}
impl From<rss_mdm_software_service::management::publication::error::PublicationError> for Error {
    fn from(e: rss_mdm_software_service::management::publication::error::PublicationError) -> Self {
        Self(rss_mdm_flow_service::Error::from(e))
    }
}

impl From<rss_mdm_software_service::management::Error> for Error {
    fn from(e: rss_mdm_software_service::management::Error) -> Self {
        rss_mdm_flow_service::Error::from(e).into()
    }
}
