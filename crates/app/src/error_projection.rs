//! One-way domain-to-host projection. HTTP codes remain owned by the host error boundary.
use crate::Error;
impl From<crate::authorization::error::AuthorizationError> for Error {
    fn from(error: crate::authorization::error::AuthorizationError) -> Self {
        use crate::authorization::error::AuthorizationError as Domain;
        match error {
            Domain::Malformed => Self::Malformed,
            Domain::Unauthorized => Self::Unauthorized,
            Domain::Forbidden => Self::Forbidden,
            Domain::Corrupt => Self::Unavailable(crate::Failure::Database),
        }
    }
}
impl From<crate::enrollment::EnrollmentError> for Error {
    fn from(error: crate::enrollment::EnrollmentError) -> Self {
        match error {
            crate::enrollment::EnrollmentError::InvalidPassword => Self::Malformed,
        }
    }
}
impl From<crate::device::DeviceError> for Error {
    fn from(error: crate::device::DeviceError) -> Self {
        match error {
            crate::device::DeviceError::InvalidSource => Self::Malformed,
        }
    }
}
impl From<crate::collection::CollectionError> for Error {
    fn from(error: crate::collection::CollectionError) -> Self {
        match error {
            crate::collection::CollectionError::CorrelationConflict => Self::Conflict,
        }
    }
}
impl From<crate::management::assets::AssetError> for Error {
    fn from(error: crate::management::assets::AssetError) -> Self {
        match error {
            crate::management::assets::AssetError::RestrictedScope => Self::Forbidden,
        }
    }
}
