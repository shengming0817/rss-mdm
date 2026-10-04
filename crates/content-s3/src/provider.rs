use crate::{Budget, Error, Result};
use aws_sdk_s3::error::{ProvideErrorMetadata, SdkError};
use base64::{Engine, engine::general_purpose::STANDARD};
use std::future::Future;

pub(crate) fn classify<E: ProvideErrorMetadata + std::error::Error + 'static>(
    error: &SdkError<E>,
) -> Error {
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        if let Some(safe) = cause.downcast_ref::<Error>() {
            return *safe;
        }
        source = cause.source();
    }
    if matches!(error, SdkError::ConstructionFailure(_)) {
        return Error::Configuration;
    }
    let code = error
        .as_service_error()
        .and_then(ProvideErrorMetadata::code);
    match (code, error.raw_response().map(|r| r.status().as_u16())) {
        (
            Some(
                "NoSuchBucket"
                | "InvalidBucketName"
                | "InvalidAccessKeyId"
                | "SignatureDoesNotMatch"
                | "InvalidRequest"
                | "NotImplemented",
            ),
            _,
        ) => Error::Configuration,
        (Some("AccessDenied" | "Forbidden" | "Unauthorized"), _) => Error::Denied,
        (Some("NoSuchKey" | "NoSuchVersion" | "NoSuchUpload" | "NotFound"), _) => Error::Missing,
        (Some("BadDigest" | "InvalidDigest"), _) => Error::Integrity,
        (
            Some(
                "PreconditionFailed"
                | "ConditionalRequestConflict"
                | "InvalidPart"
                | "InvalidPartOrder"
                | "EntityTooSmall",
            ),
            _,
        ) => Error::Conflict,
        (_, Some(401 | 403)) => Error::Denied,
        (_, Some(412 | 409)) => Error::Conflict,
        // HEAD's generic 404 is not enough to distinguish a missing bucket.
        (_, _) => Error::Transient,
    }
}
pub(crate) fn uncertain<E: ProvideErrorMetadata + std::error::Error + 'static>(
    error: &SdkError<E>,
) -> bool {
    match error {
        SdkError::ConstructionFailure(_) => false,
        SdkError::ServiceError(_) => {
            classify(error) == Error::Transient
                || error
                    .raw_response()
                    .is_some_and(|r| r.status().as_u16() >= 500)
        }
        _ => true,
    }
}
pub(crate) async fn call<T, E: ProvideErrorMetadata + std::error::Error + 'static>(
    budget: &Budget,
    future: impl Future<Output = std::result::Result<T, SdkError<E>>>,
) -> Result<T> {
    tokio::time::timeout_at(budget.deadline.instant().into(), future)
        .await
        .map_err(|_| Error::Budget)?
        .map_err(|e| classify(&e))
}
pub(crate) async fn mutation<T, E: ProvideErrorMetadata + std::error::Error + 'static>(
    budget: &Budget,
    future: impl Future<Output = std::result::Result<T, SdkError<E>>>,
) -> Result<crate::Mutation<T>> {
    match tokio::time::timeout_at(budget.deadline.instant().into(), future).await {
        Err(_) => Ok(crate::Mutation::Unknown(Error::Budget)),
        Ok(Ok(value)) => Ok(crate::Mutation::Confirmed(value)),
        Ok(Err(error)) if uncertain(&error) => Ok(crate::Mutation::Unknown(classify(&error))),
        Ok(Err(error)) => Err(classify(&error)),
    }
}
pub(crate) fn checksum(value: Option<&str>) -> Result<[u8; 32]> {
    let decoded = STANDARD
        .decode(value.ok_or(Error::Integrity)?)
        .map_err(|_| Error::Integrity)?;
    decoded.try_into().map_err(|_| Error::Integrity)
}
pub(crate) fn encode(value: [u8; 32]) -> String {
    STANDARD.encode(value)
}
