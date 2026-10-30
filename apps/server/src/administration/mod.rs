//! Application-owned administration; HTTP adapters consume these concrete services.
pub(crate) mod baseline;
pub(crate) mod first_use;
pub(crate) mod http;
mod http_error;
pub(crate) mod settings;
pub mod tenants;
pub(crate) mod user_profiles;

fn permission_denied(error: &crate::Error) -> bool {
    use crate::Error;
    matches!(
        error,
        Error::Forbidden
            | Error::Unauthorized
            | Error::Authorization(
                rss_mdm_authorization_service::Error::Forbidden
                    | rss_mdm_authorization_service::Error::Unauthorized
            )
            | Error::Execution(
                rss_mdm_execution_service::Error::Forbidden
                    | rss_mdm_execution_service::Error::Unauthorized
            )
            | Error::Webhook(
                rss_mdm_webhook_service::Error::Denied
                    | rss_mdm_webhook_service::Error::Unauthorized
            )
    )
}
