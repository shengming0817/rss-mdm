//! Application-owned administration; HTTP adapters consume these concrete services.
pub(crate) mod user_profiles;
pub(crate) mod first_use;
pub(crate) mod settings;
pub(crate) mod baseline;
pub mod tenants;
pub(crate) mod http;
mod http_error;
