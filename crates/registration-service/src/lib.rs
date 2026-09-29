//! Channel-neutral registration identity, credential binding and retirement.
mod database;
pub mod device;
pub mod enrollment;
mod error;
mod lifecycle;
mod operations;
pub use database::Store;
pub use device::{ChannelMount, DevicePrincipal, DeviceService, VerifiedChannelCredential};
pub use error::Error;
pub use lifecycle::{Retirement, retire};
use rss_mdm_authorization_service as authorization;

/// Fresh product schema owned by this capability.
pub const INSTALL_SQL: &str = include_str!("../schema/install.sql");
/// Cross-owner references and exact runtime privileges; apply after all owner tables.
pub const RELATIONS_SQL: &str = include_str!("../schema/relations.sql");
