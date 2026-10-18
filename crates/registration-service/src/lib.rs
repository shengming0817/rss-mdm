//! Channel-neutral registration identity, credential binding and retirement.
pub mod admission;
pub mod agent;
pub mod agent_pki;
mod database;
pub mod device;
pub mod enrollment;
mod error;
mod lifecycle;
mod operations;
pub mod quotas;
pub mod windows_entra;
pub mod windows_receipts;
pub use database::Store;
pub use device::{
    ChannelMount, DevicePrincipal, DeviceService, Purpose, VerifiedChannelCredential,
};
pub use error::Error;
pub use lifecycle::{Retirement, retire};
use rss_mdm_authorization_service as authorization;

/// Fresh product schema owned by this capability.
pub const AGENT_NATIVE_SQL: &str = include_str!("../schema/agent-native.sql");
pub const AGENT_BOOTSTRAP_SQL: &str = include_str!("../schema/agent-bootstrap.sql");
pub const INSTALL_SQL: &str = include_str!("../schema/install.sql");
/// Cross-owner references and exact runtime privileges; apply after all owner tables.
pub const RELATIONS_SQL: &str = include_str!("../schema/relations.sql");

/// This capability's closed privileges in the shared access connection.
pub const ACCESS_CONTRACT: &str = include_str!("access-contract.json");

/// Current quota schema; installation remains fresh-only.
pub const QUOTAS_SQL: &str = include_str!("../schema/quotas.sql");

/// Adds durable native management contact without guessing historical evidence.
pub const ENROLLMENT_PROGRESS_SQL: &str = include_str!("../schema/enrollment-progress.sql");

/// Durable Apple account authorization on the existing request lifecycle.
pub const APPLE_ACCOUNT_SQL: &str = include_str!("../schema/apple-account.sql");

pub const APPLE_ADE_SQL: &str = include_str!("../schema/apple-ade.sql");

/// Registration settings and reusable administrator configurations.
pub const AGENT_CONFIGURATIONS_SQL: &str = include_str!("../schema/agent-configurations.sql");

pub const WINDOWS_ENTRA_SQL: &str = include_str!("../schema/windows-entra.sql");

/// Windows operation receipts owned by registration; install after the Windows schema namespace.
pub const WINDOWS_RECEIPTS_SQL: &str = include_str!("../schema/windows-receipts.sql");
/// Current Entra registration policy, before native consent tables.
pub const WINDOWS_ENTRA_POLICY_SQL: &str = include_str!("../schema/windows-entra-policy.sql");

/// Dynamic new-registration admission schema.
pub const ADMISSION_SQL: &str = include_str!("../schema/admission.sql");
