//! Product execution contracts, lifecycle, storage and read service.
pub mod action_contract;
pub mod agent_install;
pub mod configuration;
pub mod enrollment;
mod error;
pub mod frozen;
pub mod model;
mod permissions;
pub mod protection;
pub mod task_signing;
pub use error::{ConfigIssue, Error, Failure};
pub use model::{AttemptPhase, Change, Create, DispatchV3, NativeTarget, Task};
use rss_mdm_authorization_service as authorization;

mod payload;
mod target;
pub use target::Target;
