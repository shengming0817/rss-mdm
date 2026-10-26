#![deny(missing_docs)]
//! Agent API families. Enrollment and runtime evolve independently.
//! HTTP API versions do not select task payload or signature versions.
mod addressing;
/// Persistent bootstrap, certificate activation and recovery contracts.
pub mod enroll;
/// Immutable producer baselines shipped with the protocol package; never execution grants.
pub mod packaged_collections;
/// Runtime JSON payloads and signed task values (wire version one).
pub mod runtime;
mod self_service;

/// Public device trust revisions and installation acknowledgements.
pub mod pki;
/// Public task-signing trust updates and durable installation acknowledgements.
pub mod task_trust;

/// Signed, revisioned transport locations bound to stable installation identity.
pub mod connections;

mod collection_scope;
pub use collection_scope::CollectionScope;

mod collection_environment;
pub use collection_environment::CollectionEnvironment;

/// Platform SSO registration and native-client contracts.
pub mod platform_sso;

/// Native proofs and RP Broker interaction contracts.
pub mod enterprise;

/// Independent, device-authenticated FileVault CMS custody.
pub mod filevault;

/// Shared static contract for published osquery templates and literal parameters.
pub mod osquery;

/// Device-scoped management activities and incremental history.
pub mod activities;
