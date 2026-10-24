#![deny(missing_docs)]
//! Agent API families. Enrollment and runtime evolve independently.
//! HTTP API versions do not select task payload or signature versions.
/// Persistent bootstrap, certificate activation and recovery contracts.
pub mod enroll;
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
