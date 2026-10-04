#![deny(missing_docs)]
//! Agent API families. Enrollment and runtime evolve independently.
//! HTTP API versions do not select task payload or signature versions.
/// Persistent bootstrap, certificate activation and recovery contracts.
pub mod enroll;
/// Runtime JSON payloads and signed task values (wire version one).
pub mod runtime;
