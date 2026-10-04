//! Product-owned S3 content operations. No business authority, journal or implicit cleanup.
//!
//! Historical extraction: RSS 5b63e10a1b396b0ff70b7d1e6e55db296cd7a891,
//! adapters/s3/src/{store.rs,dlx_archive.rs,private_ca.rs}. Old public APIs are not retained.
//! ref: aws-sdk-rust sdk/s3/src/operation/complete_multipart_upload/builders.rs
#![forbid(unsafe_code)]
mod model;
pub use model::*;

mod config;
pub use config::{Config, Credentials, Secrets};
mod body;
mod provider;
pub use body::{ByteStreamInput, ByteStreamOutput};
mod store;
pub use store::Store;
mod multipart;
#[cfg(test)]
#[path = "../tests/s3.rs"]
mod s3_tests;
