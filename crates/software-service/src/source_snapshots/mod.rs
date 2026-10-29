//! Current, read-only source JSON. Enterprise software owns any subsequently copied data.
//! ref: serde-rs/json src/value/mod.rs@v1.0.151; sqlx-core/src/transaction.rs@v0.9.0.
mod model;
mod read;
mod storage;
mod write;
pub use model::*;
pub use read::{ENTRIES, SOURCES, entries, entry, operation, snapshot, sources};
pub use write::replace;
use crate::management::{
    Error, Failure, content::ManagementContentPort, catalog::Access,
    transaction::{self, Fault, TransactionOwner},
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use rss_transactional_messaging_postgres::PgTransaction;
use serde_json::Value;
use sha2::{Digest, Sha256};
pub const INSTALL_SQL: &str = include_str!("install.sql");
pub const ADMISSION_SQL: &str = include_str!("admission.sql");
pub const ACCESS_CONTRACT: &str = include_str!("access.json");
/// The HTTP envelope, not just its document, is bounded by this limit.
pub const MAX_REQUEST_BYTES: usize = 64 * 1024 * 1024;
const MAX_ENTRIES: usize = 100_000;
fn invalid() -> Error { Error::Malformed }
fn invariant() -> Error { Error::Unavailable(Failure::SoftwareCatalogInvariant) }
fn source_id(source: &str) -> Result<(), Error> {
    rss_mdm_resource::Id::new(source).map(|_| ()).map_err(|_| invalid())
}
async fn authorize(
    tx: &mut PgTransaction<'_>, proof: &AuthorizedPrincipal, permission: Permission,
) -> transaction::Result<rss_mdm_authorization_service::Snapshot> {
    let current = transaction::current(tx, proof).await?;
    current.require(proof, permission, None)?;
    proof.check_live()?;
    Ok(current)
}
