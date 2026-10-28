//! Scope-specific persistence contracts. F03 (#3042) migrates SQL and admission.
//! No connection, migration, commit or worker is created here.
use rss_mdm_scope::ScopeDefinition;
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::{PgError, PgRuntime, PgTransaction};
use std::sync::Arc;
use uuid::Uuid;

/// Authored definition and its CAS revision, independent of observation progress.
pub struct DefinitionSnapshot {
    /// Current authored revision; deletion is checked by the owner read.
    pub revision: u64,
    /// Authored selection, not a materialized member set.
    pub definition: ScopeDefinition,
}

/// Expected coordinates for one atomic Scope/Execution projection publication.
/// This is an input, not proof that either owner has completed its work.
pub struct Publication {
    pub scope: Uuid,
    pub run: Uuid,
    pub definition_revision: u64,
    pub previous_resolution: Option<Uuid>,
}

/// Binding for a host-admitted Scope participant, not an authorization grant.
/// App supplies the initiating runtime; all provider methods must validate it
/// before SQL. The full store and its effective-role admission arrive in F03.
pub struct ScopeBinding {
    runtime: Arc<PgRuntime>,
    tenant: TenantId,
}
#[derive(Debug, thiserror::Error)]
pub enum BindingError {
    #[error("scope tenant mismatch")]
    TenantMismatch,
    #[error(transparent)]
    Storage(#[from] PgError),
}
impl ScopeBinding {
    pub fn new(runtime: Arc<PgRuntime>, tenant: TenantId) -> Self {
        Self { runtime, tenant }
    }
    /// Validate the actual runtime instance and tenant without acquiring a connection.
    pub fn validate_in(&self, tx: &PgTransaction<'_>) -> Result<(), BindingError> {
        self.runtime.validate_transaction(tx)?;
        if tx.tenant_id() != self.tenant {
            return Err(BindingError::TenantMismatch);
        }
        Ok(())
    }
}
