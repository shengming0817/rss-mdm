//! Scope definitions, immutable sources/results, tasks and consumer checkpoints.
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
/// before SQL. Application construction additionally verifies the effective-role storage contract.
pub struct ScopeBinding {
    runtime: Arc<PgRuntime>,
    tenant: TenantId,
}
#[derive(Debug, thiserror::Error)]
pub enum BindingError {
    #[error("scope tenant mismatch")]
    TenantMismatch,
    #[error("scope not found")]
    Missing,
    #[error("scope changed")]
    Conflict,
    #[error("invalid scope input")]
    Invalid,
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

impl ScopeBinding {
    /// Read active Scope references while the caller holds the target Group lock.
    /// Scope reference creation participates in that same lock protocol.
    pub async fn group_used_in(
        &self,
        tx: &mut PgTransaction<'_>,
        group: Uuid,
    ) -> Result<bool, BindingError> {
        self.validate_in(tx)?;
        let tenant = self.tenant.to_string();
        Ok(tx.with_connection(move |c| Box::pin(async move {
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_scope.scope_sources e JOIN mdm_scope.scopes s ON(s.tenant_id,s.id)=(e.tenant_id,e.scope) WHERE e.tenant_id=$1::uuid AND NOT s.deleted AND e.kind='group' AND e.target=$2)")
                .bind(tenant).bind(group.to_string()).fetch_one(c).await
        })).await?)
    }
}

/// Scope-owned durable Group change acceptance and bounded fan-out.
pub const GROUP_CHANGES_SQL: &str = include_str!("../schema/group-changes.sql");
/// One page locked until the original initiating transaction settles.
pub struct GroupChangePage {
    /// Original message identity, retained independently of other changes.
    pub event: String,
    /// Current active Scope references, in stable UUID order.
    pub scopes: Vec<Uuid>,
    /// Whether another bounded page remains.
    pub more: bool,
}
impl ScopeBinding {
    /// Accept a verified Group event in the RSS consumer's actual transaction.
    pub async fn accept_group_change_in(
        &self,
        tx: &mut PgTransaction<'_>,
        event: &str,
        group: Uuid,
    ) -> Result<(), BindingError> {
        self.validate_in(tx)?;
        self.admit_group_changes_in(tx, true).await?;
        let tenant = self.tenant.to_string();
        let event = event.to_owned();
        tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("INSERT INTO mdm_scope.group_changes(tenant_id,event_id,group_id) VALUES($1::uuid,$2,$3)").bind(tenant).bind(event).bind(group).execute(&mut *c).await?;
            sqlx::query("SELECT pg_notify('mdm_work_' || replace(current_setting('rss.tenant_id')::uuid::text,'-',''),'scopes')").execute(c).await?;
            Ok(())
        })).await?;
        Ok(())
    }
    /// Lock one pending event and read at most 64 dependent Scopes.
    pub async fn group_change_page_in(
        &self,
        tx: &mut PgTransaction<'_>,
    ) -> Result<Option<GroupChangePage>, BindingError> {
        self.validate_in(tx)?;
        self.admit_group_changes_in(tx, false).await?;
        let tenant = self.tenant.to_string();
        let row=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query_as::<_,(String,Uuid,Option<Uuid>)>("SELECT event_id,group_id,cursor FROM mdm_scope.group_changes WHERE tenant_id=$1::uuid AND NOT completed ORDER BY event_id LIMIT 1 FOR UPDATE SKIP LOCKED").bind(tenant).fetch_optional(c).await
        })).await?;
        let Some((event, group, cursor)) = row else {
            return Ok(None);
        };
        let tenant = self.tenant.to_string();
        let mut scopes=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query_scalar::<_,Uuid>("SELECT DISTINCT s.id FROM mdm_scope.scopes s JOIN mdm_scope.scope_sources e ON(e.tenant_id,e.scope)=(s.tenant_id,s.id) WHERE s.tenant_id=$1::uuid AND NOT s.deleted AND e.kind='group' AND e.target=$2 AND ($3::uuid IS NULL OR s.id>$3) ORDER BY s.id LIMIT 65")
                .bind(tenant).bind(group.to_string()).bind(cursor).fetch_all(c).await
        })).await?;
        let more = scopes.len() > 64;
        scopes.truncate(64);
        Ok(Some(GroupChangePage {
            event,
            scopes,
            more,
        }))
    }
    /// Advance only after every Scope request in this page was persisted in this transaction.
    pub async fn complete_group_change_page_in(
        &self,
        tx: &mut PgTransaction<'_>,
        page: &GroupChangePage,
    ) -> Result<(), BindingError> {
        self.validate_in(tx)?;
        self.admit_group_changes_in(tx, false).await?;
        let tenant = self.tenant.to_string();
        let event = page.event.clone();
        let cursor = page.scopes.last().copied();
        let done = !page.more;
        tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("UPDATE mdm_scope.group_changes SET cursor=$3,completed=$4 WHERE tenant_id=$1::uuid AND event_id=$2 AND NOT completed")
                .bind(tenant).bind(event).bind(cursor).bind(done).execute(c).await?;
            Ok(())
        })).await?;
        Ok(())
    }
}

/// Current Scope reference facts for a tenant-bound composable read ($1 is the tenant).
/// Coordinates are derived from the definition and published head without a mirror table.
pub const GROUP_REFERENCE_FACTS_SQL: &str = r#"
SELECT s.tenant_id,s.id,s.revision,s.deleted,s.resolution,s.resolution_revision,s.calculation_revision,
 v.definition,r.phase,
 ARRAY(SELECT e.target::uuid FROM mdm_scope.scope_sources e WHERE e.tenant_id=s.tenant_id AND e.scope=s.id AND e.kind='group' ORDER BY e.target)::uuid[] AS group_ids
FROM mdm_scope.scopes s
JOIN mdm_scope.scope_versions v ON(v.tenant_id,v.id,v.revision)=(s.tenant_id,s.id,s.revision)
LEFT JOIN mdm_scope.scope_runs r ON(r.tenant_id,r.id)=(s.tenant_id,s.resolution)
WHERE s.tenant_id=$1::uuid
"#;

impl ScopeBinding {
    async fn admit_group_changes_in(
        &self,
        tx: &mut PgTransaction<'_>,
        append: bool,
    ) -> Result<(), BindingError> {
        let valid = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    sqlx::query_scalar::<_, bool>(include_str!("group-changes-admission.sql"))
                        .bind(append)
                        .fetch_one(c)
                        .await
                })
            })
            .await?;
        if !valid {
            return Err(BindingError::Storage(
                sqlx::Error::Protocol("Scope change capability rejected".into()).into(),
            ));
        }
        Ok(())
    }
}

/// Current Scope schema.
pub const INSTALL_SQL: &str = include_str!("../schema/install.sql");
/// Scope references and privileges, installed after all owner schemas.
pub const RELATIONS_SQL: &str = include_str!("../schema/relations.sql");

mod store;
pub use store::{Head, Run, SourceMember, Task};

mod authority;
pub use authority::verify_authority;

mod directory;

/// Minimal frozen Scope facts consumed by the access role.
pub const ACCESS_CONTRACT: &str = include_str!("access-contract.json");
pub async fn verify_access(connection: &mut sqlx::PgConnection) -> Result<(), sqlx::Error> {
    let valid: bool = sqlx::query_scalar(include_str!("access-admission.sql"))
        .fetch_one(connection)
        .await?;
    if !valid {
        return Err(sqlx::Error::Protocol(
            "Scope reader admission rejected".into(),
        ));
    }
    Ok(())
}

impl ScopeBinding {
    /// Existing target-reference members, before limitations/exclusions or channel eligibility.
    /// Used to distinguish a removed source object from an unavailable assignment.
    pub async fn target_members_in(
        &self,
        tx: &mut PgTransaction<'_>,
        scope: Uuid,
        objects: Vec<serde_json::Value>,
    ) -> Result<Vec<serde_json::Value>, BindingError> {
        self.validate_in(tx)?;
        let tenant = self.tenant.to_string();
        let objects = serde_json::Value::Array(objects);
        Ok(tx.with_connection(move|c|Box::pin(async move {
            sqlx::query_scalar("SELECT DISTINCT m.input->'object' FROM mdm_scope.scopes s JOIN mdm_scope.scope_runs r ON(r.tenant_id,r.id)=(s.tenant_id,s.resolution) JOIN mdm_scope.scope_source_members m ON(m.tenant_id,m.run)=(r.tenant_id,r.id) JOIN LATERAL jsonb_array_elements(r.input->'sources') WITH ORDINALITY source(value,ordinal) ON source.ordinal=m.source+1 WHERE s.tenant_id=$1::uuid AND s.id=$2 AND r.input->'definition'->'targets' @> jsonb_build_array(source.value->'reference') AND EXISTS(SELECT 1 FROM jsonb_array_elements($3::jsonb) candidate WHERE candidate=m.input->'object')").bind(tenant).bind(scope).bind(objects).fetch_all(c).await
        })).await?)
    }
}

pub use store::RelationWindow;

mod state;
pub use state::{admission_on, state_on};
