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

/// Expected coordinates for one atomic Scope object and channel publication.
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
    profile: rss_mdm_install_support::StorageProfile,
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
    pub fn profile(&self) -> rss_mdm_install_support::StorageProfile {
        self.profile
    }
    pub fn new(
        profile: rss_mdm_install_support::StorageProfile,
        runtime: Arc<PgRuntime>,
        tenant: TenantId,
    ) -> Self {
        Self {
            profile,
            runtime,
            tenant,
        }
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

/// Scope-owned durable Group change acceptance and bounded fan-out.
pub const fn group_changes_sql(profile: rss_mdm_install_support::StorageProfile) -> &'static str {
    storage_profile::sql(profile).group_changes
}
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
        let profile = self.profile();

        self.validate_in(tx)?;
        self.admit_group_changes_in(tx, true).await?;
        let tenant = self.tenant.to_string();
        let event = event.to_owned();
        tx.with_connection(move |c|Box::pin(async move {
            sqlx::query(crate::storage_profile::sql(profile).lib_accept_group_change_in_1).bind(tenant).bind(event).bind(group).execute(&mut *c).await?;
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
        let profile = self.profile();

        self.validate_in(tx)?;
        self.admit_group_changes_in(tx, false).await?;
        let tenant = self.tenant.to_string();
        let row = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    sqlx::query_as::<_, (String, Uuid, Option<Uuid>)>(
                        crate::storage_profile::sql(profile).lib_group_change_page_in_1,
                    )
                    .bind(tenant)
                    .fetch_optional(c)
                    .await
                })
            })
            .await?;
        let Some((event, group, cursor)) = row else {
            return Ok(None);
        };
        let tenant = self.tenant.to_string();
        let mut scopes = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    sqlx::query_scalar::<_, Uuid>(
                        crate::storage_profile::sql(profile).lib_group_change_page_in_2,
                    )
                    .bind(tenant)
                    .bind(group.to_string())
                    .bind(cursor)
                    .fetch_all(c)
                    .await
                })
            })
            .await?;
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
        let profile = self.profile();

        self.validate_in(tx)?;
        self.admit_group_changes_in(tx, false).await?;
        let tenant = self.tenant.to_string();
        let event = page.event.clone();
        let cursor = page.scopes.last().copied();
        let done = !page.more;
        tx.with_connection(move |c| {
            Box::pin(async move {
                sqlx::query(
                    crate::storage_profile::sql(profile).lib_complete_group_change_page_in_1,
                )
                .bind(tenant)
                .bind(event)
                .bind(cursor)
                .bind(done)
                .execute(c)
                .await?;
                Ok(())
            })
        })
        .await?;
        Ok(())
    }
}

/// Current Scope reference facts for a tenant-bound composable read ($1 is the tenant).
/// Coordinates are derived from the definition and published head without a mirror table.
pub const fn group_reference_facts_sql(
    profile: rss_mdm_install_support::StorageProfile,
) -> &'static str {
    storage_profile::sql(profile).group_reference_facts
}

impl ScopeBinding {
    async fn admit_group_changes_in(
        &self,
        tx: &mut PgTransaction<'_>,
        append: bool,
    ) -> Result<(), BindingError> {
        let profile = self.profile();
        let valid = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    sqlx::query_scalar::<_, bool>(
                        crate::storage_profile::sql(profile).group_change_admission,
                    )
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
pub const fn install_sql(profile: rss_mdm_install_support::StorageProfile) -> &'static str {
    storage_profile::sql(profile).install
}
/// Scope references and privileges, installed after all owner schemas.
pub const fn relations_sql(profile: rss_mdm_install_support::StorageProfile) -> &'static str {
    storage_profile::sql(profile).relations
}

mod store;
pub use store::{Head, Run, SourceMember, Task};

mod authority;
pub use authority::verify_authority;

mod directory;

/// Minimal frozen Scope facts consumed by the access role.
pub const ACCESS_CONTRACT: &str =
    crate::storage_profile::sql(rss_mdm_install_support::StorageProfile::Mdm).access_contract;
pub async fn verify_access(
    profile: rss_mdm_install_support::StorageProfile,
    connection: &mut sqlx::PgConnection,
) -> Result<(), sqlx::Error> {
    let valid: bool = sqlx::query_scalar(crate::storage_profile::sql(profile).access_admission)
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
        let profile = self.profile();

        self.validate_in(tx)?;
        let tenant = self.tenant.to_string();
        let objects = serde_json::Value::Array(objects);
        Ok(tx
            .with_connection(move |c| {
                Box::pin(async move {
                    sqlx::query_scalar(crate::storage_profile::sql(profile).lib_target_members_in_1)
                        .bind(tenant)
                        .bind(scope)
                        .bind(objects)
                        .fetch_all(c)
                        .await
                })
            })
            .await?)
    }
}

pub use store::RelationWindow;

mod state;
pub use state::{admission_on, state_on};

/// Scope-owned channel projection schema and exact capability admission.
pub const fn projections_sql(profile: rss_mdm_install_support::StorageProfile) -> &'static str {
    storage_profile::sql(profile).projections
}
pub const fn projection_relations_sql(
    profile: rss_mdm_install_support::StorageProfile,
) -> &'static str {
    storage_profile::sql(profile).projection_relations
}
pub const fn projection_admission_sql(
    profile: rss_mdm_install_support::StorageProfile,
) -> &'static str {
    storage_profile::sql(profile).projection_admission
}
pub async fn verify_projection_access(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
) -> Result<(), sqlx::Error> {
    let valid: bool = sqlx::query_scalar(projection_admission_sql(profile))
        .bind(false)
        .fetch_one(c)
        .await?;
    if !valid {
        return Err(sqlx::Error::Protocol(
            "Scope projection reader rejected".into(),
        ));
    }
    Ok(())
}

mod storage_profile;

/// Shared owner objects, combined by the host for complete schema admission.
pub const fn object_manifest(profile: rss_mdm_install_support::StorageProfile) -> &'static str {
    storage_profile::sql(profile).object_manifest
}
/// Exact access-role contract for this installation.
pub const fn access_contract(profile: rss_mdm_install_support::StorageProfile) -> &'static str {
    storage_profile::sql(profile).access_contract
}

mod operations;

/// Direct Group blockers, selected by the reverse source index before projecting roles.
pub const fn group_blocker_facts_sql(
    profile: rss_mdm_install_support::StorageProfile,
) -> &'static str {
    storage_profile::sql(profile).group_blocker_facts
}
