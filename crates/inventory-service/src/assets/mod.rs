//! One product asset composition; Inventory resolves facts, Group evaluates conditions.

use crate::operation::Operation;
use crate::transaction::*;
use crate::{Error, Failure};
use rss_contract::Timepoint;
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_inventory::AssetCut;
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::PgTransaction;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use uuid::Uuid;
pub mod channel;
pub mod cut;
pub mod evaluation;
pub mod filter;

mod directory;
pub mod field_directory;
mod field_layout;
mod fields;
pub mod windows;
pub use field_layout::{FieldDisplayGroup, FieldLayout, FieldLayoutAccess};
mod lists;
mod runs;
mod scopes;
pub use fields::{FieldChange, FieldImpact, FieldMappingReference, FieldReferenceQuery, FieldView};
mod model;
pub mod planning;
pub mod raw_snapshot;
mod summaries;
pub use summaries::DeviceSummary;
mod checkpoint;
mod quality;
mod query;
mod query_read;
mod query_sort;
pub mod rsql;
pub mod runtime;
pub mod saved_directory;
mod store;
pub mod tasks;
pub use filter::{criteria_view, rule};

pub use model::*;
fn digest(value: &(impl serde::Serialize + ?Sized)) -> Result<String> {
    Ok(format!(
        "{:x}",
        Sha256::digest(checked_input(serde_json::to_vec(value))?)
    ))
}
impl AssetService {
    async fn dispatch(
        &self,
        tx: &mut PgTransaction<'_>,
        command: &Command,
        at: Timepoint,
        cut: Option<&AssetCut>,
    ) -> Result<AssetEnvelope> {
        let response = match command {
            Command::InventoryScopes {
                device,
                scope,
                limit,
                cursor,
            } => {
                self.inventory_scopes(
                    tx,
                    device,
                    scope,
                    *limit,
                    cursor.as_deref(),
                    cut.ok_or(Error::Unavailable(Failure::AssetsStorage))?,
                )
                .await?
            }
            Command::FieldLayoutRead { access } => self.field_layout_read(tx, access).await?,
            Command::FieldLayoutWrite { change } => self.field_layout_write(tx, change).await?,
            Command::RetentionWrite { change } => {
                checked_input(change.input.validate())?;
                if change.expected_revision.checked_add(1) != Some(change.input.revision) {
                    return Err(Error::Conflict.into());
                }
                let tenant = self.tenant;
                let policy = change.input.clone();
                let changed = tx
                    .with_connection(move |c| {
                        Box::pin(async move {
                            rss_mdm_inventory_postgres::publish_retention_policy_in(
                                c, tenant, &policy,
                            )
                            .await
                            .map_err(|_| {
                                sqlx::Error::Protocol("retention publication rejected".into())
                            })
                        })
                    })
                    .await?;
                if !changed {
                    return Err(Error::Conflict.into());
                }
                Response::RetentionPolicy {
                    policy: Some(change.input.clone()),
                }
            }
            Command::RetentionRead { key, revision } => {
                if *revision == 0 || *revision > i64::MAX as u64 {
                    return Err(Error::Malformed.into());
                }
                let tenant = self.tenant;
                let key = key.clone();
                let revision = *revision;
                let policy = tx
                    .with_connection(move |c| {
                        Box::pin(async move {
                            rss_mdm_inventory_postgres::retention_policy_in(
                                c, tenant, &key, revision,
                            )
                            .await
                            .map_err(|_| sqlx::Error::Protocol("retention unavailable".into()))
                        })
                    })
                    .await?;
                Response::RetentionPolicy { policy }
            }
            Command::CollectionItems {
                device,
                run,
                field,
                scope,
                cursor,
                limit,
            } => {
                self.collection_items(tx, device, *run, *field, scope, (cursor.as_deref(), *limit))
                    .await?
            }
            Command::ListItems {
                device,
                field,
                scope,
                limit,
                cursor,
            } => {
                self.list_items(
                    tx,
                    device,
                    *field,
                    scope,
                    (cursor.as_deref(), *limit),
                    cut.ok_or(Error::Unavailable(Failure::AssetsStorage))?,
                )
                .await?
            }
            Command::CollectionRun { device, run, scope } => Response::CollectionRun {
                run: Box::new(self.collection_run(tx, device, *run, scope).await?),
            },
            Command::FieldWrite { field, change } => self.field_write(tx, *field, change).await?,
            Command::FieldReferences { field, query } => {
                let page = self.field_mapping_references(tx, *field, query).await?;
                Response::FieldReferences {
                    field: *field,
                    impact: self.field_impact(tx, *field).await?,
                    mappings: page.items,
                    next_cursor: page.next_cursor,
                }
            }
            Command::Detail { device, scope } => {
                if scope
                    .devices
                    .as_ref()
                    .is_some_and(|ids| !ids.contains(device))
                {
                    return Err(Error::Forbidden.into());
                }
                let view = self
                    .detail_metadata(
                        tx,
                        device,
                        scope,
                        cut.ok_or(Error::Unavailable(Failure::AssetsStorage))?,
                    )
                    .await?;
                Response::Detail { device: view }
            }
            Command::Search { request, scope } => {
                if request.expected_revision != 0 {
                    return Err(Error::Malformed.into());
                }
                self.asset_query(
                    tx,
                    request.operation_id,
                    scope,
                    &request.input,
                    at,
                    cut.ok_or(Error::Unavailable(Failure::AssetsStorage))?,
                )
                .await?
            }
            Command::QueryStatus { task, scope } => {
                self.asset_query_status(tx, *task, scope).await?
            }
            Command::QueryItems {
                task,
                scope,
                limit,
                cursor,
            } => {
                self.asset_query_items(tx, *task, scope, *limit, cursor.as_deref())
                    .await?
            }
            Command::QueryFacets {
                task,
                scope,
                facet,
                limit,
                cursor,
            } => {
                self.asset_query_facets(tx, *task, scope, *facet, *limit, cursor.as_deref())
                    .await?
            }
            Command::Manual {
                device,
                field,
                change,
                owner,
            } => {
                self.assign_asset(tx, device, *field, change, owner, at)
                    .await?
            }
            Command::SavedRead { owner, id } => Response::Saved {
                query: self.saved_read(tx, owner, *id).await?,
            },
            Command::SavedWrite { owner, id, change } => {
                self.saved_write(tx, owner, *id, change).await?
            }
            Command::SavedExecute {
                operation,
                expected_revision,
                owner,
                id,
                scope,
            } => {
                let saved = self.saved_read(tx, owner, *id).await?;
                if saved.revision as u64 != *expected_revision {
                    return Err(Error::Conflict.into());
                }
                let definition = saved.definition.ok_or(Error::NotFound)?;
                self.asset_query(
                    tx,
                    *operation,
                    scope,
                    &definition.query,
                    at,
                    cut.ok_or(Error::Unavailable(Failure::AssetsStorage))?,
                )
                .await?
            }
        };
        Ok(AssetEnvelope {
            tenant_id: self.tenant.to_string(),
            asset: response,
        })
    }
}
#[derive(schemars::JsonSchema, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssetEnvelope {
    pub tenant_id: String,
    pub asset: Response,
}

#[cfg(test)]
#[path = "../../tests/assets/unit.rs"]
mod tests;

/// Asset algorithms and resources, independently constructible from planning workflows.
pub struct AssetService {
    worker_health: std::sync::Mutex<crate::worker_health::ObservationState>,
    task_status: std::sync::OnceLock<rss_runtime::TaskStatus>,
    inventory: Arc<crate::inventory_runtime::InventoryRuntime>,
    reconcile_messaging: rss_reconcile_postgres::PgMessagingStore,
    audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    runtime: Arc<rss_transactional_messaging_postgres::PgRuntime>,
    tenant: TenantId,
    clock: Arc<dyn crate::clock::Clock>,
    asset_cursor_key: ring::hmac::Key,
}
impl AssetService {
    pub fn new(
        inventory: Arc<crate::inventory_runtime::InventoryRuntime>,
        audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
        runtime: Arc<rss_transactional_messaging_postgres::PgRuntime>,
        tenant: TenantId,
        clock: Arc<dyn crate::clock::Clock>,
        cursor_key: &[u8],
        reconcile_messaging: rss_reconcile_postgres::PgMessagingStore,
    ) -> Self {
        Self {
            task_status: Default::default(),
            worker_health: Default::default(),
            inventory,
            reconcile_messaging,
            audit_store,
            runtime,
            tenant,
            clock,
            asset_cursor_key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, cursor_key),
        }
    }
    pub async fn execute(
        &self,
        command: &Command,
        audit: &RequestAudit,
        authorize: &(dyn Fn() -> std::result::Result<(), Error> + Sync),
    ) -> std::result::Result<AssetEnvelope, Error> {
        self.execute_with_initialization(command, audit, authorize, None, None)
            .await
    }
    pub async fn execute_authorized(
        &self,
        command: &Command,
        audit: &RequestAudit,
        proof: &crate::authorization::context::AuthorizedPrincipal,
        authorize: &(dyn Fn() -> std::result::Result<(), Error> + Sync),
    ) -> std::result::Result<AssetEnvelope, Error> {
        self.execute_with_initialization(command, audit, authorize, None, Some(proof))
            .await
    }
    /// Baseline fields and retention use the ordinary asset mutation and receipt owner.
    pub async fn execute_initialization(
        &self,
        command: &Command,
        audit: &RequestAudit,
        proof: &rss_mdm_authorization_service::context::AuthorizedPrincipal,
    ) -> std::result::Result<AssetEnvelope, Error> {
        self.execute_with_initialization(
            command,
            audit,
            &|| {
                proof
                    .manage(rss_mdm_authorization_service::Permission::InventoryFieldsWrite)
                    .map_err(Error::from)
            },
            Some(proof),
            Some(proof),
        )
        .await
    }
    async fn execute_with_initialization(
        &self,
        command: &Command,
        audit: &RequestAudit,
        authorize: &(dyn Fn() -> std::result::Result<(), Error> + Sync),
        initialization: Option<&rss_mdm_authorization_service::context::AuthorizedPrincipal>,
        principal: Option<&rss_mdm_authorization_service::context::AuthorizedPrincipal>,
    ) -> std::result::Result<AssetEnvelope, Error> {
        authorize()?;
        let budget =
            rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(6));
        let cut = if matches!(
            command,
            Command::Detail { .. }
                | Command::ListItems { .. }
                | Command::InventoryScopes { .. }
                | Command::Search { .. }
                | Command::SavedExecute { .. }
        ) {
            Some(cut::capture(&self.audit_store, self.tenant, &budget).await?)
        } else {
            None
        };
        crate::transaction::run_budget(
            &self.audit_store,
            &self.runtime,
            self.tenant,
            audit,
            &(
                self,
                command,
                audit,
                authorize,
                initialization,
                principal,
                cut.as_ref(),
            ),
            |ctx, tx| {
                Box::pin(async move {
                    let (service, command, audit, authorize, initialization, principal, cut) = *ctx;
                    if let Some(proof) = initialization {
                        let target = match command {
                            Command::FieldWrite { field, .. } => field.as_str(),
                            Command::RetentionWrite { change } => change.input.key.as_str(),
                            _ => return Err(Error::Forbidden.into()),
                        };
                        rss_mdm_authorization_service::baseline::check_in(
                            tx,
                            proof,
                            rss_mdm_authorization_service::Permission::InventoryFieldsWrite,
                            target,
                        )
                        .await?;
                    }
                    service
                        .execute_in(tx, command, audit, authorize, *principal, *cut)
                        .await
                })
            },
            crate::transaction::TransactionOwner::Assets,
            rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                budget.control().total_remaining(),
            ),
        )
        .await
    }
    async fn execute_in(
        &self,
        tx: &mut PgTransaction<'_>,
        command: &Command,
        audit: &RequestAudit,
        authorize: &(dyn Fn() -> std::result::Result<(), Error> + Sync),
        principal: Option<&rss_mdm_authorization_service::context::AuthorizedPrincipal>,
        cut: Option<&AssetCut>,
    ) -> Result<AssetEnvelope> {
        if let Some(p) = principal {
            let current = query_authority(tx, p).await?;
            match command {
                Command::Search { scope, .. }
                | Command::QueryStatus { scope, .. }
                | Command::QueryItems { scope, .. }
                | Command::QueryFacets { scope, .. }
                | Command::SavedExecute { scope, .. }
                | Command::Detail { scope, .. }
                | Command::InventoryScopes { scope, .. }
                | Command::CollectionRun { scope, .. }
                | Command::CollectionItems { scope, .. }
                | Command::ListItems { scope, .. } => {
                    let mut fresh = ReadScope::from_snapshot(p, &current)?;
                    fresh.collection_scope = scope.collection_scope.clone();
                    if &fresh != scope {
                        return Err(Error::Forbidden.into());
                    }
                }
                Command::FieldReferences { query, .. }
                    if query.authority != current.query_binding(p)? =>
                {
                    return Err(Error::Forbidden.into());
                }
                _ => {}
            }
        }
        authorize()?;
        self.audit_store.prepare_in(tx, audit, &[]).await?;
        let (operation, fingerprint) = operation_identity(command, audit)?;
        if let Some(id) = operation
            && let Some(old) = crate::assets::receipts::replay(tx, audit, id, &fingerprint).await?
        {
            audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);
            crate::assets::receipts::audit(tx, &self.audit_store, audit, operation, true).await?;
            authorize()?;
            return Ok(old);
        }
        let at = self
            .clock
            .unix_seconds()
            .ok_or(Error::Unavailable(Failure::Clock))?;
        let value = self
            .dispatch(tx, command, checked_input(Timepoint::try_from(at))?, cut)
            .await?;
        if let Some(id) = operation {
            crate::assets::receipts::receipt(tx, audit, id, &fingerprint, &value).await?;
        }
        crate::assets::receipts::audit(tx, &self.audit_store, audit, operation, false).await?;
        authorize()?;
        Ok(value)
    }
}
// The persisted operation fingerprint is independent of the internal dispatcher type.
fn operation_identity(command: &Command, audit: &RequestAudit) -> Result<(Option<Uuid>, Vec<u8>)> {
    #[derive(serde::Serialize)]
    struct Fingerprint<'a> {
        kind: &'static str,
        command: &'a Command,
    }
    let operation = command.operation();
    if operation.is_some_and(|id| id.is_nil()) {
        return Err(Error::Malformed.into());
    }
    let actor = audit.snapshot();
    let bytes = checked_input(serde_json::to_vec(&(
        audit.tenant(),
        actor.actor,
        actor.instance,
        Fingerprint {
            kind: "Asset",
            command,
        },
    )))?;
    Ok((operation, Sha256::digest(bytes).to_vec()))
}

mod error;
use error::AssetError;

mod receipts;

pub const ADMISSION_SQL: &str = include_str!("admission.sql");

/// Resolve only a persisted manual-assignment receipt, never a mutable current asset value.
pub async fn timeline_device_in(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    actor: &str,
    operation: Uuid,
    event_id: &str,
) -> std::result::Result<Option<String>, sqlx::Error> {
    use sha2::Digest;
    // Verify this owner's immutable source key; do not infer ownership from a UUID collision.
    if event_id
        != format!(
            "e-{:x}",
            Sha256::digest(format!("assets:{actor}:{operation}").as_bytes())
        )
    {
        return Ok(None);
    }
    sqlx::query_scalar("SELECT response->'asset'->>'device' FROM mdm_assets.operations WHERE tenant_id=$1::uuid AND actor=$2 AND id=$3 AND response->'asset'->>'kind'='assignment'")
        .bind(tenant).bind(actor).bind(operation).fetch_optional(c).await.map(Option::flatten)
}

/// Current field authority, independent of asset-history pagination.
pub async fn catalog_in(
    tx: &mut PgTransaction<'_>,
    tenant: TenantId,
) -> Result<rss_mdm_inventory::Catalog> {
    tx.with_connection(move |c| {
        Box::pin(async move {
            rss_mdm_inventory_postgres::catalog_in(c, tenant)
                .await
                .map_err(|_| sqlx::Error::Protocol("asset catalog unavailable".into()))
        })
    })
    .await
    .map_err(Into::into)
}
/// Immutable field interpretation for the caller's committed input.
pub async fn catalog_at_in(
    tx: &mut PgTransaction<'_>,
    tenant: TenantId,
    cut: &AssetCut,
) -> Result<rss_mdm_inventory::Catalog> {
    let cut = cut.clone();
    tx.with_connection(move |c| {
        Box::pin(async move {
            rss_mdm_inventory_postgres::catalog_at_in(c, tenant, &cut)
                .await
                .map_err(|_| sqlx::Error::Protocol("asset catalog unavailable".into()))
        })
    })
    .await
    .map_err(Into::into)
}

fn restrict_fields(device: &mut DeviceView, catalog: &rss_mdm_inventory::Catalog) {
    let allowed = |key: &FieldKey| catalog.definition(*key).is_ok_and(fields::visible);
    device.fields.retain(|key, _| allowed(key));
    device.revisions.retain(|key, _| allowed(key));
    for run in &mut device.quality {
        run.fields.retain(|f| allowed(&f.field));
    }
}

impl AssetService {
    pub fn worker_status(&self) -> crate::WorkerStatus {
        self.worker_health
            .lock()
            .expect("worker observation")
            .status(self.task_status.get().map(rss_runtime::TaskStatus::current))
    }
    pub async fn queue_health(
        &self,
        budget: std::time::Duration,
    ) -> std::result::Result<[u64; 5], Error> {
        self.runtime.local_tx(self.tenant,rss_transactional_messaging::policy::OperationDeadline::from_remaining(budget),|tx|Box::pin(async move{
            let t=tx.tenant_id().to_string();
            tx.with_connection(move|c|Box::pin(async move{
                let row:(i64,i64,i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM (SELECT 1 FROM mdm_assets.asset_query_runs WHERE tenant_id=$1::uuid AND NOT completed AND NOT started LIMIT 1001) p),(SELECT count(*) FROM (SELECT 1 FROM mdm_assets.asset_query_runs WHERE tenant_id=$1::uuid AND NOT completed AND started LIMIT 1001) p),(SELECT count(*) FROM (SELECT 1 FROM mdm_assets.asset_query_runs WHERE tenant_id=$1::uuid AND completed AND failure IS NULL LIMIT 1001) p),(SELECT count(*) FROM (SELECT 1 FROM mdm_assets.asset_query_runs WHERE tenant_id=$1::uuid AND failure IS NOT NULL AND failure<>'superseded' LIMIT 1001) p),(SELECT count(*) FROM (SELECT 1 FROM mdm_assets.asset_query_runs WHERE tenant_id=$1::uuid AND failure='superseded' LIMIT 1001) p)").bind(t).fetch_one(c).await?;
                Ok([row.0 as u64,row.1 as u64,row.2 as u64,row.3 as u64,row.4 as u64])
            })).await
        })).await.fold(Ok,|_|Err(Error::Unavailable(Failure::AssetsStorage)),|_|Err(Error::Unavailable(Failure::AssetsStorage)),|_|Err(Error::RollbackFailed),|_|Err(Error::CommitUnknown),|_|Err(Error::Conflict))
    }
}
