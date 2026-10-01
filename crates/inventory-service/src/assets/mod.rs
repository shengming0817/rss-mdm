//! One product asset composition; Inventory resolves facts, Group evaluates conditions.

use crate::operation::Operation;
use crate::transaction::*;
use crate::{Error, Failure};
use rss_contract::Timepoint;
use rss_mdm_audit_integration::RequestAudit;
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::PgTransaction;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use uuid::Uuid;
pub mod channel;
pub mod filter;

mod directory;
mod fields;
mod lists;
mod runs;
pub use fields::{FieldChange, FieldImpact};
mod model;
pub mod planning;
mod quality;
mod query;
mod query_read;
mod query_sort;
mod store;
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
    ) -> Result<Value> {
        let response = match command {
            Command::CollectionItems {
                device,
                run,
                field,
                scope,
                offset,
                limit,
            } => {
                self.collection_items(tx, device, *run, *field, scope, (*offset, *limit))
                    .await?
            }
            Command::ListItems {
                device,
                field,
                scope,
                limit,
                cursor,
            } => {
                self.list_items(tx, device, *field, scope, *limit, cursor.as_deref())
                    .await?
            }
            Command::CollectionRun { device, run, scope } => Response::CollectionRun {
                run: self.collection_run(tx, device, *run, scope).await?,
            },
            Command::FieldWrite { field, change } => self.field_write(tx, *field, change).await?,
            Command::FieldReferences { field } => Response::FieldReferences {
                field: *field,
                impact: self.field_impact(tx, *field).await?,
            },
            Command::Fields => Response::Fields {
                dictionary: rss_mdm_inventory::DICTIONARY.into(),
                fields: catalog_in(tx, self.tenant, i64::MAX)
                    .await?
                    .fields()
                    .map(|f| {
                        let mut v = checked_input(serde_json::to_value(f))?;
                        v["operations"] = checked_input(serde_json::to_value(f.operations()))?;
                        Ok(v)
                    })
                    .collect::<Result<_>>()?,
            },
            Command::Detail { device, scope } => {
                if scope
                    .devices
                    .as_ref()
                    .is_some_and(|ids| !ids.contains(device))
                {
                    return Err(Error::Forbidden.into());
                }
                let watermark = self.list_watermark(tx).await?;
                let restricted = ReadScope {
                    subject: scope.subject.clone(),
                    sensitive: scope.sensitive,
                    devices: Some([device.clone()].into()),
                };
                let mut page = planning::SnapshotReader {
                    tenant: self.tenant,
                }
                .asset_page_in(tx, watermark, None, 1, &restricted)
                .await?;
                let mut view = page.devices.pop().ok_or(Error::NotFound)?;
                self.summarize_lists(&mut view, &page.catalog, scope, watermark)?;
                Response::Detail { device: view }
            }
            Command::Search { request, scope } => {
                if request.expected_revision != 0 {
                    return Err(Error::Malformed.into());
                }
                self.asset_query(tx, request.operation_id, scope, &request.input, at)
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
            Command::SavedList { owner, after } => self.saved_list(tx, owner, *after).await?,
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
                self.asset_query(tx, *operation, scope, &definition.query, at)
                    .await?
            }
        };
        json(&AssetEnvelope {
            tenant_id: self.tenant.to_string(),
            asset: response,
        })
    }
}
#[derive(serde::Serialize, serde::Deserialize)]
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
    tasks: Arc<dyn crate::tasks::Tasks>,
    audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    runtime: Arc<rss_transactional_messaging_postgres::PgRuntime>,
    tenant: TenantId,
    clock: Arc<dyn crate::clock::Clock>,
    asset_cursor_key: ring::hmac::Key,
}
impl AssetService {
    pub fn new(
        audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
        runtime: Arc<rss_transactional_messaging_postgres::PgRuntime>,
        tenant: TenantId,
        clock: Arc<dyn crate::clock::Clock>,
        cursor_key: &[u8],
        tasks: Arc<dyn crate::tasks::Tasks>,
    ) -> Self {
        Self {
            tasks,
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
    ) -> std::result::Result<Value, Error> {
        authorize()?;
        crate::transaction::run(
            &self.audit_store,
            &self.runtime,
            self.tenant,
            audit,
            &(self, command, audit, authorize),
            |ctx, tx| {
                Box::pin(async move {
                    let (service, command, audit, authorize) = *ctx;
                    service.execute_in(tx, command, audit, authorize).await
                })
            },
            crate::transaction::TransactionOwner::Assets,
        )
        .await
    }
    async fn execute_in(
        &self,
        tx: &mut PgTransaction<'_>,
        command: &Command,
        audit: &RequestAudit,
        authorize: &(dyn Fn() -> std::result::Result<(), Error> + Sync),
    ) -> Result<Value> {
        crate::transaction::lock(tx).await?;
        authorize()?;
        let (operation, fingerprint) = operation_identity(command, audit)?;
        if let Some(id) = operation
            && let Some(old) = crate::assets::receipts::replay(tx, audit, id, &fingerprint).await?
        {
            stored(serde_json::from_value::<AssetEnvelope>(old.clone()))?;
            audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);
            crate::assets::receipts::audit(
                tx,
                &self.audit_store,
                audit,
                operation.zip(Some(fingerprint.as_slice())),
                true,
            )
            .await?;
            authorize()?;
            return Ok(old);
        }
        let at = self
            .clock
            .unix_seconds()
            .ok_or(Error::Unavailable(Failure::Clock))?;
        let value = self
            .dispatch(tx, command, checked_input(Timepoint::try_from(at))?)
            .await?;
        stored(serde_json::from_value::<AssetEnvelope>(value.clone()))?;
        if let Some(id) = operation {
            crate::assets::receipts::receipt(tx, audit, id, &fingerprint, &value).await?;
        }
        crate::assets::receipts::audit(
            tx,
            &self.audit_store,
            audit,
            operation.zip(Some(fingerprint.as_slice())),
            false,
        )
        .await?;
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

pub const CATALOG_SQL: &str = include_str!("catalog.sql");
pub const CATALOG_JSON: &str = include_str!("catalog.json");
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

/// Load one authoritative catalog snapshot within the caller's tenant transaction.
pub async fn catalog_in(
    tx: &mut PgTransaction<'_>,
    tenant: TenantId,
    watermark: i64,
) -> Result<rss_mdm_inventory::Catalog> {
    tx.with_connection(move |c| {
        Box::pin(async move {
            rss_mdm_inventory_postgres::catalog_at_in(c, tenant, watermark)
                .await
                .map_err(|_| sqlx::Error::Protocol("asset catalog unavailable".into()))
        })
    })
    .await
    .map_err(Into::into)
}
async fn datasets_in(
    tx: &mut PgTransaction<'_>,
    tenant: TenantId,
) -> Result<BTreeMap<rss_mdm_inventory::Source, Vec<String>>> {
    tx.with_connection(move |c| {
        Box::pin(async move {
            rss_mdm_inventory_postgres::datasets_in(c, tenant)
                .await
                .map_err(|_| sqlx::Error::Protocol("asset datasets unavailable".into()))
        })
    })
    .await
    .map_err(Into::into)
}

fn restrict_fields(device: &mut DeviceView, catalog: &rss_mdm_inventory::Catalog, sensitive: bool) {
    let allowed = |key: &FieldKey| {
        catalog
            .definition(*key)
            .is_ok_and(|f| fields::visible(f, sensitive))
    };
    device.fields.retain(|key, _| allowed(key));
    device.revisions.retain(|key, _| allowed(key));
    for run in &mut device.quality {
        run.fields.retain(|f| allowed(&f.field));
    }
}
