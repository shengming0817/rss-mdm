//! One product asset composition; Inventory resolves facts, Group evaluates conditions.
pub(crate) mod collection;
use crate::mutation::Operation;
use crate::mutation::*;
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
pub(crate) mod criteria;
pub(crate) mod http;
mod model;
mod quality;
mod query;
mod query_read;
mod query_sort;
pub(crate) mod snapshot;
mod store;
pub(crate) use criteria::{criteria_view, rule};
pub(crate) use http::routes;
pub(crate) use model::*;
fn digest(value: &(impl serde::Serialize + ?Sized)) -> Result<String> {
    Ok(format!(
        "{:x}",
        Sha256::digest(input(serde_json::to_vec(value))?)
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
            Command::Fields => Response::Fields {
                dictionary: rss_mdm_inventory::DICTIONARY.into(),
                fields: FieldKey::ALL
                    .into_iter()
                    .map(|f| input(serde_json::to_value(f.definition())))
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
                Response::Detail {
                    device: self.asset_detail_in(tx, device).await?,
                }
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
pub(super) struct AssetEnvelope {
    pub tenant_id: String,
    pub asset: Response,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn persisted_asset_fingerprint_keeps_its_original_encoding() {
        let audit = RequestAudit::new(
            "11111111-1111-4111-8111-111111111111".into(),
            "management_write",
        );
        audit.set_principal("operator", "mdm");
        let id = Uuid::parse_str("22222222-2222-4222-8222-222222222222").unwrap();
        let command = Command::Search {
            request: Operation {
                operation_id: id,
                expected_revision: 0,
                input: Query::default(),
            },
            scope: ReadScope {
                subject: "operator".into(),
                devices: None,
            },
        };
        let original=br#"["11111111-1111-4111-8111-111111111111","operator","mdm",{"kind":"Asset","command":{"kind":"search","request":{"operationId":"22222222-2222-4222-8222-222222222222","expectedRevision":0,"input":{"criteria":null,"select":[],"sort":null}},"scope":{"subject":"operator","devices":null}}}]"#;
        let (operation, digest) = operation_identity(&command, &audit).unwrap();
        assert_eq!(operation, Some(id));
        assert_eq!(digest, Sha256::digest(original).to_vec());
        audit.finalize(None);
    }
    #[test]
    fn closed_manual_and_query_wire_rejects_legacy_deadlines() {
        for input in [
            serde_json::json!({"action":"delete","ttl":1}),
            serde_json::json!({"action":"null","validUntil":1}),
            serde_json::json!({"action":"set","value":{"kind":"integer","value":3},"expiresAt":1}),
        ] {
            assert!(serde_json::from_value::<ManualChange>(input).is_err());
        }
        assert!(serde_json::from_value::<Query>(serde_json::json!({"validUntil":1})).is_err());
        assert!(
            serde_json::from_value::<Criteria>(
                serde_json::json!({"kind":"eq","field":"device.model","value":"old"})
            )
            .is_err()
        );
    }
    #[test]
    fn one_typed_condition_round_trips_through_the_existing_group_core() {
        let tenant = TenantId::parse("11111111-1111-4111-8111-111111111111").unwrap();
        let c = Criteria::Predicate {
            field: FieldKey::OfficeFloor,
            op: Operator::Ge,
            value: Some(Scalar::Integer(3)),
            values: None,
        };
        let r = rule(tenant, Uuid::new_v4(), &c).unwrap();
        assert_eq!(
            serde_json::to_value(&c).unwrap(),
            serde_json::to_value(criteria_view(r.view().criteria).unwrap()).unwrap()
        );
        let invalid = Criteria::Predicate {
            field: FieldKey::OfficeFloor,
            op: Operator::Eq,
            value: Some(Scalar::String("3".into())),
            values: None,
        };
        assert!(rule(tenant, Uuid::new_v4(), &invalid).is_err());
    }
}

/// Asset algorithms and resources, independently constructible from planning workflows.
pub(crate) struct AssetService {
    audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    runtime: Arc<rss_transactional_messaging_postgres::PgRuntime>,
    tenant: TenantId,
    clock: Arc<dyn crate::clock::Clock>,
    asset_cursor_key: ring::hmac::Key,
}
impl AssetService {
    pub(crate) fn new(
        audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
        runtime: Arc<rss_transactional_messaging_postgres::PgRuntime>,
        tenant: TenantId,
        clock: Arc<dyn crate::clock::Clock>,
        cursor_key: &[u8],
    ) -> Self {
        Self {
            audit_store,
            runtime,
            tenant,
            clock,
            asset_cursor_key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, cursor_key),
        }
    }
    pub(crate) async fn execute(
        &self,
        command: &Command,
        audit: &RequestAudit,
        authorize: &(dyn Fn() -> std::result::Result<(), Error> + Sync),
    ) -> std::result::Result<Value, Error> {
        authorize()?;
        crate::mutation::run(
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
        crate::mutation::lock(tx).await?;
        authorize()?;
        let (operation, fingerprint) = operation_identity(command, audit)?;
        if let Some(id) = operation
            && let Some(old) = crate::mutation::replay(tx, id, &fingerprint).await?
        {
            stored(serde_json::from_value::<AssetEnvelope>(old.clone()))?;
            audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);
            crate::mutation::audit(
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
            .map_err(|_| Error::Unavailable(Failure::Clock))?;
        let value = self
            .dispatch(tx, command, input(Timepoint::try_from(at))?)
            .await?;
        stored(serde_json::from_value::<AssetEnvelope>(value.clone()))?;
        if let Some(id) = operation {
            crate::mutation::receipt(tx, id, &fingerprint, &value).await?;
        }
        crate::mutation::audit(
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
    let bytes = input(serde_json::to_vec(&(
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

#[derive(Clone, Debug, thiserror::Error)]
pub(crate) enum AssetError {
    #[error("operation requires the full authorized inventory scope")]
    RestrictedScope,
}

pub(crate) const ASSETS_MIGRATION_SQL: &str = include_str!("../../migrations/0011_assets.sql");
