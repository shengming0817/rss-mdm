//! One product asset composition; Inventory resolves facts, Group evaluates conditions.
use super::{
    Audit, Error, Failure, Management, Operation, PgTransaction, Result, TenantId, Timepoint, Uuid,
    Value, input, json, stored,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
mod criteria;
mod http;
mod model;
mod query;
mod snapshot;
mod store;
pub(in crate::management) use criteria::{criteria_view, rule};
pub(crate) use http::routes;
pub(crate) use model::*;
fn digest(value: &(impl serde::Serialize + ?Sized)) -> Result<String> {
    Ok(format!(
        "{:x}",
        Sha256::digest(input(serde_json::to_vec(value))?)
    ))
}
impl Management {
    pub(super) async fn asset_dispatch(
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
                let mut filter = scope.clone();
                if filter
                    .devices
                    .as_ref()
                    .is_some_and(|ids| !ids.contains(device))
                {
                    return Err(Error::Forbidden.into());
                }
                filter.devices = Some(BTreeSet::from([device.clone()]));
                let data = self.load_assets(tx, &filter).await?;
                Response::Detail {
                    device: data.into_iter().next().ok_or(Error::NotFound)?,
                }
            }
            Command::Search { query, scope } => self.asset_query(tx, scope, query, at).await?,
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
                owner,
                id,
                scope,
                cursor,
            } => {
                let saved = self.saved_read(tx, owner, *id).await?;
                let mut definition = saved.definition.ok_or(Error::NotFound)?;
                definition.query.cursor = cursor.clone();
                self.asset_query(tx, scope, &definition.query, at).await?
            }
        };
        json(&AssetEnvelope {
            tenant_id: self.tenant.to_string(),
            asset: response,
        })
    }
    pub(super) async fn assets(
        &self,
        tx: &mut PgTransaction<'_>,
        _at: Timepoint,
    ) -> Result<(rss_mdm_group_postgres::core::Snapshot, Value)> {
        let devices = self.load_assets(tx, &ReadScope::all()).await?;
        let snapshot = criteria::snapshot(self.tenant, &devices)?;
        Ok((snapshot, json(&devices)?))
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
