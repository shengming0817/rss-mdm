//! Field definitions are tenant configuration; references are checked on the shared configuration transaction.
use super::*;
use rss_mdm_inventory::{FieldDefinition, Sensitivity};
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum FieldChange {
    Put {
        #[schemars(with = "rss_mdm_agent_wire::runtime::FieldDefinition")]
        definition: Box<FieldDefinition>,
    },
    Delete {},
}
impl AssetService {
    pub(super) async fn field_write(
        &self,
        tx: &mut PgTransaction<'_>,
        field: FieldKey,
        change: &Operation<FieldChange>,
    ) -> Result<Response> {
        let tenant = self.tenant;
        tx.with_connection(move |c| {
            Box::pin(async move {
                rss_mdm_inventory_postgres::lock_catalog_write_in(c, tenant)
                    .await
                    .map_err(|_| sqlx::Error::Protocol("field authority fence".into()))
            })
        })
        .await?;
        let catalog = catalog_in(tx, self.tenant).await?;
        let old = catalog.definition(field).ok();
        let expected = change.expected_revision;
        if expected >= i64::MAX as u64 || old.map_or(0, |f| f.version) != expected {
            return Err(Error::Conflict.into());
        }
        let used = self.field_used_in(tx, field).await?;
        let next = match &change.input {
            FieldChange::Put { definition } => {
                checked_input(definition.validate())?;
                if let Some(seed) = rss_mdm_inventory::builtin::fields()
                    .into_iter()
                    .find(|f| f.key == field && rss_mdm_inventory::builtin::protected(field))
                    && (seed.value_type != definition.value_type
                        || seed.nullable != definition.nullable
                        || seed.manual != definition.manual
                        || seed.item_key != definition.item_key
                        || !definition
                            .sources
                            .keys()
                            .all(|s| seed.sources.contains_key(s)))
                {
                    return Err(Error::Conflict.into());
                }

                if definition.key != field || definition.version != expected + 1 {
                    return Err(Error::Malformed.into());
                }
                if let Some(old) = old {
                    // Changing a field's meaning would reinterpret historical values. A new key
                    // is required; reference impact remains visible before any retirement.
                    if !definition.time_series_extends(old)
                        || !definition.value_type.extends(&old.value_type)
                        || old.unit != definition.unit
                        || old.item_key != definition.item_key
                        || old.sensitivity != definition.sensitivity
                    {
                        return Err(Error::Conflict.into());
                    }
                    if used
                        && (!old
                            .sources
                            .keys()
                            .all(|s| definition.sources.contains_key(s))
                            || old.nullable != definition.nullable
                            || old.manual != definition.manual
                            || old.platforms != definition.platforms
                            || old.searchable != definition.searchable)
                    {
                        return Err(Error::Referenced.into());
                    }
                } else if !field.as_str().starts_with("custom.") {
                    return Err(Error::Malformed.into());
                }
                Some(definition.as_ref().clone())
            }
            FieldChange::Delete {} => {
                if old.is_none() || rss_mdm_inventory::builtin::protected(field) {
                    return Err(Error::Conflict.into());
                }
                if used {
                    return Err(Error::Referenced.into());
                }
                None
            }
        };
        let tenant = self.tenant;
        let definition = next.clone();
        let changed = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    let result = match definition {
                        Some(d) => {
                            rss_mdm_inventory_postgres::publish_field_in(c, tenant, expected, &d)
                                .await
                        }
                        None => {
                            rss_mdm_inventory_postgres::retire_field_in(c, tenant, field, expected)
                                .await
                        }
                    };
                    result.map_err(|_| sqlx::Error::Protocol("field publication rejected".into()))
                })
            })
            .await?;
        if !changed {
            return Err(Error::Conflict.into());
        }
        Ok(Response::Field {
            field,
            version: expected + 1,
            definition: next.map(Box::new),
        })
    }
}
/// Ordinary inventory excludes secrets regardless of the caller’s privileges.
pub fn visible(definition: &FieldDefinition) -> bool {
    definition.sensitivity != Sensitivity::Secret
}

/// Actual field directory entry, using the same field contract as signed projections.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FieldView {
    #[serde(flatten)]
    pub definition: rss_mdm_agent_wire::runtime::FieldDefinition,
    pub operations: Vec<rss_mdm_inventory::Operator>,
}
