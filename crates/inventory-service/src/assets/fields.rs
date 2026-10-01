//! Field definitions are tenant configuration; references are checked on the shared configuration transaction.
use super::*;
use rss_mdm_inventory::{FieldDefinition, Sensitivity};
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum FieldChange {
    Put { definition: Box<FieldDefinition> },
    Delete {},
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FieldImpact {
    pub groups: i64,
    pub templates: i64,
    pub compliance: i64,
    pub saved_queries: i64,
}
impl FieldImpact {
    fn used(&self) -> bool {
        self.groups > 0 || self.templates > 0 || self.compliance > 0 || self.saved_queries > 0
    }
}
impl AssetService {
    pub(super) async fn field_impact(
        &self,
        tx: &mut PgTransaction<'_>,
        field: FieldKey,
    ) -> Result<FieldImpact> {
        let tenant = self.tenant;
        let key = field.as_str().to_owned();
        let (groups,compliance,saved_queries)=tx.with_connection(move|c|Box::pin(async move {
            let groups=sqlx::query_scalar("SELECT count(*) FROM mdm_assets.group_fields WHERE tenant_id=$1::uuid AND field=$2").bind(tenant.to_string()).bind(&key).fetch_one(&mut *c).await?;
            let compliance=rss_mdm_compliance_postgres::field_references_in(c,tenant,&key).await?;
            let saved_queries=sqlx::query_scalar("SELECT count(*) FROM mdm_assets.saved_queries WHERE tenant_id=$1::uuid AND document IS NOT NULL AND (jsonb_path_exists(document,'$.query.**.field ? (@ == $field || @ starts with $prefix)',jsonb_build_object('field',$2::text,'prefix',$2::text||'.')) OR jsonb_path_exists(document,'$.query.select[*] ? (@ == $field)',jsonb_build_object('field',$2::text)))").bind(tenant.to_string()).bind(key).fetch_one(c).await?;
            Ok((groups,compliance,saved_queries))
        })).await?;
        let templates = rss_mdm_resource_postgres::field_references_in(tx, field.as_str()).await?;
        Ok(FieldImpact {
            groups,
            templates,
            compliance,
            saved_queries,
        })
    }
    pub(super) async fn field_write(
        &self,
        tx: &mut PgTransaction<'_>,
        field: FieldKey,
        change: &Operation<FieldChange>,
    ) -> Result<Response> {
        let catalog = catalog_in(tx, self.tenant, i64::MAX).await?;
        let old = catalog.definition(field).ok();
        let expected = change.expected_revision;
        if expected >= i64::MAX as u64 || old.map_or(0, |f| f.version) != expected {
            return Err(Error::Conflict.into());
        }
        let impact = self.field_impact(tx, field).await?;
        let next = match &change.input {
            FieldChange::Put { definition } => {
                checked_input(definition.validate())?;
                if let Some(seed) = rss_mdm_inventory::builtin::fields()
                    .into_iter()
                    .find(|f| f.key == field)
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
                    if old.value_type != definition.value_type
                        || old.unit != definition.unit
                        || old.item_key != definition.item_key
                        || old.sensitivity != definition.sensitivity
                    {
                        return Err(Error::Conflict.into());
                    }
                    if impact.used()
                        && (old.nullable != definition.nullable
                            || old.manual != definition.manual
                            || old.platforms != definition.platforms
                            || old.searchable != definition.searchable)
                    {
                        return Err(Error::Conflict.into());
                    }
                } else if !field.as_str().starts_with("custom.") {
                    return Err(Error::Malformed.into());
                }
                Some(definition.as_ref().clone())
            }
            FieldChange::Delete {} => {
                if old.is_none()
                    || impact.used()
                    || rss_mdm_inventory::builtin::fields()
                        .iter()
                        .any(|f| f.key == field)
                {
                    return Err(Error::Conflict.into());
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
            definition: next,
        })
    }
}
/// Only explicit grants can expose sensitive raw fields or accept conditions using them.
pub fn visible(definition: &FieldDefinition, sensitive: bool) -> bool {
    sensitive || definition.sensitivity == Sensitivity::Standard
}
