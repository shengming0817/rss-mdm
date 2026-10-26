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
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FieldImpact {
    pub groups: i64,
    pub templates: i64,
    pub telemetry_profiles: i64,
    pub archived_resource_versions: i64,
    pub compliance: i64,
    pub saved_queries: i64,
}
impl FieldImpact {
    fn used(&self) -> bool {
        self.groups > 0
            || self.templates > 0
            || self.telemetry_profiles > 0
            || self.compliance > 0
            || self.saved_queries > 0
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
            let saved_queries=sqlx::query_scalar("SELECT count(*) FROM mdm_assets.saved_queries WHERE tenant_id=$1::uuid AND document IS NOT NULL AND (jsonb_path_exists(document,'$.query.**.field ? (@ == $field || @ starts with $prefix)',jsonb_build_object('field',$2::text,'prefix',$2::text||'.')) OR jsonb_path_exists(document,'$.query.fields[*] ? (@ == $field)',jsonb_build_object('field',$2::text)))").bind(tenant.to_string()).bind(key).fetch_one(c).await?;
            Ok((groups,compliance,saved_queries))
        })).await?;
        let (templates, telemetry_profiles, archived_resource_versions) =
            rss_mdm_resource_postgres::field_reference_details_in(tx, field.as_str()).await?;
        Ok(FieldImpact {
            groups,
            templates,
            telemetry_profiles,
            archived_resource_versions,
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
                    if impact.used()
                        && (!old
                            .sources
                            .keys()
                            .all(|s| definition.sources.contains_key(s))
                            || old.nullable != definition.nullable
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
                if old.is_none() || impact.used() || rss_mdm_inventory::builtin::protected(field) {
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

/// Bounded continuation for the existing field-reference endpoint.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FieldReferenceQuery {
    #[serde(skip_deserializing)]
    #[schemars(skip)]
    pub authority: String,
    #[serde(default = "reference_limit")]
    #[schemars(extend("minimum" = 1, "maximum" = 128))]
    pub limit: u16,
    pub cursor: Option<String>,
}
fn reference_limit() -> u16 {
    64
}
/// Exact resource coordinates; presence is configuration, not an execution/readiness assertion.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FieldMappingReference {
    pub resource: String,
    pub version: String,
    pub state: String,
    pub telemetry: bool,
}
impl AssetService {
    pub(super) async fn field_mapping_references(
        &self,
        tx: &mut PgTransaction<'_>,
        field: FieldKey,
        query: &FieldReferenceQuery,
    ) -> Result<rss_mdm_query::Page<FieldMappingReference>> {
        if !(1..=1000).contains(&query.limit) {
            return Err(Error::Malformed.into());
        }
        let codec = rss_mdm_query::cursor::CursorCodec::from_key(self.asset_cursor_key.clone());
        let context = checked_input(rss_mdm_query::cursor::fingerprint(&(
            "field-mapping-references-v1",
            self.tenant.to_string(),
            field,
            &query.authority,
        )))?;
        let after: Option<(String, String)> = query
            .cursor
            .as_ref()
            .map(|cursor| {
                let token = checked_input(rss_contract::PageCursor::parse(cursor))?;
                checked_input(codec.decode(&token, &context))
            })
            .transpose()?;
        let mut rows = rss_mdm_resource_postgres::field_mapping_references_in(
            tx,
            field.as_str(),
            after,
            query.limit + 1,
        )
        .await?;
        let more = rows.len() > usize::from(query.limit);
        rows.truncate(usize::from(query.limit));
        let next = if more {
            let (owner, version, _, _) = rows.last().ok_or(Error::Malformed)?;
            Some(
                checked_input(codec.encode(&context, &(owner, version)))?
                    .as_str()
                    .to_owned(),
            )
        } else {
            None
        };
        let mut items = Vec::new();
        for (resource, version, telemetry, state) in rows {
            let state = match state {
                rss_mdm_resource::State::Frozen => "frozen",
                rss_mdm_resource::State::Active => "active",
                rss_mdm_resource::State::Deprecated => "deprecated",
                rss_mdm_resource::State::Archived => "archived",
            }
            .into();
            items.push(FieldMappingReference {
                resource,
                version,
                state,
                telemetry,
            });
        }
        Ok(rss_mdm_query::Page {
            items,
            next_cursor: next,
        })
    }
}
