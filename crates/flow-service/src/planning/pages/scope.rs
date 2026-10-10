use super::*;
use rss_mdm_execution_service::source_authority::ScopeAdmission;
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScopePage {
    result: Uuid,
    scope: Uuid,
    current: bool,
    channel: rss_mdm_inventory::Channel,
    page: ScopeItems,
    next_cursor: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum ScopeItems {
    Members {
        items: Vec<rss_mdm_inventory_service::objects::ObjectRef>,
    },
    Decisions {
        items: Vec<Value>,
    },
}
impl Planning {
    pub async fn scope_page_in(
        &self,
        tx: &mut PgTransaction<'_>,
        scope: Uuid,
        result: Uuid,
        kind: ScopePageKind,
        query: &PageQuery,
    ) -> Result<Value> {
        if !(1..=1000).contains(&query.limit) {
            return Err(Error::Malformed.into());
        }
        let channel = query.channel;
        let binding = ResultBinding::Scope {
            scope,
            kind,
            channel,
        };
        let after = query
            .cursor
            .as_ref()
            .map(|token| {
                decode(
                    &self.cursor_key,
                    token,
                    &self.tenant.to_string(),
                    result,
                    &binding,
                )
            })
            .transpose()?;
        let tenant = self.tenant;
        let limit = query.limit;
        let page = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    Ok(super::super::targets::result_devices_on(
                        c,
                        tenant,
                        scope,
                        result,
                        channel,
                        after.as_deref(),
                        limit,
                    )
                    .await)
                })
            })
            .await?
            .map_err(|error| match error {
                rss_mdm_execution_service::source_authority::SourceError::Missing => {
                    Error::Planning(super::super::error::PlanningError::Missing(
                        super::super::error::Missing::Scope,
                    ))
                    .into()
                }
                other => Fault::from(rss_mdm_execution_service::Error::from(other)),
            })?;
        if page.result != result {
            return Err(Error::Conflict.into());
        }
        let more = page.devices.len() > query.limit;
        let devices: Vec<_> = page.devices.into_iter().take(query.limit).collect();
        let next_cursor = if more {
            devices
                .last()
                .map(|after| {
                    encode(
                        &self.cursor_key,
                        Cursor {
                            tenant: self.tenant.to_string(),
                            result,
                            binding,
                            after: after.clone(),
                        },
                    )
                })
                .transpose()?
        } else {
            None
        };
        let mut items = Vec::new();
        let mut decisions = Vec::new();
        for device in devices {
            let tenant = self.tenant;
            let key = device.clone();
            let admission = tx
                .with_connection(move |c| {
                    Box::pin(async move {
                        Ok(super::super::targets::result_admission_on(
                            c, tenant, scope, result, channel, &key,
                        )
                        .await)
                    })
                })
                .await?
                .map_err(|error| match error {
                    rss_mdm_execution_service::source_authority::SourceError::Missing => {
                        Error::Planning(super::super::error::PlanningError::Missing(
                            super::super::error::Missing::Scope,
                        ))
                        .into()
                    }
                    other => Fault::from(rss_mdm_execution_service::Error::from(other)),
                })?;
            let object = rss_mdm_inventory_service::objects::ObjectRef::Endpoint(device);
            if matches!(admission, ScopeAdmission::Eligible { .. }) {
                items.push(object.clone());
            }
            let key = match &object {
                rss_mdm_inventory_service::objects::ObjectRef::Endpoint(id) => id.clone(),
                _ => return Err(Error::Conflict.into()),
            };
            let explanation = tx
                .with_connection(move |c| {
                    Box::pin(async move {
                        Ok(super::super::targets::result_explanation_on(
                            c, tenant, scope, result, channel, &key,
                        )
                        .await)
                    })
                })
                .await?
                .map_err(|error| match error {
                    rss_mdm_execution_service::source_authority::SourceError::Missing => {
                        Error::Planning(super::super::error::PlanningError::Missing(
                            super::super::error::Missing::Scope,
                        ))
                        .into()
                    }
                    other => Fault::from(rss_mdm_execution_service::Error::from(other)),
                })?;
            let reasons = explanation
                .as_ref()
                .map(|e| {
                    e.reasons
                        .iter()
                        .map(|r| match r {
                            rss_mdm_scope::ExclusionReason::ExplicitExclusion => {
                                "explicit_exclusion"
                            }
                            rss_mdm_scope::ExclusionReason::MissingLimitationMatch => {
                                "missing_limitation_match"
                            }
                            rss_mdm_scope::ExclusionReason::UnknownTarget => "unknown_target",
                            rss_mdm_scope::ExclusionReason::UnknownLimitation => {
                                "unknown_limitation"
                            }
                            rss_mdm_scope::ExclusionReason::UnknownExclusion => "unknown_exclusion",
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let sources = |refs: &[rss_mdm_scope::SourceRef]| {
                refs.iter()
                    .map(|r| {
                        let reference = match r.id() {
                            rss_mdm_scope::SourceId::Direct(id) => {
                                Reference::Device(id.value().into())
                            }
                            rss_mdm_scope::SourceId::Group(id) => {
                                Reference::Group(Uuid::parse_str(id.value()).unwrap())
                            }
                        };
                        serde_json::json!({"reference":reference,"version":r.version()})
                    })
                    .collect::<Vec<_>>()
            };
            decisions.push(serde_json::json!({"object":object,"qualification":admission,"reasons":reasons,"targets":explanation.as_ref().map(|e|sources(&e.targets)),"limitations":explanation.as_ref().map(|e|sources(&e.limitations)),"exclusions":explanation.as_ref().map(|e|sources(&e.exclusions))}));
        }
        let tenant = self.tenant.to_string();
        let current=tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar::<_,bool>("SELECT NOT deleted AND resolution=$3 FROM mdm_planning.scopes WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(scope).bind(result).fetch_one(c).await})).await?;
        json(&ScopePage {
            result,
            scope,
            current,
            channel,
            page: if kind == ScopePageKind::Members {
                ScopeItems::Members { items }
            } else {
                ScopeItems::Decisions { items: decisions }
            },
            next_cursor,
        })
    }
}
