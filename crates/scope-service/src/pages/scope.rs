use super::*;
use rss_mdm_scope::Reference;
#[derive(schemars::JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScopePage {
    result: Uuid,
    scope: Uuid,
    current: bool,
    channel: rss_mdm_inventory::Channel,
    page: ScopeItems,
    next_cursor: Option<String>,
}
#[derive(schemars::JsonSchema, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum ScopeItems {
    Members { items: Vec<ScopeMember> },
    Decisions { items: Vec<ScopeDecision> },
}
#[derive(schemars::JsonSchema, Serialize, Deserialize)]
struct ScopeMember {
    object: rss_mdm_inventory_service::objects::ObjectRef,
    available: bool,
}
#[derive(schemars::JsonSchema, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum Qualification {
    Eligible { entry: i64 },
    Pending,
    Excluded,
}
#[derive(schemars::JsonSchema, Serialize, Deserialize)]
struct ScopeDecision {
    object: rss_mdm_inventory_service::objects::ObjectRef,
    /// Frozen qualification of this published result; availability is evaluated now.
    qualification: Qualification,
    available: bool,
    reasons: Vec<ScopeReason>,
    targets: Option<Vec<ScopeSource>>,
    limitations: Option<Vec<ScopeSource>>,
    exclusions: Option<Vec<ScopeSource>>,
}
#[derive(schemars::JsonSchema, Serialize, Deserialize)]
struct ScopeSource {
    reference: Reference,
    version: u64,
}
#[derive(schemars::JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ScopeReason {
    ExplicitExclusion,
    MissingLimitationMatch,
    UnknownTarget,
    UnknownLimitation,
    UnknownExclusion,
}
fn sources(refs: &[rss_mdm_scope::SourceRef]) -> transaction::Result<Vec<ScopeSource>> {
    refs.iter()
        .map(|r| {
            Ok(ScopeSource {
                reference: match r.id() {
                    rss_mdm_scope::SourceId::Direct(id) => Reference::Device(id.value().into()),
                    rss_mdm_scope::SourceId::Group(id) => {
                        Reference::Group(stored(Uuid::parse_str(id.value()))?)
                    }
                },
                version: r.version(),
            })
        })
        .collect()
}
impl Scopes {
    pub(super) async fn page_on(
        &self,
        c: &mut sqlx::PgConnection,
        request: &PageRequest,
        authority: &str,
    ) -> transaction::Result<Value> {
        let PageRequest {
            scope,
            result,
            projection: kind,
            query,
        } = request;
        let (scope, result, kind) = (*scope, *result, *kind);
        let head = sqlx::query_as::<_, (i64, Option<Uuid>, bool)>(
            "SELECT revision,resolution,deleted FROM mdm_scope.scopes WHERE tenant_id=$1::uuid AND id=$2"
        ).bind(self.tenant.to_string()).bind(scope).fetch_optional(&mut *c).await?.ok_or(Error::NotFound)?;
        let binding = ResultBinding::Scope {
            scope,
            kind,
            channel: query.channel,
            authority: authority.to_owned(),
            head,
        };
        let after = query
            .page
            .cursor()
            .as_ref()
            .map(|t| {
                decode(
                    &self.cursor_key,
                    t,
                    &self.tenant.to_string(),
                    result,
                    &binding,
                )
            })
            .transpose()?;
        let projection = self.projection.clone();
        let tenant = self.tenant;
        let channel = query.channel;
        let limit = query.page.limit();
        let page = projection
            .result_devices_on(
                c,
                crate::sources::ResultPage {
                    tenant,
                    scope,
                    run: result,
                    channel,
                    after: after.as_deref(),
                    limit,
                },
            )
            .await?;
        if page.result != result {
            return Err(Error::Conflict.into());
        }
        let more = page.devices.len() > limit;
        let current = page.current;
        let devices: Vec<_> = page.devices.into_iter().take(limit).collect();
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
        #[cfg(feature = "integration")]
        self.page_boundary().await;
        let mut items = Vec::new();
        let mut decisions = Vec::new();
        for device in devices {
            let d = projection
                .result_detail_on(
                    c,
                    crate::sources::ResultMember {
                        tenant,
                        scope,
                        run: result,
                        channel,
                        device: &device,
                        objects: self.objects.as_ref(),
                    },
                )
                .await?;
            let object = rss_mdm_inventory_service::objects::ObjectRef::Endpoint(device);
            let qualification = if d.pending {
                Qualification::Pending
            } else if d.matched && d.entry > 0 {
                items.push(ScopeMember {
                    object: object.clone(),
                    available: d.available,
                });
                Qualification::Eligible { entry: d.entry }
            } else {
                Qualification::Excluded
            };
            let explanation = d.explanation;
            let reasons = explanation
                .as_ref()
                .map(|e| {
                    e.reasons
                        .iter()
                        .map(|r| match r {
                            rss_mdm_scope::ExclusionReason::ExplicitExclusion => {
                                ScopeReason::ExplicitExclusion
                            }
                            rss_mdm_scope::ExclusionReason::MissingLimitationMatch => {
                                ScopeReason::MissingLimitationMatch
                            }
                            rss_mdm_scope::ExclusionReason::UnknownTarget => {
                                ScopeReason::UnknownTarget
                            }
                            rss_mdm_scope::ExclusionReason::UnknownLimitation => {
                                ScopeReason::UnknownLimitation
                            }
                            rss_mdm_scope::ExclusionReason::UnknownExclusion => {
                                ScopeReason::UnknownExclusion
                            }
                        })
                        .collect()
                })
                .unwrap_or_default();
            decisions.push(ScopeDecision {
                object,
                qualification,
                available: d.available,
                reasons,
                targets: explanation
                    .as_ref()
                    .map(|e| sources(&e.targets))
                    .transpose()?,
                limitations: explanation
                    .as_ref()
                    .map(|e| sources(&e.limitations))
                    .transpose()?,
                exclusions: explanation
                    .as_ref()
                    .map(|e| sources(&e.exclusions))
                    .transpose()?,
            });
        }
        json(&ScopePage {
            scope,
            result,
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
