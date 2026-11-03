//! Request-local matching examples. No task, receipt or member publication is created.
//! ref: tokio tokio/src/time/timeout.rs@556820ff84030b37e74e11b86b7733f5795770ea
//! Synchronous evaluation also retains the core work/byte budgets; a timeout alone is insufficient.
use super::*;
use assets::evaluation::EvaluationStep;
use rss_mdm_audit_integration::{AuditIntent, RequestAudit, budget::AuditBudget};
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use rss_mdm_group::{AssetContext, Decision, GroupSource};
use rss_mdm_inventory_service::objects::{ObjectRef, ObjectSnapshot};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, time::Duration};

/// Examples are deliberately not a complete member set or a counted search result.
pub const SAMPLE_LIMIT: usize = 1000;
// These bound one read, not the size/depth of an authored Group graph.
const REFERENCE_CHECKS: usize = 1000;
const SCAN_OBJECTS: usize = 1000;

#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Editing {
    pub group_id: Uuid,
    pub expected_revision: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request {
    pub criteria: criteria::Condition,
    pub asset_context: AssetContext,
    pub editing: Option<Editing>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Response {
    #[schemars(length(max = 1000))]
    pub items: Vec<ObjectRef>,
    /// False also covers a sample/work limit; an empty sample is then inconclusive.
    pub scan_complete: bool,
    pub input_fingerprint: String,
    pub asset_cut: rss_mdm_inventory::AssetCut,
    pub object_snapshot: Option<Uuid>,
    pub sources: Vec<GroupSource>,
    pub as_of: i64,
}

fn work_left(budget: &AuditBudget) -> bool {
    budget.control().total_remaining() > Duration::from_secs(1)
}

impl Groups {
    pub async fn preview(
        &self,
        proof: &AuthorizedPrincipal,
        request: &Request,
        audit: &RequestAudit,
    ) -> std::result::Result<Response, Error> {
        if proof.tenant_id() != self.tenant.to_string()
            || proof.initialization_authority().is_some()
        {
            return Err(Error::Forbidden);
        }
        proof.manage(Permission::GroupRead)?;
        proof.require_all_devices(Permission::InventoryRead)?;
        proof.bind_audit(audit)?;
        audit.set_action("management_read", AuditIntent::Routine);
        let budget = AuditBudget::new(Duration::from_secs(6));
        let candidate = assets::cut::capture(&self.audit_store, self.tenant, &budget).await?;
        let result = inspect_budget(
            &self.runtime,
            self.tenant,
            rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                budget.control().total_remaining(),
            ),
            (self, proof, request, &budget, &candidate),
            |ctx, tx| {
                Box::pin(async move {
                    let (s, proof, request, budget, candidate) = *ctx;
                    let authority = query_authority(tx, proof).await?;
                    authority.require(proof, Permission::GroupRead, None)?;
                    authority.require_all_devices(proof, Permission::InventoryRead)?;
                    group_checked(s.groups.lock_graph_in(tx).await?)?;
                    let snapshot = if request.asset_context == AssetContext::AssociatedDevice {
                        let reader = s.objects.clone();
                        let tenant = s.tenant;
                        Some(
                            tx.with_connection(move |c| {
                                Box::pin(async move { reader.capture(c, tenant, None).await })
                            })
                            .await?,
                        )
                    } else {
                        None
                    };
                    let cut = snapshot.as_ref().map_or(candidate, |s| &s.asset_cut);
                    request.criteria.validate()?;
                    let catalog = assets::catalog_at_in(tx, s.tenant, cut).await?;
                    let rule = criteria::rule(
                        s.tenant,
                        Uuid::new_v4(),
                        &request.criteria.criteria,
                        &catalog,
                    )?;
                    let current_catalog = assets::catalog_in(tx, s.tenant).await?;
                    assets::filter::require_visible_rule(&current_catalog, &rule)?;
                    let mut targets = rule.groups().into_iter().collect::<BTreeSet<_>>();
                    if let Some(editing) = &request.editing {
                        targets.insert(editing.group_id.to_string());
                    }
                    s.lock_group_targets_in(tx, targets).await?;
                    s.preview_owner_in(tx, request).await?;
                    let sources = s.preview_sources_in(tx, request, &rule, budget).await?;
                    let at = checked_input(Timepoint::try_from(
                        s.clock
                            .unix_seconds()
                            .ok_or(Error::Unavailable(Failure::Clock))?,
                    ))?;
                    let (items, scan_complete) = s
                        .preview_matches_in(
                            tx,
                            PreviewInput {
                                request,
                                cut,
                                snapshot: snapshot.as_ref(),
                                rule: &rule,
                                sources: &sources,
                                at,
                                budget,
                            },
                        )
                        .await?;
                    // Current visibility and live authentication remain required even for a fixed cut.
                    let current_catalog = assets::catalog_in(tx, s.tenant).await?;
                    assets::filter::require_visible_rule(&current_catalog, &rule)?;
                    proof.check_live()?;
                    Ok(Response {
                        items,
                        scan_complete,
                        input_fingerprint: checked_input(rss_mdm_query::cursor::fingerprint(
                            request,
                        ))?,
                        asset_cut: cut.clone(),
                        object_snapshot: snapshot.map(|s| s.id),
                        sources,
                        as_of: at.unix_seconds(),
                    })
                })
            },
        )
        .await?;
        proof.check_live()?;
        Ok(result)
    }

    async fn preview_owner_in(&self, tx: &mut PgTransaction<'_>, request: &Request) -> Result<()> {
        if let Some(editing) = &request.editing {
            let id = checked_input(rss_mdm_group::GroupId::parse(&editing.group_id.to_string()))?;
            let group = group_checked(self.groups.lock_reference_target_in(tx, id).await?)?;
            if group.revision.get() as u64 != editing.expected_revision {
                return Err(Error::Conflict.into());
            }
            if group.kind != rss_mdm_group_postgres::GroupKind::Dynamic
                || group.asset_context != request.asset_context
            {
                return Err(Error::Malformed.into());
            }
        }
        Ok(())
    }

    async fn preview_sources_in(
        &self,
        tx: &mut PgTransaction<'_>,
        request: &Request,
        rule: &rss_mdm_group::Rule,
        budget: &AuditBudget,
    ) -> Result<Vec<GroupSource>> {
        let roots = rule
            .groups()
            .iter()
            .map(|id| checked_input(Uuid::parse_str(id)))
            .collect::<Result<BTreeSet<_>>>()?;
        let mut pending = roots.clone();
        let mut visited = BTreeSet::new();
        while let Some(id) = pending.pop_first() {
            if !visited.insert(id) {
                continue;
            }
            if visited.len() > REFERENCE_CHECKS
                || pending.len() > REFERENCE_CHECKS
                || !work_left(budget)
            {
                return Err(Error::Unavailable(Failure::Capacity).into());
            }
            if request.editing.as_ref().is_some_and(|e| e.group_id == id) {
                return Err(Error::Malformed.into());
            }
            // Same existence/context/field checks as the saved-definition walk, without its writes.
            for child in self
                .reference_edges_in(tx, id, request.asset_context)
                .await?
            {
                if !visited.contains(&child) {
                    pending.insert(child);
                }
            }
        }
        let mut sources = Vec::new();
        for id in roots {
            let source = self.capture_group_source_in(tx, id).await?;
            if !self.source_current_in(tx, &source).await? {
                return Err(Error::Conflict.into());
            }
            sources.push(source);
        }
        Ok(sources)
    }

    async fn preview_matches_in(
        &self,
        tx: &mut PgTransaction<'_>,
        input: PreviewInput<'_>,
    ) -> Result<(Vec<ObjectRef>, bool)> {
        let PreviewInput {
            request,
            cut,
            snapshot,
            rule,
            sources,
            at,
            budget,
        } = input;
        let mut items = Vec::new();
        let mut after = None;
        let mut progress = None;
        let mut scanned = 0usize;
        let mut limit = 64;
        let version = snapshot.map_or_else(|| cut.input_version(), ObjectSnapshot::group_input);
        while work_left(budget) && scanned < SCAN_OBJECTS {
            let page = self
                .condition_page_in(
                    tx,
                    crate::input::ConditionPageRequest {
                        cut,
                        snapshot,
                        condition: &request.criteria,
                        rule,
                        after: after.clone(),
                        limit: limit.min(SCAN_OBJECTS - scanned),
                        selected: None,
                        progress: progress.take(),
                    },
                )
                .await;
            let page = match page {
                Err(Fault::Request(Error::Unavailable(
                    Failure::AssetBytesLimit | Failure::AssetSourceLimit,
                ))) if limit > 1 => {
                    limit = 1;
                    continue;
                }
                result => result?,
            };
            let mut facts = match page.evaluation {
                EvaluationStep::Pending(next) => {
                    progress = Some(next);
                    continue;
                }
                EvaluationStep::Ready(facts) => facts,
            };
            match self
                .fill_group_sources_in(tx, sources, &mut facts.objects)
                .await
            {
                Err(Fault::Request(Error::Unavailable(Failure::AssetBytesLimit))) if limit > 1 => {
                    limit = (limit / 2).max(1);
                    continue;
                }
                result => result?,
            }
            let key = after
                .as_ref()
                .map(|s| checked_input(rss_mdm_group::ObjectKey::new(self.tenant, s)))
                .transpose()?;
            let evaluated = rule.evaluate_page(
                &rss_mdm_group::PageInput {
                    tenant: self.tenant,
                    id: if snapshot.is_some() {
                        "objects"
                    } else {
                        "assets"
                    },
                    version: &version,
                    dictionary_version: rss_mdm_inventory::DICTIONARY,
                    coverage: &facts.coverage,
                    objects: &facts.objects,
                    after: key.as_ref(),
                },
                at,
            );
            let evaluated = match evaluated {
                Err(rss_mdm_group::Error::LimitExceeded(_)) if limit > 1 => {
                    limit = 1;
                    continue;
                }
                Err(rss_mdm_group::Error::LimitExceeded(_)) => {
                    return Err(Error::Unavailable(Failure::AssetBytesLimit).into());
                }
                result => stored(result)?,
            };
            after = evaluated
                .objects
                .last()
                .map(|o| o.key.id().to_owned())
                .or(after);
            for object in evaluated.objects {
                if object.decision == Decision::Match {
                    items.push(group_checked(ObjectRef::from_key(
                        request.asset_context,
                        object.key.id(),
                    ))?);
                    if items.len() == SAMPLE_LIMIT {
                        return Ok((items, false));
                    }
                }
            }
            scanned += page.count;
            if !page.more {
                return Ok((items, true));
            }
        }
        Ok((items, false))
    }
}

struct PreviewInput<'a> {
    request: &'a Request,
    cut: &'a rss_mdm_inventory::AssetCut,
    snapshot: Option<&'a ObjectSnapshot>,
    rule: &'a rss_mdm_group::Rule,
    sources: &'a [GroupSource],
    at: Timepoint,
    budget: &'a AuditBudget,
}
