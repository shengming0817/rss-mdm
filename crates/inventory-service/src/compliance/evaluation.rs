use super::*;
use rss_mdm_compliance::{
    Applicability, Assessment, Decision, Explanation, FactReference, FieldEvidence, GroupEvidence,
    Outcome, SourceReference,
};
use rss_mdm_group_postgres as group;
use std::collections::BTreeMap;
impl Compliance {
    pub(super) async fn capture(&self, tx: &mut PgTransaction<'_>, r: &Rule) -> Result<Input> {
        let t = self.tenant();
        let definition: Definition = r.definition.clone();
        let mut groups = Vec::new();
        let mut ids = definition.groups();
        ids.sort();
        for id in ids {
            let gid = stored(group::GroupId::parse(&id.to_string()))?;
            let g = checked(self.groups.lock_reference_target_in(tx, gid).await?)?;
            let set = checked(self.groups.current_member_set_in(tx, gid).await?)?;
            let mut ready = g.kind == group::GroupKind::Static;
            let mut asset_watermark = None;
            if let Some(set) = set {
                let build = checked(self.groups.build_in(tx, set).await?)?;
                let receipt = build
                    .receipt
                    .ok_or(Error::Unavailable(Failure::ComplianceStorage))?;
                if receipt.group.id != gid || receipt.group.member_version != g.member_version {
                    return Err(Error::Unavailable(Failure::ComplianceStorage).into());
                }
                ready = build.request.rule_version == g.rule_version;
                if g.kind == group::GroupKind::Dynamic {
                    let at = build
                        .request
                        .input_version
                        .strip_prefix("assets:")
                        .and_then(|s| s.parse::<i64>().ok())
                        .ok_or(Error::Unavailable(Failure::ComplianceStorage))?;
                    asset_watermark = Some(at);
                    let tenant = t.to_string();
                    let dirty:bool=tx.with_connection(move|c|Box::pin(async move{
      sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm.asset_changes c WHERE c.tenant_id=$1::uuid AND c.revision>$2 AND (c.kind IN('device','registration','source','credential') OR EXISTS(SELECT 1 FROM mdm_assets.group_fields f WHERE f.tenant_id=c.tenant_id AND f.group_id=$3::uuid AND f.field=ANY(c.fields))))")
      .bind(tenant).bind(at).bind(id.to_string()).fetch_one(c).await
     })).await?;
                    ready &= !dirty;
                }
            }
            groups.push(GroupInput {
                id,
                revision: g.revision.get(),
                member_version: g.member_version as i64,
                member_set: set
                    .map(|v| stored(Uuid::parse_str(&v.to_string())))
                    .transpose()?,
                asset_watermark,
                ready,
            });
        }
        let watermark = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    rss_mdm_inventory_postgres::watermark_in(c, t)
                        .await
                        .map_err(|_| sqlx::Error::Protocol("asset watermark".into()))
                })
            })
            .await?;
        Ok(Input {
            rule: r.id,
            revision: r.revision,
            definition,
            watermark,
            evaluated_at: self
                .clock
                .unix_seconds()
                .ok_or(Error::Unavailable(Failure::Clock))?,
            groups,
        })
    }
    pub(super) async fn enqueue(&self, tx: &mut PgTransaction<'_>, r: &Rule) -> Result<Uuid> {
        let input = self.capture(tx, r).await?;
        let task = Uuid::new_v4();
        let t = self.tenant();
        let id = r.id;
        let revision = r.revision;
        self.tasks
            .enqueue(
                tx,
                task,
                &crate::tasks::JobInput::Compliance {
                    input: Box::new(input),
                },
            )
            .await?;
        if !tx
            .with_connection(move |c| {
                Box::pin(async move { pg::desired(c, t, id, revision, task).await })
            })
            .await?
        {
            return Err(Error::Conflict.into());
        }
        Ok(task)
    }
    pub(super) async fn fresh(
        &self,
        tx: &mut PgTransaction<'_>,
        r: &Rule,
        input: &Input,
    ) -> Result<bool> {
        if !r.enabled || r.id != input.rule || r.revision != input.revision {
            return Ok(false);
        }
        Ok(self
            .inputs_current(tx, std::slice::from_ref(input))
            .await?
            .contains(&r.id))
    }
    pub async fn advance(
        &self,
        tx: &mut PgTransaction<'_>,
        task: Uuid,
        input: &Input,
        cursor: Option<String>,
    ) -> Result<()> {
        crate::transaction::lock(tx).await?;
        let r = self.rule(tx, input.rule).await?;
        if r.desired != Some(task) || !self.fresh(tx, &r, input).await? {
            return self.supersede(tx, task, &r).await;
        }
        let page = self
            .asset_reader
            .asset_page_in(
                tx,
                input.watermark,
                cursor.clone(),
                32,
                &crate::assets::ReadScope::all(),
            )
            .await?;
        let facts = crate::assets::filter::page(self.tenant(), &page.devices)?;
        let rule = crate::assets::rule(self.tenant(), input.rule, &input.definition.criteria)?;
        let id = task.to_string();
        let version = format!("assets:{}", input.watermark);
        let after = cursor
            .as_ref()
            .map(|s| stored(group::core::ObjectKey::new(self.tenant(), s.clone())))
            .transpose()?;
        let evaluated = stored(rule.evaluate_page(
            &group::core::PageInput {
                tenant: self.tenant(),
                id: &id,
                version: &version,
                dictionary_version: rss_mdm_inventory::DICTIONARY,
                coverage: &facts.coverage,
                objects: &facts.objects,
                after: after.as_ref(),
            },
            stored(rss_contract::Timepoint::try_from(input.evaluated_at))?,
        ))?;
        let targets = self.group_targets(tx, input, &page.devices, cursor).await?;
        let platforms = self.platforms(tx, input, &page.devices).await?;
        for (device, e) in page.devices.iter().zip(evaluated.objects) {
            let document = assessment(
                input,
                device,
                e,
                targets.get(&device.device).cloned().unwrap_or_default(),
                platforms.get(&device.device).cloned().unwrap_or_default(),
            )?;
            let t = self.tenant();
            let name = device.device.clone();
            tx.with_connection(move |c| {
                Box::pin(async move { pg::result(c, t, task, &name, &document).await })
            })
            .await?;
        }
        if let Some(next) = page.next {
            self.tasks.cursor(tx, task, Some(next)).await?;
            return Ok(());
        }
        // Lock the ingress clock before the final check: a later report linearizes after publication.
        let t = self.tenant();
        tx.with_connection(move |c| {
            Box::pin(async move { rss_mdm_inventory_postgres::lock_watermark_in(c, t).await })
        })
        .await?;
        if !self.fresh(tx, &r, input).await? {
            return Err(Error::Conflict.into());
        }
        let t = self.tenant();
        let id = r.id;
        let revision = r.revision;
        if !tx
            .with_connection(move |c| {
                Box::pin(async move { pg::publish(c, t, id, revision, task).await })
            })
            .await?
        {
            return Err(Error::Conflict.into());
        }
        self.tasks
            .finish(tx, &self.audit_store, task, None)
            .await
            .map_err(Into::into)
    }
}

impl Compliance {
    async fn platforms(
        &self,
        tx: &mut PgTransaction<'_>,
        input: &Input,
        devices: &[crate::assets::DeviceView],
    ) -> Result<BTreeMap<String, Vec<SourceReference>>> {
        let t = self.tenant();
        let ids: Vec<_> = devices.iter().map(|d| d.device.clone()).collect();
        let at = input.watermark;
        let sources = tx
            .with_connection(move |c| {
                Box::pin(
                    async move { crate::device::read::sources_at(c, t.to_string(), ids, at).await },
                )
            })
            .await?;
        let mut platforms: BTreeMap<String, Vec<SourceReference>> = BTreeMap::new();
        for row in sources {
            platforms
                .entry(row.try_get("device")?)
                .or_default()
                .push(SourceReference {
                    source: row.try_get("source")?,
                    registration: row.try_get("registration")?,
                    generation: row.try_get("generation")?,
                    epoch: row.try_get("epoch")?,
                });
        }
        Ok(platforms)
    }
}

fn assessment(
    input: &Input,
    device: &crate::assets::DeviceView,
    e: group::core::ObjectEvaluation,
    groups: Vec<GroupEvidence>,
    sources: Vec<SourceReference>,
) -> Result<Assessment> {
    let condition = match e.decision {
        group::core::Decision::Match => Decision::Match,
        group::core::Decision::NoMatch => Decision::NoMatch,
        group::core::Decision::Unknown => Decision::Unknown,
    };
    let explanations = e
        .explanations
        .into_iter()
        .map(|e| Explanation {
            path: e.path,
            outcome: match e.outcome {
                group::core::Outcome::Match => Outcome::Match,
                group::core::Outcome::NoMatch => Outcome::NoMatch,
                group::core::Outcome::Unknown(r) => match r {
                    group::core::UnknownReason::Null => Outcome::Null,
                    group::core::UnknownReason::Missing => Outcome::Missing,
                    group::core::UnknownReason::Deleted => Outcome::Deleted,
                    group::core::UnknownReason::Unsupported => Outcome::Unsupported,
                    group::core::UnknownReason::Conflict => Outcome::Conflict,
                },
            },
        })
        .collect();
    let evidence = e
        .provenance
        .keys()
        .filter_map(|field| {
            device
                .fields
                .iter()
                .find(|(k, _)| k.as_str() == field)
                .map(|(k, v)| FieldEvidence {
                    field: k.as_str().into(),
                    sources: v
                        .sources
                        .iter()
                        .map(|s| {
                            let e = &s.evidence;
                            FactReference {
                                source: e.source.as_str().into(),
                                registration: e.registration.clone(),
                                registration_generation: e.registration_generation,
                                epoch: e.epoch.clone(),
                                snapshot_id: e.snapshot_id.clone(),
                                observed_at: e.observed_at,
                                received_at: e.received_at,
                                actor: e.actor.clone(),
                            }
                        })
                        .collect(),
                })
        })
        .collect();
    let applicability = Applicability {
        platform: input.definition.platform,
        platform_decision: rss_mdm_compliance::platform_decision(
            input.definition.platform,
            &sources,
        ),
        sources,
        groups,
    };
    stored(Assessment::evaluate(
        input,
        rss_mdm_inventory::DICTIONARY,
        condition,
        applicability,
        explanations,
        evidence,
    ))
}

impl Compliance {
    async fn group_targets(
        &self,
        tx: &mut PgTransaction<'_>,
        input: &Input,
        devices: &[crate::assets::DeviceView],
        cursor: Option<String>,
    ) -> Result<BTreeMap<String, Vec<GroupEvidence>>> {
        let mut targets: BTreeMap<String, Vec<GroupEvidence>> = devices
            .iter()
            .map(|d| {
                (
                    d.device.clone(),
                    input
                        .groups
                        .iter()
                        .map(|g| GroupEvidence {
                            id: g.id,
                            member_set: g.member_set,
                            decision: Decision::NoMatch,
                        })
                        .collect(),
                )
            })
            .collect();
        for (index, g) in input.groups.iter().enumerate() {
            if let Some(set) = g.member_set {
                self.group_target_page(
                    tx,
                    set,
                    cursor.clone(),
                    devices.last().map(|d| d.device.as_str()),
                    index,
                    &mut targets,
                )
                .await?;
            }
        }
        Ok(targets)
    }
    async fn group_target_page(
        &self,
        tx: &mut PgTransaction<'_>,
        set: Uuid,
        mut after: Option<String>,
        last_device: Option<&str>,
        index: usize,
        targets: &mut BTreeMap<String, Vec<GroupEvidence>>,
    ) -> Result<()> {
        loop {
            let records = checked(
                self.groups
                    .build_decisions_in(
                        tx,
                        stored(group::OperationId::parse(&set.to_string()))?,
                        after.clone(),
                        32,
                    )
                    .await?,
            )?;
            let Some(last) = records.last().map(|r| r.device.clone()) else {
                return Ok(());
            };
            if after.as_ref().is_some_and(|a| a >= &last) {
                return Err(Error::Unavailable(Failure::ComplianceStorage).into());
            }
            merge_targets(targets, index, records);
            if last_device.is_none_or(|d| last.as_str() >= d) {
                return Ok(());
            }
            after = Some(last);
        }
    }
}
fn merge_targets(
    targets: &mut BTreeMap<String, Vec<GroupEvidence>>,
    index: usize,
    records: Vec<group::DecisionRecord>,
) {
    for record in records {
        if let Some(target) = targets.get_mut(&record.device) {
            target[index].decision = match record.decision {
                group::DecisionValue::Match => Decision::Match,
                group::DecisionValue::NoMatch => Decision::NoMatch,
                _ => Decision::Unknown,
            };
        }
    }
}

impl Compliance {
    async fn supersede(&self, tx: &mut PgTransaction<'_>, task: Uuid, r: &Rule) -> Result<()> {
        // Do not create an unbounded succession of jobs while Group is still converging.
        if r.desired == Some(task) && r.enabled {
            let next = self.capture(tx, r).await?;
            if next.groups.iter().any(|g| !g.ready) {
                self.tasks
                    .set_detail(
                        tx,
                        task,
                        serde_json::json!({"reason":"group_input_pending"}),
                    )
                    .await?;
                // This frozen input can never become publishable. Group mutation/publication
                // invalidates the rule and wakes the shared dispatcher to create a new run.
                return self
                    .tasks
                    .finish(tx, &self.audit_store, task, Some("superseded"))
                    .await
                    .map_err(Into::into);
            }
            self.enqueue(tx, r).await?;
        }
        return self
            .tasks
            .finish(tx, &self.audit_store, task, Some("superseded"))
            .await
            .map_err(Into::into);
    }
}

#[cfg(test)]
#[path = "../../tests/compliance/evaluation_unit.rs"]
mod tests;
