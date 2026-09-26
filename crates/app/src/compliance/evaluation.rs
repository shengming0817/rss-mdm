use super::*;
use rss_mdm_compliance::{Decision, Status};
use rss_mdm_group_postgres as group;
use std::collections::BTreeMap;
impl Compliance {
    pub(super) async fn capture(&self, tx: &mut PgTransaction<'_>, r: &pg::Rule) -> Result<Input> {
        let t = self.tenant();
        let definition: Definition = stored(serde_json::from_value(r.definition.clone()))?;
        let mut groups = Vec::new();
        let mut ids = definition.groups();
        ids.sort();
        for id in ids {
            let gid = stored(group::GroupId::parse(&id.to_string()))?;
            let g = checked(
                self.planning
                    .groups
                    .lock_reference_target_in(tx, gid)
                    .await?,
            )?;
            let set = checked(self.planning.groups.current_member_set_in(tx, gid).await?)?;
            let mut ready = g.kind == group::GroupKind::Static;
            if let Some(set) = set {
                let build = checked(self.planning.groups.build_in(tx, set).await?)?;
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
                    let tenant = t.to_string();
                    let dirty:bool=tx.with_connection(move|c|Box::pin(async move{
      sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm.asset_changes c WHERE c.tenant_id=$1::uuid AND c.revision>$2 AND (c.kind IN('device','registration','source','credential') OR EXISTS(SELECT 1 FROM mdm_planning.group_fields f WHERE f.tenant_id=c.tenant_id AND f.group_id=$3::uuid AND f.field=ANY(c.fields))))")
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
                .planning
                .clock
                .unix_seconds()
                .map_err(|_| Error::Unavailable(Failure::Clock))?,
            groups,
        })
    }
    pub(super) async fn enqueue(&self, tx: &mut PgTransaction<'_>, r: &pg::Rule) -> Result<Uuid> {
        let input = self.capture(tx, r).await?;
        let task = Uuid::new_v4();
        let t = self.tenant();
        let id = r.id;
        let revision = r.revision;
        crate::automation::jobs::enqueue_job_in(
            tx,
            task,
            &crate::automation::JobInput::Compliance {
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
        r: &pg::Rule,
        input: &Input,
    ) -> Result<bool> {
        if !r.enabled || r.id != input.rule || r.revision != input.revision {
            return Ok(false);
        }
        let now = self.capture(tx, r).await?;
        if json(&now.definition)? != json(&input.definition)? {
            return Err(Error::Unavailable(Failure::ComplianceStorage).into());
        }
        if now.groups.len() != input.groups.len()
            || now.groups.iter().zip(&input.groups).any(|(a, b)| {
                !a.ready
                    || !b.ready
                    || a.id != b.id
                    || a.revision != b.revision
                    || a.member_set != b.member_set
                    || a.member_version != b.member_version
            })
        {
            return Ok(false);
        }
        let t = self.tenant().to_string();
        let at = input.watermark;
        let id = r.id;
        let dirty:bool=tx.with_connection(move|c|Box::pin(async move{
   sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm.asset_changes c WHERE c.tenant_id=$1::uuid AND c.revision>$2 AND (c.kind IN('device','registration','source','credential') OR EXISTS(SELECT 1 FROM mdm_compliance.fields f WHERE f.tenant_id=c.tenant_id AND f.rule_id=$3::uuid AND f.field=ANY(c.fields))))")
    .bind(t).bind(at).bind(id.to_string()).fetch_one(c).await
  })).await?;
        Ok(!dirty)
    }
    pub(crate) async fn advance(
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
            .planning
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
                targets[&device.device],
                platforms.get(&device.device).copied().unwrap_or_default(),
            );
            let t = self.tenant();
            let rule = input.rule;
            let name = device.device.clone();
            let at = input.evaluated_at;
            tx.with_connection(move |c| {
                Box::pin(async move { pg::result(c, t, task, rule, &name, at, &document).await })
            })
            .await?;
        }
        if let Some(next) = page.next {
            let t = self.tenant().to_string();
            tx.with_connection(move|c|Box::pin(async move{sqlx::query("UPDATE mdm_automation.automation_jobs SET cursor=$3 WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(t).bind(task.to_string()).bind(next).execute(c).await?;Ok(())})).await?;
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
        crate::automation::jobs::finish_job_in(tx, &self.planning.audit_store, task, None).await
    }
}

impl Compliance {
    async fn platforms(
        &self,
        tx: &mut PgTransaction<'_>,
        input: &Input,
        devices: &[crate::assets::DeviceView],
    ) -> Result<BTreeMap<String, (bool, bool)>> {
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
        let mut platforms: BTreeMap<String, (bool, bool)> = BTreeMap::new();
        for s in sources {
            let flags = platforms.entry(s.try_get("device")?).or_default();
            match s.try_get::<&str, _>("source")? {
                "mdm.windows" => flags.0 = true,
                "mdm.apple" => flags.1 = true,
                _ => {}
            }
        }

        Ok(platforms)
    }
}

fn assessment(
    input: &Input,
    device: &crate::assets::DeviceView,
    e: group::core::ObjectEvaluation,
    target: Decision,
    platforms: (bool, bool),
) -> Value {
    let mut applicable = target;
    let platform = match input.definition.platform {
        Platform::All => Decision::Match,
        other => match platforms {
            (true, false) => {
                if matches!(other, Platform::Windows) {
                    Decision::Match
                } else {
                    Decision::NoMatch
                }
            }
            (false, true) => {
                if matches!(other, Platform::Macos) {
                    Decision::Match
                } else {
                    Decision::NoMatch
                }
            }
            _ => Decision::Unknown,
        },
    };
    applicable = match (applicable, platform) {
        (Decision::NoMatch, _) | (_, Decision::NoMatch) => Decision::NoMatch,
        (Decision::Unknown, _) | (_, Decision::Unknown) => Decision::Unknown,
        _ => Decision::Match,
    };
    let decision = match e.decision {
        group::core::Decision::Match => Decision::Match,
        group::core::Decision::NoMatch => Decision::NoMatch,
        group::core::Decision::Unknown => Decision::Unknown,
    };
    let status = rss_mdm_compliance::assess(applicable, decision);
    let reasons:Vec<_>=e.explanations.iter().map(|x|json!({"path":x.path,"outcome":match x.outcome{group::core::Outcome::Match=>"match",group::core::Outcome::NoMatch=>"no_match",group::core::Outcome::Unknown(r)=>match r{group::core::UnknownReason::Null=>"null",group::core::UnknownReason::Missing=>"missing",group::core::UnknownReason::Deleted=>"deleted",group::core::UnknownReason::Unsupported=>"unsupported",group::core::UnknownReason::Conflict=>"conflict"}}})).collect();
    let evidence:Vec<_>=e.provenance.keys().filter_map(|field|device.fields.iter().find(|(k,_)|k.as_str()==field).map(|(k,v)|json!({"field":k,"sources":v.sources.iter().map(|s|&s.evidence).collect::<Vec<_>>()}))).collect();
    let reason = match status {
        Status::NotApplicable => "not_applicable",
        Status::Unknown if applicable == Decision::Unknown => "applicability_unknown",
        Status::Unknown => "facts_unknown",
        Status::Compliant => "rule_satisfied",
        Status::NonCompliant => "rule_failed",
    };
    let document = json!({"ruleId":input.rule,"ruleVersion":input.revision,"dictionaryVersion":rss_mdm_inventory::DICTIONARY,"factWatermark":input.watermark,"groups":input.groups,"evaluatedAt":input.evaluated_at,"status":status,"reason":reason,"explanations":reasons,"evidence":evidence});

    document
}

impl Compliance {
    async fn group_targets(
        &self,
        tx: &mut PgTransaction<'_>,
        input: &Input,
        devices: &[crate::assets::DeviceView],
        cursor: Option<String>,
    ) -> Result<BTreeMap<String, Decision>> {
        let mut targets: BTreeMap<String, Decision> = devices
            .iter()
            .map(|d| {
                (
                    d.device.clone(),
                    if matches!(input.definition.target, Target::All) {
                        Decision::Match
                    } else {
                        Decision::NoMatch
                    },
                )
            })
            .collect();

        for set in input.groups.iter().filter_map(|g| g.member_set) {
            self.group_target_page(
                tx,
                set,
                cursor.clone(),
                devices.last().map(|d| d.device.as_str()),
                &mut targets,
            )
            .await?;
        }
        Ok(targets)
    }
    async fn group_target_page(
        &self,
        tx: &mut PgTransaction<'_>,
        set: Uuid,
        mut after: Option<String>,
        last_device: Option<&str>,
        targets: &mut BTreeMap<String, Decision>,
    ) -> Result<()> {
        loop {
            let records = checked(
                self.planning
                    .groups
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
            merge_targets(targets, records);
            if last_device.is_none_or(|d| last.as_str() >= d) {
                return Ok(());
            }
            after = Some(last);
        }
    }
}
fn merge_targets(targets: &mut BTreeMap<String, Decision>, records: Vec<group::DecisionRecord>) {
    for record in records {
        if let Some(target) = targets.get_mut(&record.device) {
            match record.decision {
                group::DecisionValue::Match => *target = Decision::Match,
                group::DecisionValue::NoMatch => {}
                _ if *target != Decision::Match => *target = Decision::Unknown,
                _ => {}
            }
        }
    }
}

impl Compliance {
    async fn supersede(&self, tx: &mut PgTransaction<'_>, task: Uuid, r: &pg::Rule) -> Result<()> {
        // Do not create an unbounded succession of jobs while Group is still converging.
        if r.desired == Some(task) && r.enabled {
            let next = self.capture(tx, r).await?;
            if next.groups.iter().any(|g| !g.ready) {
                return Err(Error::Unavailable(Failure::ComplianceInputPending).into());
            }
            self.enqueue(tx, r).await?;
        }
        return crate::automation::jobs::finish_job_in(
            tx,
            &self.planning.audit_store,
            task,
            Some("superseded"),
        )
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn input() -> Input {
        Input{rule:Uuid::nil(),revision:1,definition:serde_json::from_value(json!({"name":"rule","severity":"high","enabled":true,"platform":"all","target":{"kind":"all"},"criteria":{"kind":"predicate","field":"custom.is_loaner","op":"eq","value":{"kind":"boolean","value":false}}})).unwrap(),watermark:1,evaluated_at:1,groups:vec![]}
    }
    #[test]
    fn unknown_causes_and_absent_platform_are_not_compliance() {
        let mut input = input();
        let tenant = TenantId::parse("11111111-1111-4111-8111-111111111111").unwrap();
        let device = crate::assets::DeviceView {
            device: "device".into(),
            channels: Default::default(),
            fields: Default::default(),
            quality: vec![],
            revisions: Default::default(),
        };
        let mut result = group::core::ObjectEvaluation {
            key: group::core::ObjectKey::new(tenant, "device").unwrap(),
            decision: group::core::Decision::Unknown,
            explanations: vec![],
            provenance: Default::default(),
        };
        for cause in [
            group::core::UnknownReason::Null,
            group::core::UnknownReason::Missing,
            group::core::UnknownReason::Deleted,
            group::core::UnknownReason::Unsupported,
            group::core::UnknownReason::Conflict,
        ] {
            result.explanations = vec![group::core::Explanation {
                path: vec![],
                outcome: group::core::Outcome::Unknown(cause),
            }];
            let value = assessment(
                &input,
                &device,
                result.clone(),
                Decision::Match,
                (false, false),
            );
            assert_eq!(value["status"], "unknown");
            assert_ne!(value["explanations"][0]["outcome"], "match");
        }
        result.decision = group::core::Decision::Match;
        input.definition.platform = Platform::Windows;
        assert_eq!(
            assessment(
                &input,
                &device,
                result.clone(),
                Decision::Match,
                (false, false)
            )["status"],
            "unknown"
        );
        assert_eq!(
            assessment(
                &input,
                &device,
                result.clone(),
                Decision::Match,
                (true, true)
            )["status"],
            "unknown"
        );
        assert_eq!(
            assessment(
                &input,
                &device,
                result.clone(),
                Decision::Match,
                (false, true)
            )["status"],
            "not_applicable"
        );
        assert_eq!(
            assessment(&input, &device, result, Decision::Match, (true, false))["status"],
            "compliant"
        );
    }
    #[test]
    fn rules_have_no_timer_or_legacy_field_surface() {
        let definition = serde_json::to_value(input().definition).unwrap();
        for key in ["graceSeconds", "ttl", "expiresAt", "validUntil"] {
            let mut value = definition.clone();
            value[key] = json!(1);
            assert!(serde_json::from_value::<Definition>(value).is_err());
        }
        let mut value = definition;
        value["criteria"]["value"] = json!({"kind":"string","value":"false"});
        let rule: Definition = serde_json::from_value(value).unwrap();
        assert!(
            rule.validate(
                TenantId::parse("11111111-1111-4111-8111-111111111111").unwrap(),
                Uuid::new_v4()
            )
            .is_err()
        );
    }
}
