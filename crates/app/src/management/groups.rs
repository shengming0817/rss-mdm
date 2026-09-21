use super::assets::{criteria_view, rule};
use super::*;
use rss_mdm_group_postgres::{self as pg, core as g};
use serde_json::json;
impl Management {
    pub(super) async fn group_read(&self, tx: &mut PgTransaction<'_>, id: Uuid) -> Result<Value> {
        let id = input(pg::GroupId::parse(&id.to_string()))?;
        let group = group_checked(self.groups.lock_reference_target_in(tx, id).await?)?;
        let members = checked(self.groups.members_in(tx, id).await?)?;
        let criteria = if let Some(version) = &group.rule_version {
            let rule = self
                .groups
                .rule(id, version, deadline())
                .await
                .map_err(|_| Error::Unavailable(Failure::Runtime))?
                .ok_or(Error::ManagementNotFound(Missing::Rule))?;
            if rule.view().dictionary_version != rss_mdm_inventory::DICTIONARY {
                return Err(Error::Conflict.into());
            }
            Some(criteria_view(rule.view().criteria)?)
        } else {
            None
        };
        Ok(
            json!({"group":group,"criteria":criteria,"members":members.iter().map(|m|m.id()).collect::<Vec<_>>()}),
        )
    }
    pub(super) async fn group_change(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        op: &Operation<GroupChange>,
        at: Timepoint,
    ) -> Result<Value> {
        let group = input(pg::GroupId::parse(&id.to_string()))?;
        let operation = input(pg::OperationId::parse(&op.operation_id.to_string()))?;
        let expected = || {
            input(pg::Revision::new(
                i64::try_from(op.expected_revision).map_err(|_| Error::Malformed)?,
            ))
        };
        let command = match &op.input {
            GroupChange::Create {
                name,
                description,
                criteria,
            } => {
                if op.expected_revision != 0 {
                    return Err(Error::Conflict.into());
                }
                pg::Command::Create {
                    group,
                    name: name.clone(),
                    description: description.clone(),
                    definition: match criteria {
                        None => pg::Definition::Static,
                        Some(c) => pg::Definition::Dynamic(Box::new(rule(
                            self.tenant,
                            op.operation_id,
                            c,
                        )?)),
                    },
                }
            }
            GroupChange::Edit { name, description } => pg::Command::Edit {
                group,
                expected: expected()?,
                name: name.clone(),
                description: description.clone(),
            },
            GroupChange::Rule { criteria } => pg::Command::SetRule {
                group,
                expected: expected()?,
                rule: rule(self.tenant, op.operation_id, criteria)?,
            },
            GroupChange::Members { add, remove } => {
                if add.len() + remove.len() > 10_000 {
                    return Err(Error::Malformed.into());
                }
                for id in add {
                    storage::device(tx, id).await?;
                }
                for id in remove {
                    input(rss_mdm_scope::DeviceId::new(self.tenant, id))?;
                }
                pg::Command::Members {
                    group,
                    expected: expected()?,
                    add: add.clone(),
                    remove: remove.clone(),
                }
            }
            GroupChange::Delete => {
                group_checked(self.groups.lock_reference_target_in(tx, group).await?)?;
                self.reject_group_reference(tx, id).await?;
                pg::Command::Delete {
                    group,
                    expected: expected()?,
                }
            }
            GroupChange::Recompute { snapshot } => {
                let current =
                    group_checked(self.groups.lock_reference_target_in(tx, group).await?)?;
                let (facts, _) = self.assets(tx, at).await?;
                if &facts.version != snapshot {
                    return Err(Error::Conflict.into());
                }
                let request = pg::RecalculationRequest {
                    id: operation,
                    group,
                    expected: expected()?,
                    rule_version: current.rule_version.ok_or(Error::Conflict)?,
                    trigger: pg::Trigger::Manual,
                    snapshot: facts,
                    as_of: at,
                };
                checked(self.groups.start_recalculation_in(tx, &request).await?)?;
                let run = checked(self.groups.resume_in(tx, operation).await?)?;
                return match run.state {
                    pg::RunState::Completed(receipt) => json(&receipt),
                    _ => Err(Error::Conflict.into()),
                };
            }
        };
        json(&checked(
            self.groups.execute_in(tx, operation, at, &command).await?,
        )?)
    }
    pub(super) async fn group_preview(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        revision: u64,
        at: Timepoint,
    ) -> Result<Value> {
        let group = input(pg::GroupId::parse(&id.to_string()))?;
        let current = group_checked(self.groups.lock_reference_target_in(tx, group).await?)?;
        if current.revision.get() as u64 != revision {
            return Err(Error::Conflict.into());
        }
        let version = current.rule_version.ok_or(Error::Conflict)?;
        // Immutable rule reads can use a separate read transaction; the group lock
        // prevents its selected rule or members changing during this preview.
        let rule = self
            .groups
            .rule(group, &version, deadline())
            .await
            .map_err(|_| Error::Unavailable(Failure::Runtime))?
            .ok_or(Error::ManagementNotFound(Missing::Rule))?;
        if rule.view().dictionary_version != rss_mdm_inventory::DICTIONARY {
            return Err(Error::Conflict.into());
        }
        let (facts, provenance) = self.assets(tx, at).await?;
        let evaluated = input(rule.evaluate(&facts, at))?;
        Ok(
            json!({"revision":revision,"snapshot":facts.version,"members":evaluated.objects.iter().filter(|o|o.decision==g::Decision::Match).map(|o|o.key.id()).collect::<Vec<_>>(),"assets":provenance,"decisions":evaluated.objects.iter().map(|o|json!({"device":o.key.id(),"decision":decision(o.decision),"explanations":o.explanations.iter().map(|e|json!({"path":e.path,"outcome":outcome(e.outcome)})).collect::<Vec<_>>()})).collect::<Vec<_>>()}),
        )
    }
}

fn decision(d: g::Decision) -> &'static str {
    match d {
        g::Decision::Match => "match",
        g::Decision::NoMatch => "no_match",
        g::Decision::Unknown => "unknown",
    }
}
fn outcome(o: g::Outcome) -> Value {
    match o {
        g::Outcome::Match => json!({"kind":"match"}),
        g::Outcome::NoMatch => json!({"kind":"no_match"}),
        g::Outcome::Unknown(r) => {
            json!({"kind":"unknown","reason":match r {g::UnknownReason::Null=>"null",g::UnknownReason::Missing=>"missing",g::UnknownReason::Deleted=>"deleted",g::UnknownReason::Unsupported=>"unsupported",g::UnknownReason::Conflict=>"conflict"}})
        }
    }
}
