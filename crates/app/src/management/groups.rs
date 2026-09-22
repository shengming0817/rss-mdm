use super::assets::{criteria_view, rule};
use super::*;
use rss_mdm_group_postgres as pg;
use serde_json::json;
impl Management {
    pub(super) async fn group_read(&self, tx: &mut PgTransaction<'_>, id: Uuid) -> Result<Value> {
        let id = input(pg::GroupId::parse(&id.to_string()))?;
        let group = group_checked(self.groups.lock_reference_target_in(tx, id).await?)?;
        let member_set = checked(self.groups.current_member_set_in(tx, id).await?)?;
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
            json!({"group":group,"criteria":criteria,"member_set":member_set.map(|id|id.to_string())}),
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
                if add.len() + remove.len() > 1000 {
                    return Err(Error::Malformed.into());
                }
                for device in add {
                    storage::device(tx, device).await?;
                }
                return self
                    .start_group_job_in(
                        tx,
                        id,
                        op.operation_id,
                        op.expected_revision,
                        Some(pg::MemberPatch {
                            add: add.clone(),
                            remove: remove.clone(),
                        }),
                        true,
                        false,
                        at,
                    )
                    .await;
            }
            GroupChange::Delete => {
                group_checked(self.groups.lock_reference_target_in(tx, group).await?)?;
                self.reject_group_reference(tx, id).await?;
                pg::Command::Delete {
                    group,
                    expected: expected()?,
                }
            }
            GroupChange::Recompute => {
                return self
                    .start_group_job_in(
                        tx,
                        id,
                        op.operation_id,
                        op.expected_revision,
                        None,
                        true,
                        false,
                        at,
                    )
                    .await;
            }
        };
        let receipt = checked(self.groups.execute_in(tx, operation, at, &command).await?)?;
        let criteria = match &op.input {
            GroupChange::Create { criteria, .. } => Some(criteria.as_ref()),
            GroupChange::Rule { criteria } => Some(Some(criteria)),
            _ => None,
        };
        let mut response = json(&receipt)?;
        if let Some(criteria) = criteria {
            self.register_group_inputs_in(tx, id, receipt.group.revision.get() as u64, criteria)
                .await?;
            if criteria.is_some() {
                let task = Uuid::new_v4();
                self.start_group_job_in(
                    tx,
                    id,
                    task,
                    receipt.group.revision.get() as u64,
                    None,
                    true,
                    true,
                    at,
                )
                .await?;
                response["task"] = serde_json::json!(task);
            }
        }
        Ok(response)
    }
    pub(super) async fn group_preview(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        operation: Uuid,
        revision: u64,
        at: Timepoint,
    ) -> Result<Value> {
        self.start_group_job_in(tx, id, operation, revision, None, false, false, at)
            .await
    }
}
