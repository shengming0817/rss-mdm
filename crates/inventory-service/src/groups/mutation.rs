use super::*;
use crate::assets::{criteria_view, rule};
use rss_mdm_group_postgres as pg;
use serde_json::json;
impl Groups {
    pub async fn group_read(&self, tx: &mut PgTransaction<'_>, id: Uuid) -> Result<Value> {
        let id = checked_input(pg::GroupId::parse(&id.to_string()))?;
        let group = group_checked(self.groups.lock_reference_target_in(tx, id).await?)?;
        let member_set = checked(self.groups.current_member_set_in(tx, id).await?)?;
        let criteria = if let Some(version) = &group.rule_version {
            let rule = self
                .groups
                .rule(id, version, deadline())
                .await
                .map_err(|_| Error::Unavailable(Failure::Runtime))?
                .ok_or(Error::Group(GroupMissing::Rule))?;
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
    pub async fn group_change(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        op: &Operation<GroupChange>,
        at: Timepoint,
        flow: &dyn Flow,
    ) -> Result<Value> {
        let group = checked_input(pg::GroupId::parse(&id.to_string()))?;
        let operation = checked_input(pg::OperationId::parse(&op.operation_id.to_string()))?;
        let expected = || {
            checked_input(pg::Revision::new(
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
                    require_device(tx, device).await?;
                }
                return flow
                    .start(
                        tx,
                        GroupStart {
                            id,
                            task: op.operation_id,
                            expected: op.expected_revision,
                            patch: Some(pg::MemberPatch {
                                add: add.clone(),
                                remove: remove.clone(),
                            }),
                            publish: true,
                            automatic: false,
                            at,
                        },
                    )
                    .await
                    .map_err(Into::into);
            }
            GroupChange::Delete => {
                group_checked(self.groups.lock_reference_target_in(tx, group).await?)?;
                flow.assert_unused(tx, id).await?;
                let tenant = self.tenant;
                if tx
                    .with_connection(move |c| {
                        Box::pin(async move {
                            rss_mdm_compliance_postgres::group_used(c, tenant, id).await
                        })
                    })
                    .await?
                {
                    return Err(Error::Conflict.into());
                }
                pg::Command::Delete {
                    group,
                    expected: expected()?,
                }
            }
            GroupChange::Recompute {} => {
                return flow
                    .start(
                        tx,
                        GroupStart {
                            id,
                            task: op.operation_id,
                            expected: op.expected_revision,
                            patch: None,
                            publish: true,
                            automatic: true,
                            at,
                        },
                    )
                    .await
                    .map_err(Into::into);
            }
        };
        let receipt = checked(self.groups.execute_in(tx, operation, at, &command).await?)?;
        crate::compliance::group_changed(tx, id).await?;
        let criteria = match &op.input {
            GroupChange::Create { criteria, .. } => Some(criteria.as_ref()),
            GroupChange::Rule { criteria } => Some(Some(criteria)),
            _ => None,
        };
        let mut response = json(&receipt)?;
        if let Some(criteria) = criteria {
            self.register_fields_in(tx, id, criteria).await?;
            flow.changed(tx, id, receipt.group.revision.get() as u64)
                .await?;
            if criteria.is_some() {
                let task = Uuid::new_v4();
                let accepted = flow
                    .start(
                        tx,
                        GroupStart {
                            id,
                            task,
                            expected: receipt.group.revision.get() as u64,
                            patch: None,
                            publish: true,
                            automatic: true,
                            at,
                        },
                    )
                    .await?;
                response["task"] = accepted["task"].clone();
            }
        }
        Ok(response)
    }
    pub async fn group_preview(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        operation: Uuid,
        revision: u64,
        at: Timepoint,
        flow: &dyn Flow,
    ) -> Result<Value> {
        flow.start(
            tx,
            GroupStart {
                id,
                task: operation,
                expected: revision,
                patch: None,
                publish: false,
                automatic: false,
                at,
            },
        )
        .await
        .map_err(Into::into)
    }
}

impl Groups {
    async fn register_fields_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        criteria: Option<&assets::Criteria>,
    ) -> Result<()> {
        let mut fields = std::collections::BTreeSet::new();
        fn collect(c: &assets::Criteria, out: &mut std::collections::BTreeSet<String>) {
            match c {
                assets::Criteria::Predicate { field, .. } => {
                    out.insert(field.as_str().to_owned());
                }
                assets::Criteria::And { children } | assets::Criteria::Or { children } => {
                    for c in children {
                        collect(c, out);
                    }
                }
            }
        }
        if let Some(criteria) = criteria {
            collect(criteria, &mut fields);
        }
        let tenant = self.tenant.to_string();
        let fields: Vec<_> = fields.into_iter().collect();
        tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("DELETE FROM mdm_assets.group_fields WHERE tenant_id=$1::uuid AND group_id=$2::uuid").bind(&tenant).bind(id.to_string()).execute(&mut *c).await?;
            sqlx::query("INSERT INTO mdm_assets.group_fields SELECT $1::uuid,$2::uuid,f FROM unnest($3::text[]) f").bind(tenant).bind(id.to_string()).bind(fields).execute(c).await?;Ok(())
        })).await?;
        Ok(())
    }
}
