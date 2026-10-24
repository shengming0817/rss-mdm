use super::criteria::rule;
use super::*;
use rss_mdm_group_postgres as pg;
use serde_json::json;
impl Groups {
    pub async fn group_read(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        flow: &dyn Flow,
    ) -> Result<Value> {
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
            Some(super::condition_in(tx, self.tenant, id, version, &rule).await?)
        } else {
            None
        };
        Ok(
            json!({"group":group,"criteria":criteria,"member_set":member_set.map(|id|id.to_string()),"freshness":if flow.current(tx,checked_input(Uuid::parse_str(&id.to_string()))?).await? {references::Freshness::Current}else{references::Freshness::Pending}}),
        )
    }
    pub async fn group_change(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        op: &Operation<GroupChange>,
        context: (Timepoint, bool),
        flow: &dyn Flow,
    ) -> Result<Value> {
        let (at, sensitive) = context;
        let group = checked_input(pg::GroupId::parse(&id.to_string()))?;
        let operation = checked_input(pg::OperationId::parse(&op.operation_id.to_string()))?;
        let expected = || {
            checked_input(pg::Revision::new(
                i64::try_from(op.expected_revision).map_err(|_| Error::Malformed)?,
            ))
        };
        let catalog = crate::assets::catalog_in(tx, self.tenant, i64::MAX).await?;
        match &op.input {
            GroupChange::Create {
                criteria: Some(c), ..
            }
            | GroupChange::Rule { criteria: c } => {
                c.validate()?;
                assets::filter::require_visible_rule(
                    &catalog,
                    &rule(self.tenant, op.operation_id, &c.criteria, &catalog)?,
                    sensitive,
                )?
            }
            _ => (),
        }
        let references = match &op.input {
            GroupChange::Create {
                criteria: Some(c),
                asset_context,
                ..
            } => {
                self.validate_references_in(
                    tx,
                    id,
                    *asset_context,
                    &rule(self.tenant, op.operation_id, &c.criteria, &catalog)?,
                    sensitive,
                )
                .await?
            }
            GroupChange::Rule { criteria: c } => {
                let context =
                    group_checked(self.groups.lock_reference_target_in(tx, group).await?)?
                        .asset_context;
                self.validate_references_in(
                    tx,
                    id,
                    context,
                    &rule(self.tenant, op.operation_id, &c.criteria, &catalog)?,
                    sensitive,
                )
                .await?
            }
            _ => vec![],
        };
        let command = match &op.input {
            GroupChange::CreateSystem {
                presentation,
                selector,
            } => {
                if op.expected_revision != 0 {
                    return Err(Error::Conflict.into());
                }
                pg::Command::Create {
                    group,
                    presentation: presentation.clone(),
                    asset_context: pg::AssetContext::Endpoint,
                    definition: pg::Definition::System(*selector),
                }
            }
            GroupChange::Create {
                presentation,
                criteria,
                asset_context,
            } => {
                if op.expected_revision != 0 {
                    return Err(Error::Conflict.into());
                }
                pg::Command::Create {
                    group,
                    presentation: presentation.clone(),
                    asset_context: *asset_context,
                    definition: match criteria {
                        None => pg::Definition::Static,
                        Some(c) => pg::Definition::Dynamic(Box::new(rule(
                            self.tenant,
                            op.operation_id,
                            &c.criteria,
                            &catalog,
                        )?)),
                    },
                }
            }
            GroupChange::Edit { presentation } => pg::Command::Edit {
                group,
                expected: expected()?,
                presentation: presentation.clone(),
            },
            GroupChange::Rule { criteria } => pg::Command::SetRule {
                group,
                expected: expected()?,
                rule: rule(self.tenant, op.operation_id, &criteria.criteria, &catalog)?,
            },
            GroupChange::Members { add, remove } => {
                if add.len() + remove.len() > 1000 {
                    return Err(Error::Malformed.into());
                }
                let endpoints = |objects: &[crate::objects::ObjectRef]| -> Result<Vec<String>> {
                    objects
                        .iter()
                        .map(|object| match object {
                            crate::objects::ObjectRef::Endpoint(id) if !id.is_empty() => {
                                Ok(id.clone())
                            }
                            _ => Err(Error::Malformed.into()),
                        })
                        .collect()
                };
                let add = endpoints(add)?;
                let remove = endpoints(remove)?;
                for device in &add {
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
                if dependencies::used_in(tx, id).await? {
                    return Err(Error::Conflict.into());
                }
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
        crate::compliance::group_changed(&self.reconcile_messaging, tx, id).await?;
        if matches!(op.input, GroupChange::Delete) {
            self.register_fields_in(tx, id, None).await?;
        }
        let criteria = match &op.input {
            GroupChange::Create { criteria, .. } => Some(criteria.as_ref()),
            GroupChange::Rule { criteria } => Some(Some(criteria)),
            _ => None,
        };
        let mut response = json(&receipt)?;
        if matches!(op.input, GroupChange::CreateSystem { .. }) {
            flow.changed(tx, id, receipt.group.revision.get() as u64)
                .await?;
            let accepted = flow
                .start(
                    tx,
                    GroupStart {
                        id,
                        task: Uuid::new_v4(),
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
        if let Some(criteria) = criteria {
            self.register_fields_in(tx, id, criteria.map(|c| &c.criteria))
                .await?;
            if let Some(condition) = criteria {
                let version = receipt
                    .group
                    .rule_version
                    .as_ref()
                    .ok_or(Error::Conflict)?
                    .clone();
                let selection = checked_input(serde_json::to_string(&(
                    condition.selector.clone(),
                    condition.quantifier,
                )))?;
                let tenant = self.tenant.to_string();
                tx.with_connection(move |c| Box::pin(async move {
                    sqlx::query("INSERT INTO mdm_assets.group_selections(tenant_id,group_id,rule_version,selection,group_ids) VALUES($1::uuid,$2,$3,$4::jsonb,$5) ON CONFLICT DO NOTHING")
                        .bind(tenant).bind(id).bind(version).bind(selection).bind(references).execute(c).await?; Ok(())
                })).await?;
            }
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
        criteria: Option<&criteria::Criteria>,
    ) -> Result<()> {
        let mut fields = std::collections::BTreeSet::new();
        let catalog = assets::catalog_in(tx, self.tenant, i64::MAX).await?;
        if let Some(criteria) = criteria {
            fields.extend(
                rule(self.tenant, id, criteria, &catalog)?
                    .view()
                    .fields
                    .keys()
                    .cloned(),
            );
        }
        let catalog = assets::catalog_in(tx, self.tenant, i64::MAX).await?;
        let fields = fields
            .into_iter()
            .map(|name| {
                let key = checked_input(assets::FieldKey::parse(&name))?;
                Ok(checked_input(catalog.path(key))?
                    .root
                    .key
                    .as_str()
                    .to_owned())
            })
            .collect::<Result<std::collections::BTreeSet<_>>>()?;
        let tenant = self.tenant.to_string();
        let fields: Vec<_> = fields.into_iter().collect();
        tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("DELETE FROM mdm_assets.group_fields WHERE tenant_id=$1::uuid AND group_id=$2::uuid").bind(&tenant).bind(id.to_string()).execute(&mut *c).await?;
            sqlx::query("INSERT INTO mdm_assets.group_fields SELECT $1::uuid,$2::uuid,f FROM unnest($3::text[]) f").bind(tenant).bind(id.to_string()).bind(fields).execute(c).await?;Ok(())
        })).await?;
        Ok(())
    }
}
