use super::criteria::rule;
use super::*;
use rss_mdm_group_postgres as pg;
use serde_json::json;
impl Groups {
    pub async fn group_read(&self, tx: &mut PgTransaction<'_>, id: Uuid) -> Result<Value> {
        let id = checked_input(rss_mdm_group::GroupId::parse(&id.to_string()))?;
        let group = group_checked(self.groups.get_in(tx, id).await?)?
            .filter(|g| !g.deleted)
            .ok_or(Error::Group(GroupMissing::Group))?;
        let member_set = checked(self.groups.current_member_set_in(tx, id).await?)?;
        let criteria = if let Some(version) = &group.rule_version {
            let rule = group_checked(self.groups.rule_in(tx, id, version).await?)?
                .ok_or(Error::Group(GroupMissing::Rule))?;
            if rule.view().dictionary_version != rss_mdm_inventory::DICTIONARY {
                return Err(Error::Conflict.into());
            }
            Some(super::condition_in(tx, self.tenant, id, version, &rule).await?)
        } else {
            None
        };
        Ok(
            json!({"group":group,"criteria":criteria,"member_set":member_set.map(|id|id.to_string()),"freshness":if self.current_in(tx,checked_input(Uuid::parse_str(&id.to_string()))?).await? {references::Freshness::Current}else{references::Freshness::Pending}}),
        )
    }
    pub async fn group_change(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        op: &Operation<GroupChange>,
        at: Timepoint,
        authority: &[RequiredAuthority],
        candidate: &rss_mdm_inventory::AssetCut,
    ) -> Result<Value> {
        if matches!(
            &op.input,
            GroupChange::Create { .. }
                | GroupChange::CreateSystem { .. }
                | GroupChange::Rule { .. }
                | GroupChange::Delete
        ) {
            group_checked(self.groups.lock_graph_in(tx).await?)?;
        }
        if matches!(
            &op.input,
            GroupChange::Create {
                criteria: Some(_),
                ..
            } | GroupChange::Rule { .. }
        ) {
            self.definition_references_in(tx, id, op).await?;
            return self
                .define_in(
                    tx,
                    DefinitionEdit {
                        authority: authority.to_vec(),
                        group: id,
                        change: op.clone(),
                        at: at.unix_seconds(),
                    },
                )
                .await;
        }
        self.publish_change_in(tx, id, op, at, authority, candidate)
            .await
    }
    /// Publish an already validated definition in the graph-fenced owner transaction.
    pub async fn publish_change_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        op: &Operation<GroupChange>,
        at: Timepoint,
        authority: &[RequiredAuthority],
        candidate: &rss_mdm_inventory::AssetCut,
    ) -> Result<Value> {
        crate::collection::resource_authoring::fence_in(tx).await?;
        if matches!(
            &op.input,
            GroupChange::Create { .. }
                | GroupChange::CreateSystem { .. }
                | GroupChange::Rule { .. }
                | GroupChange::Delete
        ) {
            group_checked(self.groups.lock_graph_in(tx).await?)?;
        }
        let group = checked_input(rss_mdm_group::GroupId::parse(&id.to_string()))?;
        let operation = checked_input(rss_mdm_group::OperationId::parse(
            &op.operation_id.to_string(),
        ))?;
        let expected = || {
            checked_input(pg::Revision::new(
                i64::try_from(op.expected_revision).map_err(|_| Error::Malformed)?,
            ))
        };
        let catalog = crate::assets::catalog_in(tx, self.tenant).await?;
        match &op.input {
            GroupChange::Create {
                criteria: Some(c), ..
            }
            | GroupChange::Rule { criteria: c } => {
                c.validate()?;
                assets::filter::require_visible_rule(
                    &catalog,
                    &rule(self.tenant, op.operation_id, &c.criteria, &catalog)?,
                )?
            }
            _ => (),
        }
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
                    asset_context: rss_mdm_group::AssetContext::Endpoint,
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
                return self
                    .start_group_job_in(
                        tx,
                        GroupStart {
                            asset_cut: candidate.clone(),
                            authority: authority.to_vec(),
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
                    .and_then(|accepted| json(&accepted));
            }
            GroupChange::Delete => {
                group_checked(self.groups.lock_reference_target_in(tx, group).await?)?;
                self.assert_unused_in(tx, id).await?;
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
                return self
                    .start_group_job_in(
                        tx,
                        GroupStart {
                            asset_cut: candidate.clone(),
                            authority: authority.to_vec(),
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
                    .and_then(|accepted| json(&accepted));
            }
        };
        let receipt = checked(self.groups.execute_in(tx, operation, at, &command).await?)?;
        if matches!(
            op.input,
            GroupChange::Create { .. }
                | GroupChange::CreateSystem { .. }
                | GroupChange::Rule { .. }
                | GroupChange::Delete
        ) {
            group_checked(self.groups.advance_graph_in(tx).await?)?;
        }
        crate::compliance::group_changed(tx, id).await?;
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
            group_checked(
                self.groups
                    .register_source_in(tx, group, receipt.group.revision.get() as u64)
                    .await?,
            )?;
            let accepted = self
                .start_group_job_in(
                    tx,
                    GroupStart {
                        asset_cut: candidate.clone(),
                        authority: authority.to_vec(),
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
            response["task"] = json!(accepted.task);
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
                    sqlx::query("INSERT INTO mdm_assets.group_selections(tenant_id,group_id,rule_version,selection) VALUES($1::uuid,$2,$3,$4::jsonb) ON CONFLICT DO NOTHING")
                        .bind(tenant).bind(id).bind(version).bind(selection).execute(c).await?; Ok(())
                })).await?;
            }
            group_checked(
                self.groups
                    .register_source_in(tx, group, receipt.group.revision.get() as u64)
                    .await?,
            )?;
            if criteria.is_some() {
                let task = Uuid::new_v4();
                let accepted = self
                    .start_group_job_in(
                        tx,
                        GroupStart {
                            asset_cut: candidate.clone(),
                            authority: authority.to_vec(),
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
                response["task"] = json!(accepted.task);
            }
        }
        Ok(response)
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
        let catalog = assets::catalog_in(tx, self.tenant).await?;
        if let Some(criteria) = criteria {
            fields.extend(
                rule(self.tenant, id, criteria, &catalog)?
                    .view()
                    .fields
                    .keys()
                    .cloned(),
            );
        }
        let catalog = assets::catalog_in(tx, self.tenant).await?;
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
