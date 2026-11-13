use super::*;
use rss_mdm_compliance::Current;
use rss_mdm_query::cursor::{CursorCodec, fingerprint};
use std::collections::BTreeMap;
impl Compliance {
    pub(crate) async fn task(
        &self,
        tx: &mut PgTransaction<'_>,
        rule: Uuid,
        task: Uuid,
    ) -> Result<TaskView> {
        let state = self.read_task_in(tx, task).await?;
        let input = state.input;
        let (done, failure, cursor, forwarded) =
            (state.completed, state.failure, state.cursor, state.started);
        if input.rule != rule {
            return Err(Error::NotFound.into());
        }
        let tenant = self.tenant();
        let processed = tx
            .with_connection(move |c| {
                Box::pin(async move { pg::result_count(c, tenant, task).await })
            })
            .await?;
        let detail = state
            .detail
            .map(|v| stored(serde_json::from_value(v)))
            .transpose()?;
        let phase = match failure.as_deref() {
            Some("superseded") => Phase::Superseded,
            Some(_) => Phase::Failed,
            None if done => Phase::Published,
            None if cursor.is_some() || forwarded => Phase::Evaluating,
            None => Phase::Queued,
        };
        Ok(TaskView {
            task,
            rule_id: rule,
            rule_version: input.revision,
            asset_cut: input.asset_cut,
            phase,
            processed,
            completed: done,
            failure,
            diagnostic: detail,
        })
    }
    async fn device(
        &self,
        tx: &mut PgTransaction<'_>,
        device: &rss_mdm_agent_wire::DeviceId,
    ) -> Result<()> {
        let t = self.tenant().to_string();
        let d = device.to_owned();
        if !tx
            .with_connection(move |c| {
                Box::pin(async move {
                    crate::device::read::exists(
                        rss_mdm_install_support::StorageProfile::Mdm,
                        c,
                        t,
                        d,
                    )
                    .await
                })
            })
            .await?
        {
            return Err(Error::NotFound.into());
        }
        Ok(())
    }
    pub(crate) async fn current(
        &self,
        tx: &mut PgTransaction<'_>,
        device: &rss_mdm_agent_wire::DeviceId,
    ) -> Result<CurrentView> {
        self.device(tx, device).await?;
        let t = self.tenant();
        let rules = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    pg::rules::<rss_mdm_inventory_service::assets::InventoryCondition>(
                        c, t, None, 101,
                    )
                    .await
                })
            })
            .await?;
        if rules.len() > 100 {
            return Err(Error::Unavailable(Failure::ComplianceStorage).into());
        }
        let tasks: Vec<Uuid> = rules.iter().filter_map(|r| r.current_run).collect();
        let name = device.to_owned();
        let ids = tasks.clone();
        let rows=tx.with_connection(move|c|Box::pin(async move{
          sqlx::query("SELECT task,document::text FROM mdm_compliance.results WHERE tenant_id=$1::uuid AND task=ANY($2::uuid[]) AND device=$3")
          .bind(t.to_string()).bind(ids).bind(name.into_uuid()).fetch_all(c).await
        })).await?;
        let mut documents = std::collections::BTreeMap::<Uuid, String>::new();
        for row in rows {
            documents.insert(row.try_get("task")?, row.try_get("document")?);
        }
        let mut runs = BTreeMap::new();
        let mut inputs = Vec::new();
        for id in tasks {
            let state = self.read_task_in(tx, id).await?;
            let (input, completed, failure) = (state.input, state.completed, state.failure);
            let value = documents
                .remove(&id)
                .map(|s| stored(serde_json::from_str::<Assessment>(&s)))
                .transpose()?;
            if let Some(v) = &value {
                stored(v.validate())?;
                if (v.rule_id, v.rule_version, &v.asset_cut)
                    != (input.rule, input.revision, &input.asset_cut)
                {
                    return Err(Error::Unavailable(Failure::ComplianceStorage).into());
                }
            }
            if completed && failure.is_none() {
                inputs.push(input);
            }
            runs.insert(id, value);
        }
        let fresh = self.inputs_current(tx, &inputs).await?;
        let mut items = Vec::new();
        let mut statuses = Vec::new();
        for rule in rules.into_iter().filter(|r| r.enabled) {
            let previous = rule.current_run.and_then(|id| runs.remove(&id).flatten());
            let current = if rule.current_run == rule.desired && fresh.contains(&rule.id) {
                previous.clone()
            } else {
                None
            };
            let status = current
                .as_ref()
                .map_or(Current::Pending, |v| Current::from(v.status));
            statuses.push(status);
            items.push(CurrentRule {
                rule_id: rule.id,
                rule_version: rule.revision,
                status,
                current,
                previous: if status == Current::Pending {
                    previous
                } else {
                    None
                },
            });
        }
        Ok(CurrentView {
            device: *device,
            status: rss_mdm_compliance::aggregate(statuses),
            reason: if items.is_empty() {
                Some(EmptyReason::NoRules)
            } else {
                None
            },
            rules: items,
        })
    }
    pub(crate) async fn history(
        &self,
        tx: &mut PgTransaction<'_>,
        device: &rss_mdm_agent_wire::DeviceId,
        subject: &str,
        query: &HistoryQuery,
    ) -> Result<History> {
        self.device(tx, device).await?;
        checked_input(query.page.require_schema(&HISTORY))?;
        let codec = CursorCodec::from_key(self.cursor_key.clone());
        let binding = checked_input(fingerprint(&(
            HISTORY.id,
            self.tenant().to_string(),
            device,
            subject,
            query.bounds,
        )))?;
        let after = query
            .page
            .cursor()
            .as_ref()
            .map(|token| -> Result<HistoryPosition> {
                codec
                    .decode(
                        &checked_input(rss_contract::PageCursor::parse(token))?,
                        &binding,
                    )
                    .map_err(|_| Error::Conflict.into())
            })
            .transpose()?;
        let limit = query.page.limit();
        let mut rows = self
            .history_in(tx, device, query.bounds, after, limit)
            .await?;
        let more = rows.len() > limit;
        rows.truncate(limit);
        let next = if more {
            rows.last()
                .map(|r| {
                    checked_input(codec.encode(&binding, &r.position))
                        .map(|c| c.as_str().to_owned())
                })
                .transpose()?
        } else {
            None
        };
        let mut items = Vec::with_capacity(rows.len());
        for row in rows {
            let assessment: Assessment = stored(serde_json::from_str(&row.document))?;
            stored(assessment.validate())?;
            items.push(HistoryEntry {
                assessment,
                task: row.position.task,
                disposition: match row.failure.as_deref() {
                    None => Disposition::Published,
                    Some("superseded") => Disposition::Superseded,
                    Some(_) => Disposition::Failed,
                },
            });
        }
        Ok(History {
            items,
            next_cursor: next,
        })
    }
}

impl crate::Compliance {
    /// Safe projection of the stored change/recompute result, independent of current rule state.
    pub async fn operation_receipt(
        &self,
        p: &rss_mdm_authorization_service::context::AuthorizedPrincipal,
        id: uuid::Uuid,
    ) -> std::result::Result<
        Option<rss_mdm_audit_integration::operation::ReceiptSummary>,
        crate::Error,
    > {
        use rss_mdm_authorization_service::Permission;
        p.manage(Permission::ComplianceRuleRead)?;
        crate::transaction::inspect(&self.runtime, self.tenant, p, |p, tx| {
            Box::pin(async move {
                crate::transaction::query_authority(tx, p).await?.require(
                    p,
                    Permission::ComplianceRuleRead,
                    None,
                )?;
                let tenant = tx.tenant_id();
                let row = tx
                    .with_connection(move |c| {
                        Box::pin(
                            async move { rss_mdm_compliance_postgres::replay(c, tenant, id).await },
                        )
                    })
                    .await?;
                row.map(|(_, v)| {
                    let mut s = rss_mdm_audit_integration::operation::ReceiptSummary::new(id);
                    s.object = v["id"].as_str().map(str::to_owned);
                    s.revision = v["revision"].as_i64();
                    if let Some(task) = v["task"].as_str() {
                        s.executions
                            .push(uuid::Uuid::parse_str(task).map_err(|_| crate::Error::Conflict)?);
                    }
                    if s.object.is_none() && s.executions.is_empty() {
                        return Err(crate::Error::Conflict.into());
                    }
                    Ok(s)
                })
                .transpose()
            })
        })
        .await
    }
}

impl Compliance {
    pub async fn task_receipt(
        &self,
        p: &rss_mdm_authorization_service::context::AuthorizedPrincipal,
        id: Uuid,
    ) -> std::result::Result<Option<rss_mdm_audit_integration::operation::ReceiptSummary>, Error>
    {
        crate::transaction::inspect(&self.runtime, self.tenant, (self, p), |(s, p), tx| {
            Box::pin(async move {
                crate::transaction::query_authority(tx, p).await?.require(
                    p,
                    rss_mdm_authorization_service::Permission::ComplianceRuleRead,
                    None,
                )?;
                let state = s.read_task_in(tx, id).await?;
                let mut value = rss_mdm_audit_integration::operation::ReceiptSummary::new(id);
                value.object = Some(state.input.rule.to_string());
                value.revision = Some(state.input.revision);
                value.accepted = Some(true);
                value.executions.push(id);
                let detail = s.task(tx, state.input.rule, id).await?;
                value.state = Some(
                    stored(serde_json::to_value(detail.phase))?
                        .as_str()
                        .ok_or(Error::Conflict)?
                        .into(),
                );
                p.check_live()?;
                Ok(Some(value))
            })
        })
        .await
    }
}
