use crate::*;
use operation::Operation;
use rss_contract::Timepoint;
use rss_mdm_scope::{Reference, ScopeDefinition};
impl Scopes {
    pub async fn scope_definition(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
    ) -> transaction::Result<rss_mdm_scope_postgres::DefinitionSnapshot> {
        let head = self.store.head_in(tx, id, false).await?;
        Ok(rss_mdm_scope_postgres::DefinitionSnapshot {
            revision: head.revision,
            definition: head.definition,
        })
    }
    pub async fn scope_read(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
    ) -> transaction::Result<Value> {
        let h = self.store.head_in(tx, id, false).await?;
        Ok(
            serde_json::json!({"id":id,"revision":h.revision,"definition":h.definition,"resolution":h.resolution,"resolution_revision":h.resolution_revision}),
        )
    }
    pub(crate) async fn validate_references_in(
        &self,
        tx: &mut PgTransaction<'_>,
        definition: &ScopeDefinition,
    ) -> transaction::Result<()> {
        let profile = self.profile();

        if definition.references().len() > 1000 {
            return Err(Error::Malformed.into());
        }
        for r in definition.references() {
            match r {
                Reference::Group(id) => {
                    group_checked(
                        self.groups
                            .lock_reference_target_in(
                                tx,
                                checked_input(rss_mdm_group::GroupId::parse(&id.to_string()))?,
                            )
                            .await?,
                    )?;
                }
                Reference::Device(id) => {
                    checked_input(rss_mdm_scope::DeviceId::new(self.tenant, &id))?;
                    let tenant = self.tenant.to_string();
                    if !tx
                        .with_connection(move |c| {
                            Box::pin(rss_mdm_registration_service::device::read::registered(
                                profile, c, tenant, id,
                            ))
                        })
                        .await?
                    {
                        return Err(Error::NotFound.into());
                    }
                }
            }
        }
        Ok(())
    }
    pub async fn scope_change(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        op: &Operation<ScopeChange>,
        _: Timepoint,
    ) -> transaction::Result<Value> {
        self.store.lock_scope_in(tx, id).await?;
        self.store.admit_in(tx).await?;
        if id.is_nil() {
            return Err(Error::Malformed.into());
        }
        let (revision, task) = match &op.input {
            ScopeChange::Put { definition } => {
                self.validate_references_in(tx, definition).await?;
                let revision = self
                    .store
                    .put_in(tx, id, op.expected_revision, definition)
                    .await?;
                let task = self.enqueue_in(tx, Uuid::new_v4(), id).await?;
                (revision, Some(task))
            }
            ScopeChange::Recompute => {
                let head = self.store.head_in(tx, id, true).await?;
                if head.revision != op.expected_revision {
                    return Err(Error::Conflict.into());
                }
                self.validate_references_in(tx, &head.definition).await?;
                let old = self.store.pending_task_in(tx, id).await?;
                if let Some(old) = old {
                    if self.store.run_in(tx, old).await?.is_some() {
                        self.store.phase_in(tx, old, "superseded").await?;
                    }
                    self.finish_in(tx, old, Some("superseded")).await?;
                }
                let new = self.enqueue_in(tx, Uuid::new_v4(), id).await?;
                if let Some(old) = old {
                    self.store.replace_task_in(tx, old, new).await?;
                }
                (head.revision, Some(new))
            }
            ScopeChange::Delete => {
                let head = self.store.head_in(tx, id, true).await?;
                if head.revision != op.expected_revision {
                    return Err(Error::Conflict.into());
                }
                if self.dependents.used_in(tx, id).await? {
                    return Err(Error::Referenced.into());
                }
                (
                    self.store.delete_in(tx, id, op.expected_revision).await?,
                    None,
                )
            }
        };
        Ok(serde_json::json!({"id":id,"revision":revision,"task":task}))
    }
}

impl Scopes {
    /// Original actor-bound Scope receipt under the current Scope read permission.
    pub async fn operation_receipt(
        &self,
        p: &rss_mdm_authorization_service::context::AuthorizedPrincipal,
        id: Uuid,
    ) -> std::result::Result<Option<rss_mdm_audit_integration::operation::ReceiptSummary>, Error>
    {
        use rss_mdm_authorization_service::Permission;
        p.manage(Permission::ScopeRead)?;
        crate::transaction::inspect(&self.runtime, self.tenant, (self, p), |(s, p), tx| {
            Box::pin(async move {
                crate::action_admission::current(tx, p).await?.require(
                    p,
                    Permission::ScopeRead,
                    None,
                )?;
                let value = s
                    .store
                    .operation_in(tx, p.principal_id(), p.instance_id(), id)
                    .await?;
                value
                    .map(|v| {
                        let mut s = rss_mdm_audit_integration::operation::ReceiptSummary::new(id);
                        s.object = Some(v["id"].as_str().ok_or(Error::Conflict)?.into());
                        s.revision = Some(v["revision"].as_i64().ok_or(Error::Conflict)?);
                        if let Some(task) = v["task"].as_str() {
                            s.executions
                                .push(Uuid::parse_str(task).map_err(|_| Error::Conflict)?);
                        }
                        Ok(s)
                    })
                    .transpose()
            })
        })
        .await
    }
}
