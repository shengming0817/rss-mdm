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
    async fn validate_references_in(
        &self,
        tx: &mut PgTransaction<'_>,
        definition: &ScopeDefinition,
    ) -> transaction::Result<()> {
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
                                c, tenant, id,
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
            ScopeChange::Delete => {
                let head = self.store.head_in(tx, id, true).await?;
                if head.revision != op.expected_revision {
                    return Err(Error::Conflict.into());
                }
                if self.dependents.used_in(tx, id).await? {
                    return Err(Error::Conflict.into());
                }
                (
                    self.store.delete_in(tx, id, op.expected_revision).await?,
                    None,
                )
            }
        };
        Ok(serde_json::json!({"id":id,"revision":revision,"task":task}))
    }
    #[cfg(feature = "integration")]
    pub async fn seed_scope_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        definition: ScopeDefinition,
    ) -> transaction::Result<()> {
        let run = Uuid::new_v4();
        self.audit_store.bind_in(tx).await?;
        self.validate_references_in(tx, &definition).await?;
        self.store.put_in(tx, id, 0, &definition).await?;
        self.enqueue_in(tx, run, id).await?;
        for _ in 0..2048 {
            self.advance_in(tx, run).await?;
            if self.store.task_in(tx, run).await?.completed {
                return Ok(());
            }
        }
        Err(Error::Unavailable(Failure::Capacity).into())
    }
}
