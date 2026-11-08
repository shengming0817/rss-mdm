use crate::*;
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use rss_mdm_scope::{Reference, ScopeDefinition};
use rss_mdm_scope_postgres::{OwnedScope, ScopeOwner};
impl Scopes {
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

    pub async fn owned_in(
        &self,
        tx: &mut PgTransaction<'_>,
        owner: ScopeOwner,
    ) -> transaction::Result<Option<OwnedScope>> {
        Ok(self.store.owned_in(tx, owner).await?)
    }
    pub async fn lock_owned_in(
        &self,
        tx: &mut PgTransaction<'_>,
        ids: &[Uuid],
    ) -> transaction::Result<()> {
        let mut ids = ids.to_vec();
        ids.sort_unstable();
        ids.dedup();
        for id in ids {
            self.store.lock_scope_in(tx, id).await?;
        }
        Ok(())
    }
    pub async fn authorize_definition_in(
        &self,
        tx: &mut PgTransaction<'_>,
        proof: &AuthorizedPrincipal,
        definition: &ScopeDefinition,
    ) -> transaction::Result<()> {
        let grant = crate::action_admission::current(tx, proof).await?;
        grant.require_all_devices(proof, Permission::InventoryRead)?;
        if definition
            .references()
            .iter()
            .any(|r| matches!(r, Reference::Group(_)))
        {
            grant.require(proof, Permission::GroupRead, None)?;
        }
        Ok(())
    }
    /// Participate in the Policy save; the caller owns CAS, audit and settlement.
    pub async fn save_owned_in(
        &self,
        tx: &mut PgTransaction<'_>,
        proof: &AuthorizedPrincipal,
        owner: ScopeOwner,
        id: Uuid,
        definition: &ScopeDefinition,
    ) -> transaction::Result<wire::ScopeRead> {
        self.store.lock_scope_in(tx, id).await?;
        self.store.admit_configuration_in(tx).await?;
        self.authorize_definition_in(tx, proof, definition).await?;
        self.validate_references_in(tx, definition).await?;
        let previous = self.store.owned_in(tx, owner).await?;
        if previous.as_ref().is_some_and(|s| s.retired || s.id != id) {
            return Err(Error::Conflict.into());
        }
        let expected = previous.as_ref().map_or(0, |s| s.head.revision);
        let task = if previous
            .as_ref()
            .is_none_or(|s| s.head.definition != *definition)
        {
            self.store
                .put_in(tx, id, expected, owner, definition)
                .await?;
            Some(self.enqueue_in(tx, Uuid::new_v4(), id).await?)
        } else {
            self.store.pending_task_in(tx, id).await?
        };
        let child = self
            .store
            .owned_in(tx, owner)
            .await?
            .ok_or(Error::NotFound)?;
        Ok(child_view(owner, child, task))
    }
    pub async fn read_owned_in(
        &self,
        tx: &mut PgTransaction<'_>,
        owner: ScopeOwner,
    ) -> transaction::Result<wire::ScopeRead> {
        let child = self
            .store
            .owned_in(tx, owner)
            .await?
            .ok_or(Error::NotFound)?;
        let task = self.store.pending_task_in(tx, child.id).await?;
        Ok(child_view(owner, child, task))
    }
    pub async fn retire_owned_in(
        &self,
        tx: &mut PgTransaction<'_>,
        owner: ScopeOwner,
    ) -> transaction::Result<()> {
        let child = self
            .store
            .owned_in(tx, owner)
            .await?
            .ok_or(Error::NotFound)?;
        self.store
            .retire_in(tx, child.id, child.head.revision, owner)
            .await?;
        Ok(())
    }
    /// Explicit recomputation keeps its original actor-bound Scope receipt.
    pub async fn recompute_owned_in(
        &self,
        tx: &mut PgTransaction<'_>,
        proof: &AuthorizedPrincipal,
        audit: &RequestAudit,
        owner: ScopeOwner,
        operation: Uuid,
        expected_policy_revision: u64,
        current_policy_revision: u64,
    ) -> transaction::Result<wire::ScopeReceipt> {
        if operation.is_nil() {
            return Err(Error::Malformed.into());
        }
        self.store.admit_configuration_in(tx).await?;
        let child = self
            .store
            .owned_in(tx, owner)
            .await?
            .ok_or(Error::NotFound)?;
        self.authorize_definition_in(tx, proof, &child.head.definition)
            .await?;
        let fingerprint =
            transaction::fingerprint(&(owner, operation, expected_policy_revision, proof.actor()))?;
        if let Some(value) = self
            .store
            .replay_operation_in(
                tx,
                proof.principal_id(),
                proof.instance_id(),
                operation,
                &fingerprint,
            )
            .await?
        {
            audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);
            return stored(serde_json::from_value(value));
        }
        if child.retired || expected_policy_revision != current_policy_revision {
            return Err(Error::Conflict.into());
        }
        self.store.lock_scope_in(tx, child.id).await?;
        self.validate_references_in(tx, &child.head.definition)
            .await?;
        let old = self.store.pending_task_in(tx, child.id).await?;
        if let Some(old) = old {
            if self.store.run_in(tx, old).await?.is_some() {
                self.store.phase_in(tx, old, "superseded").await?;
            }
            self.finish_in(tx, old, Some("superseded")).await?;
        }
        let new = self.enqueue_in(tx, Uuid::new_v4(), child.id).await?;
        if let Some(old) = old {
            self.store.replace_task_in(tx, old, new).await?;
        }
        let value = wire::ScopeReceipt {
            id: child.id,
            revision: child.head.revision,
            task: Some(new),
        };
        self.store
            .record_operation_in(
                tx,
                proof.principal_id(),
                proof.instance_id(),
                operation,
                &fingerprint,
                &json(&value)?,
            )
            .await?;
        let fact = rss_mdm_audit_integration::Fact::business(
            audit,
            rss_mdm_audit_integration::operation::OperationOwner::Scope,
            &format!("scope:{}:{operation}", proof.principal_id()),
            200,
            "success",
            None,
        )?;
        self.audit_store.append_in(tx, &fact).await?;
        Ok(value)
    }
}
fn child_view(owner: ScopeOwner, child: OwnedScope, task: Option<Uuid>) -> wire::ScopeRead {
    wire::ScopeRead {
        id: child.id,
        stage: owner.stage,
        revision: child.head.revision,
        definition: child.head.definition,
        retired: child.retired,
        resolution: child.head.resolution,
        resolution_revision: child.head.resolution_revision,
        task,
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
        p.manage(Permission::PolicyRead)?;
        crate::transaction::inspect(&self.runtime, self.tenant, (self, p), |(s, p), tx| {
            Box::pin(async move {
                crate::action_admission::current(tx, p).await?.require(
                    p,
                    Permission::PolicyRead,
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
