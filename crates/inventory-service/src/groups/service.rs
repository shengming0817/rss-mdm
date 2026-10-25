use super::*;
use rss_mdm_audit_integration::RequestAudit;
#[derive(serde::Serialize)]
#[serde(tag = "kind")]
pub enum Command {
    Group {
        id: Uuid,
        change: Box<Operation<GroupChange>>,
    },
    GroupRead {
        id: Uuid,
    },
    GroupPreview {
        id: Uuid,
        operation: Uuid,
        expected_revision: u64,
    },
    GroupPage {
        group: Uuid,
        result: Uuid,
        projection: pages::GroupPageKind,
        query: pages::PageQuery,
    },
    TaskRead {
        id: Uuid,
        target: String,
    },
}
impl Groups {
    pub async fn execute(
        &self,
        command: &Command,
        audit: &RequestAudit,
        authorize: &(dyn Fn() -> std::result::Result<(), Error> + Sync),
        flow: &dyn Flow,
    ) -> std::result::Result<Value, Error> {
        self.execute_with_initialization(command, audit, authorize, flow, None)
            .await
    }
    /// Only the product initializer can create a lifecycle-owned system group.
    pub async fn execute_initialization(
        &self,
        command: &Command,
        audit: &RequestAudit,
        proof: &rss_mdm_authorization_service::context::AuthorizedPrincipal,
        flow: &dyn Flow,
    ) -> std::result::Result<Value, Error> {
        self.execute_with_initialization(
            command,
            audit,
            &|| {
                proof
                    .manage(rss_mdm_authorization_service::Permission::GroupWrite)
                    .map_err(Error::from)
            },
            flow,
            Some(proof),
        )
        .await
    }
    async fn execute_with_initialization(
        &self,
        command: &Command,
        audit: &RequestAudit,
        authorize: &(dyn Fn() -> std::result::Result<(), Error> + Sync),
        flow: &dyn Flow,
        initialization: Option<&rss_mdm_authorization_service::context::AuthorizedPrincipal>,
    ) -> std::result::Result<Value, Error> {
        if matches!(command,Command::Group {change,..} if matches!(change.input,GroupChange::CreateSystem {..}))
            && initialization.is_none()
        {
            return Err(Error::Forbidden);
        }
        match command {
            Command::Group { id, .. }
            | Command::GroupRead { id }
            | Command::GroupPreview { id, .. } => audit.resource_target(
                rss_mdm_audit_integration::TargetKind::Group,
                &id.to_string(),
            ),
            Command::GroupPage { group, .. } => audit.resource_target(
                rss_mdm_audit_integration::TargetKind::Group,
                &group.to_string(),
            ),
            Command::TaskRead { target, .. } => {
                audit.resource_target(rss_mdm_audit_integration::TargetKind::Group, target)
            }
        }
        authorize()?;
        crate::transaction::run(
            &self.audit_store,
            &self.runtime,
            self.tenant,
            audit,
            (self, command, audit, authorize, flow, initialization),
            |ctx, tx| {
                Box::pin(async move {
                    let (s, command, audit, authorize, flow, initialization) = *ctx;
                    if let Some(proof) = initialization {
                        let Command::Group { id, .. } = command else {
                            return Err(Error::Forbidden.into());
                        };
                        rss_mdm_authorization_service::baseline::check_in(
                            tx,
                            proof,
                            rss_mdm_authorization_service::Permission::GroupWrite,
                            &id.to_string(),
                        )
                        .await?;
                    }
                    if matches!(
                        command,
                        Command::Group { .. } | Command::GroupPreview { .. }
                    ) {
                        crate::transaction::lock(tx).await?;
                        let tenant = tx.tenant_id().to_string();
                        tx.with_connection(move |c| {
                            Box::pin(async move {
                                sqlx::query("SELECT mdm_devices.lock_query_revision($1::uuid)")
                                    .bind(tenant)
                                    .execute(c)
                                    .await?;
                                Ok(())
                            })
                        })
                        .await?;
                    }
                    authorize()?;
                    let partitions = match command {
                        Command::Group { id, .. } => vec![
                            s.groups
                                .partition(&id.to_string())
                                .map_err(|_| Error::Malformed)?,
                        ],
                        _ => vec![],
                    };
                    s.audit_store.prepare_in(tx, audit, &partitions).await?;
                    let operation = match command {
                        Command::Group { change, .. } => Some(change.operation_id),
                        Command::GroupPreview { operation, .. } => Some(*operation),
                        _ => None,
                    };
                    if operation.is_some_and(|id| id.is_nil()) {
                        return Err(Error::Malformed.into());
                    }
                    let who = audit.snapshot();
                    let actor = who.actor.as_deref().ok_or(Error::Unauthorized)?;
                    let digest = fingerprint(&(
                        "groups",
                        audit.tenant(),
                        actor,
                        who.instance.as_deref(),
                        command,
                    ))?;
                    if let Some(id) = operation
                        && let Some(old) = receipts::replay(tx, actor, id, &digest).await?
                    {
                        audit.management_result(
                            rss_mdm_audit_integration::ManagementResult::Replayed,
                        );
                        receipts::audit(tx, &s.audit_store, audit, operation, true).await?;
                        authorize()?;
                        return Ok(old);
                    }
                    let at = checked_input(Timepoint::try_from(
                        s.clock
                            .unix_seconds()
                            .ok_or(Error::Unavailable(Failure::Clock))?,
                    ))?;
                    let result = match command {
                        Command::Group { id, change } => {
                            s.group_change(tx, *id, change, at, flow).await?
                        }
                        Command::GroupRead { id } => s.group_read(tx, *id, flow).await?,
                        Command::GroupPreview {
                            id,
                            operation,
                            expected_revision,
                        } => {
                            s.group_preview(tx, *id, *operation, *expected_revision, at, flow)
                                .await?
                        }
                        Command::GroupPage {
                            group,
                            result,
                            projection,
                            query,
                        } => {
                            s.group_page_in(tx, *group, *result, *projection, query, flow)
                                .await?
                        }
                        Command::TaskRead { id, target } => flow.task(tx, *id, target).await?,
                    };
                    if let Some(id) = operation {
                        receipts::receipt(tx, actor, id, &digest, &result).await?;
                    }
                    receipts::audit(tx, &s.audit_store, audit, operation, false).await?;
                    authorize()?;
                    Ok(result)
                })
            },
            crate::transaction::TransactionOwner::Assets,
        )
        .await
    }
}
