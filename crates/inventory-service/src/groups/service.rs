use super::*;
use rss_mdm_audit_integration::RequestAudit;
#[derive(serde::Serialize)]
#[serde(tag = "kind")]
pub enum Command {
    Group {
        id: Uuid,
        change: Box<Operation<GroupChange>>,
        sensitive: bool,
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
        authorize()?;
        crate::transaction::run(
            &self.audit_store,
            &self.runtime,
            self.tenant,
            audit,
            (self, command, audit, authorize, flow),
            |ctx, tx| {
                Box::pin(async move {
                    let (s, command, audit, authorize, flow) = *ctx;
                    let partitions = match command {
                        Command::Group { id, .. } => vec![s.groups.partition(&id.to_string())?],
                        _ => vec![],
                    };
                    tx.prepare_outbox_partitions(&partitions).await?;
                    crate::transaction::lock(tx).await?;
                    authorize()?;
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
                        receipts::audit(
                            tx,
                            &s.audit_store,
                            audit,
                            operation.zip(Some(digest.as_slice())),
                            true,
                        )
                        .await?;
                        authorize()?;
                        return Ok(old);
                    }
                    let at = checked_input(Timepoint::try_from(
                        s.clock
                            .unix_seconds()
                            .ok_or(Error::Unavailable(Failure::Clock))?,
                    ))?;
                    let result = match command {
                        Command::Group {
                            id,
                            change,
                            sensitive,
                        } => {
                            s.group_change(tx, *id, change, (at, *sensitive), flow)
                                .await?
                        }
                        Command::GroupRead { id } => s.group_read(tx, *id).await?,
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
                            s.group_page_in(tx, *group, *result, *projection, query)
                                .await?
                        }
                        Command::TaskRead { id, target } => flow.task(tx, *id, target).await?,
                    };
                    if let Some(id) = operation {
                        receipts::receipt(tx, actor, id, &digest, &result).await?;
                    }
                    receipts::audit(
                        tx,
                        &s.audit_store,
                        audit,
                        operation.zip(Some(digest.as_slice())),
                        false,
                    )
                    .await?;
                    authorize()?;
                    Ok(result)
                })
            },
            crate::transaction::TransactionOwner::Assets,
        )
        .await
    }
}
