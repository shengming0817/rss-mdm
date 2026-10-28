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
        query: rss_mdm_query::window::Query,
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
        proof: &rss_mdm_authorization_service::context::AuthorizedPrincipal,
    ) -> std::result::Result<Value, Error> {
        self.execute_with_initialization(command, audit, proof, false)
            .await
    }
    /// Only the product initializer can create a lifecycle-owned system group.
    pub async fn execute_initialization(
        &self,
        command: &Command,
        audit: &RequestAudit,
        proof: &rss_mdm_authorization_service::context::AuthorizedPrincipal,
    ) -> std::result::Result<Value, Error> {
        self.execute_with_initialization(command, audit, proof, true)
            .await
    }

    async fn execute_with_initialization(
        &self,
        command: &Command,
        audit: &RequestAudit,
        proof: &rss_mdm_authorization_service::context::AuthorizedPrincipal,
        initialization: bool,
    ) -> std::result::Result<Value, Error> {
        if matches!(command,Command::Group {change,..} if matches!(change.input,GroupChange::CreateSystem {..}))
            && !initialization
        {
            return Err(Error::Forbidden);
        }
        if !initialization && proof.initialization_authority().is_some() {
            return Err(Error::Forbidden);
        }
        use rss_mdm_authorization_service::{OperationAuthority, Permission};
        if proof.tenant_id() != self.tenant.to_string() {
            return Err(Error::Forbidden);
        }
        proof.bind_audit(audit)?;
        let permission = match command {
            Command::Group { change, .. }
                if matches!(change.input, GroupChange::Recompute { .. }) =>
            {
                Permission::GroupRecompute
            }
            Command::Group { .. } => Permission::GroupWrite,
            _ => Permission::GroupRead,
        };
        let nested = matches!(command,Command::Group {change,..} if matches!(&change.input,GroupChange::Create{criteria:Some(c),..}|GroupChange::Rule{criteria:c} if c.criteria.references_groups()));
        let authorize = || -> std::result::Result<(), Error> {
            proof.manage(permission)?;
            proof.require_all_devices(Permission::InventoryRead)?;
            if nested {
                proof.manage(Permission::GroupRead)?;
            }
            Ok(())
        };
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
            (
                self,
                command,
                audit,
                &authorize,
                proof,
                initialization,
                permission,
                nested,
            ),
            |ctx, tx| {
                Box::pin(async move {
                    let (s, command, audit, authorize, proof, initialization, permission, nested) =
                        *ctx;
                    let partitions = match command {
                        Command::Group { id, .. } => vec![
                            s.groups
                                .partition(&id.to_string())
                                .map_err(|_| Error::Malformed)?,
                        ],
                        _ => vec![],
                    };
                    s.audit_store.prepare_in(tx, audit, &partitions).await?;
                    if initialization {
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
                    let auth_tenant = proof.tenant_id().to_owned();
                    let instance = proof.instance_id().to_owned();
                    let snapshot = tx
                        .with_connection(move |c| {
                            Box::pin(async move {
                                rss_mdm_authorization_service::lock_on(c, &auth_tenant, &instance)
                                    .await
                                    .map_err(|_| {
                                        sqlx::Error::Protocol("group authorization lock".into())
                                    })?;
                                Ok(rss_mdm_authorization_service::snapshot_on(
                                    c,
                                    &auth_tenant,
                                    &instance,
                                )
                                .await)
                            })
                        })
                        .await??;
                    let mut authority = vec![
                        RequiredAuthority {
                            permission,
                            evidence: OperationAuthority::tenant(&snapshot, proof, permission)?,
                        },
                        RequiredAuthority {
                            permission: Permission::InventoryRead,
                            evidence: OperationAuthority::all_devices(
                                &snapshot,
                                proof,
                                Permission::InventoryRead,
                            )?,
                        },
                    ];
                    if nested {
                        authority.push(RequiredAuthority {
                            permission: Permission::GroupRead,
                            evidence: OperationAuthority::tenant(
                                &snapshot,
                                proof,
                                Permission::GroupRead,
                            )?,
                        });
                    }
                    if matches!(
                        command,
                        Command::Group { .. } | Command::GroupPreview { .. }
                    ) {
                        s.lock_business_in(tx).await?;
                    }
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
                            s.group_change(tx, *id, change, at, &authority).await?
                        }
                        Command::GroupRead { id } => s.group_read(tx, *id).await?,
                        Command::GroupPreview {
                            id,
                            operation,
                            expected_revision,
                        } => {
                            s.group_preview(tx, *id, *operation, *expected_revision, at, &authority)
                                .await?
                        }
                        Command::GroupPage {
                            group,
                            result,
                            projection,
                            query,
                        } => {
                            s.group_page_in(
                                tx,
                                *group,
                                *result,
                                *projection,
                                query,
                                &checked_input(rss_mdm_query::cursor::fingerprint(&(
                                    audit.snapshot().actor,
                                    audit.snapshot().instance,
                                )))?,
                            )
                            .await?
                        }
                        Command::TaskRead { id, target } => s.task_read_in(tx, *id, target).await?,
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
