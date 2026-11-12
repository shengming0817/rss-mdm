//! Configuration admission and settlement in the initiating Apple transaction.
use super::*;
use rss_mdm_apple_mdm::native::evidence::Settlement;
use rss_mdm_registration_service::DevicePrincipal;
pub struct AppleAdmission {
    pub command: AppleCommand,
    pub target: AppleRegistration,
    pub eligible: bool,
    pub dispatch: bool,
}
pub struct AppleRegistration {
    pub tenant: String,
    pub device: String,
}
pub struct AppleCommand {
    pub operation: Uuid,
    pub owner: String,
    pub deadline: i64,
    pub input_version: String,
    pub target: NativeTarget,
    pub request: rss_mdm_apple_mdm::native::request::Request,
}
async fn eligible(
    service: &Transactions,
    tx: &mut PgTransaction<'_>,
    p: &DevicePrincipal,
    op: &storage::Operation,
) -> Result<bool> {
    if op.device != p.device() || !matches!(op.request.task, Task::Macos { .. }) {
        return Err(Error::Unauthorized.into());
    }
    let now = storage::now(tx).await?;
    let command = service.required_command(tx, op).await?;
    Ok(now < op.request.deadline
        && matches!(
            command.status(),
            dc::Status::Published | dc::Status::Received
        )
        && storage::authority_decision(&service.source, &service.protection, tx, op, now)
            .await?
            .is_authorized())
}

impl Transactions {
    pub async fn apple_command_in(
        &self,
        tx: &mut PgTransaction<'_>,
        p: &DevicePrincipal,
        id: Uuid,
    ) -> Result<AppleAdmission> {
        self.runtime.validate_transaction(tx)?;
        let op = storage::load(tx, &self.protection, id).await?;
        let accepted = eligible(self, tx, p, &op).await?;
        let authority = op.authority.clone();
        let source = self.source.clone();
        let dispatch = tx
            .with_connection(move |c| {
                Box::pin(async move { Ok(authority.dispatch_ready(source.as_ref(), c).await) })
            })
            .await??;
        admission(self, op, accepted, dispatch)
    }
    pub async fn apple_candidates_in(
        &self,
        tx: &mut PgTransaction<'_>,
        p: &DevicePrincipal,
        user: &str,
        after: Uuid,
    ) -> Result<Vec<Uuid>> {
        self.runtime.validate_transaction(tx)?;
        let tenant = tx.tenant_id().to_string();
        let registration = p.device().to_string();

        let scope = user.to_owned();
        let cursor = after;
        Ok(tx.with_connection(move|c|Box::pin(async move {
        sqlx::query_scalar::<_,Uuid>("SELECT o.id FROM mdm_planning.configuration_operations AS o INNER JOIN rss_device_command.commands AS d ON d.tenant_id = o.tenant_id AND d.command_id = CAST(o.id AS text) WHERE o.tenant_id = CAST($1 AS uuid) AND o.device = CAST($2 AS text) AND o.gateway_accepted AND o.dispatch_failure IS NULL AND o.input_context ->> 'platform' = 'macos' AND d.status IN ('published', 'received') AND o.id > $3 AND ($4 = '' OR (o.input_context -> 'target' ->> 'kind' = 'user' AND o.input_context -> 'target' ->> 'userId' = $4)) AND CAST(o.input_context ->> 'deadline' AS bigint) > EXTRACT(EPOCH FROM clock_timestamp()) ORDER BY o.id LIMIT 64")
            .bind(tenant).bind(&registration).bind(cursor).bind(scope).fetch_all(c).await
  })).await?)
    }
    pub async fn apple_settle_in(
        &self,
        tx: &mut PgTransaction<'_>,
        p: &DevicePrincipal,
        id: Uuid,
        input_version: &str,
        fact: Settlement,
        audit: &RequestAudit,
    ) -> Result<()> {
        self.runtime.validate_transaction(tx)?;
        let service = self;
        let op = storage::load(tx, &self.protection, id).await?;
        if op.request.input_version != input_version {
            return Err(Error::Conflict.into());
        }
        if !eligible(self, tx, p, &op).await? {
            return Ok(());
        }
        let previous = self.required_command(tx, &op).await?.version();
        let event = match fact {
            Settlement::Waiting => return Ok(()),
            Settlement::Received => dc::DeviceEvent::Received,
            Settlement::Reported => dc::DeviceEvent::Reported(op.request.digest(
                &service.protection,
                service.tenant,
                &op.device,
            )?),
            Settlement::Rejected => dc::DeviceEvent::Rejected,
            Settlement::Profile => return Err(Error::Malformed.into()),
        };
        let report = dc::DeviceReport {
            scope: op.scope,
            command_id: op.command_id()?,
            coordinate: op.coordinate,
            event,
        };
        if matches!(report.event, dc::DeviceEvent::Reported(_))
            && service.required_command(tx, &op).await?.status() == dc::Status::Published
        {
            // A correlated recovery query establishes receipt of native evidence. The
            // failed mutation's own receipt stays unchanged and separately visible.
            let received = dc::DeviceReport {
                event: dc::DeviceEvent::Received,
                ..report.clone()
            };
            if service.store.report(tx, &received).await?.outcome == dc::Outcome::OutOfOrder {
                return Err(Error::Conflict.into());
            }
        }
        let transition = service.store.report(tx, &report).await?;
        if transition.outcome == dc::Outcome::OutOfOrder {
            return Err(Error::Conflict.into());
        }
        if transition.command.version() != previous {
            super::protocol::native_fact_in(
                service,
                tx,
                &op,
                transition.command.status(),
                transition.command.version(),
                audit,
            )
            .await?;
        }
        if transition.command.version() != previous {
            service.changes.configuration_progressed_in(tx, std::slice::from_ref(&op.device)).await?;
        }
        let withdrawal_received = transition.command.status() == dc::Status::Received
            && matches!(&op.request.task,Task::Macos{request:rss_mdm_apple_mdm::native::request::Request::Declarations{declarations,..}} if declarations.is_empty());
        if transition.command.status().is_terminal() || withdrawal_received {
            // Logical publication withdrawal can release desired claims without claiming an OS effect.
            service
                .wake_devices_in(tx, std::slice::from_ref(&op.device))
                .await?;
        }
        Ok(())
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "synchronization binds operation, input version and exact user/registration/generation in the borrowed transaction"
    )]
    pub async fn apple_synchronized_in(
        &self,
        tx: &mut PgTransaction<'_>,
        p: &DevicePrincipal,
        id: Uuid,
        input_version: &str,
        user: &str,
        device: &str,
    ) -> Result<()> {
        self.runtime.validate_transaction(tx)?;
        if device != p.device() {
            return Err(Error::Unauthorized.into());
        }
        let op = storage::load(tx, &self.protection, id).await?;
        if op.request.input_version != input_version || op.request.target.user_key() != user {
            return Err(Error::Conflict.into());
        }
        if !matches!(
            op.request.task,
            Task::Macos {
                request: rss_mdm_apple_mdm::native::request::Request::Declarations { .. }
            }
        ) {
            return Err(Error::Malformed.into());
        }
        if eligible(self, tx, p, &op).await? {
            complete_ddm(self, tx, &op).await?;
        }
        Ok(())
    }
    pub async fn apple_rejected_in(
        &self,
        tx: &mut PgTransaction<'_>,
        p: &DevicePrincipal,
        id: Uuid,
        reason: String,
    ) -> Result<()> {
        self.runtime.validate_transaction(tx)?;
        let tenant = tx.tenant_id().to_string();
        let registration = p.device().to_owned();

        tx.with_connection(move|c|Box::pin(async move{sqlx::query("UPDATE mdm_planning.configuration_operations SET dispatch_failure = $3, revision = revision + 1 WHERE tenant_id = CAST($1 AS uuid) AND id = $2 AND device = $4 AND dispatch_failure IS NULL").bind(tenant).bind(id).bind(sqlx::types::Json(model::DispatchFailure::Macos{reason})).bind(&registration).execute(c).await?;Ok(())})).await?;
        Ok(())
    }
    pub async fn apple_declarations_in(
        &self,
        tx: &mut PgTransaction<'_>,
        p: &DevicePrincipal,
        user: &str,
        ids: Vec<Uuid>,
    ) -> Result<Vec<AppleAdmission>> {
        self.runtime.validate_transaction(tx)?;
        let now = storage::now(tx).await?;
        let mut output = Vec::new();
        for id in ids {
            let op = storage::load(tx, &self.protection, id).await?;
            let status = self.required_command(tx, &op).await?.status();
            if (status == dc::Status::Applied
                || (!status.is_terminal() && now < op.request.deadline))
                && op.device == p.device()
                && op.request.target.user_key() == user
                && storage::authority_decision(&self.source, &self.protection, tx, &op, now)
                    .await?
                    .is_authorized()
            {
                output.push(admission(self, op, true, false)?);
            }
        }
        Ok(output)
    }
}
fn admission(
    s: &Transactions,
    op: storage::Operation,
    eligible: bool,
    dispatch: bool,
) -> Result<AppleAdmission> {
    let Task::Macos { request } = &op.request.task else {
        return Err(Error::Malformed.into());
    };
    Ok(AppleAdmission {
        eligible,
        dispatch,
        target: AppleRegistration {
            tenant: s.tenant.to_string(),
            device: op.device,
        },
        command: AppleCommand {
            operation: op.id,
            owner: op.authority.apple_owner(),
            deadline: op.request.deadline,
            input_version: op.request.input_version,
            target: op.request.target,
            request: request.clone(),
        },
    })
}
async fn complete_ddm(
    service: &Transactions,
    tx: &mut PgTransaction<'_>,
    op: &storage::Operation,
) -> Result<()> {
    let previous = service.required_command(tx, op).await?.version();
    if service.required_command(tx, op).await?.status() == dc::Status::Published {
        let transition = service
            .store
            .report(
                tx,
                &dc::DeviceReport {
                    scope: op.scope,
                    command_id: op.command_id()?,
                    coordinate: op.coordinate,
                    event: dc::DeviceEvent::Received,
                },
            )
            .await?;
        if transition.outcome == dc::Outcome::OutOfOrder {
            return Err(Error::Conflict.into());
        }
    }
    let transition = service
        .store
        .report(
            tx,
            &dc::DeviceReport {
                scope: op.scope,
                command_id: op.command_id()?,
                coordinate: op.coordinate,
                event: dc::DeviceEvent::Reported(op.request.digest(
                    &service.protection,
                    service.tenant,
                    &op.device,
                )?),
            },
        )
        .await?;
    if transition.outcome == dc::Outcome::OutOfOrder {
        return Err(Error::Conflict.into());
    }
    if transition.command.version() != previous {
        service.changes.configuration_progressed_in(tx, std::slice::from_ref(&op.device)).await?;
    }
    service
        .wake_devices_in(tx, std::slice::from_ref(&op.device))
        .await?;
    Ok(())
}

pub struct WakePage {
    pub next: Option<Uuid>,
    pub commands: Vec<(Uuid, String)>,
}
impl Transactions {
    pub async fn apple_wake_commands_in(
        &self,
        tx: &mut PgTransaction<'_>,
        device: String,
        after: Uuid,
    ) -> Result<WakePage> {
        self.runtime.validate_transaction(tx)?;
        let tenant = tx.tenant_id().to_string();
        let ids:Vec<Uuid>=tx.with_connection(move|c|Box::pin(async move {
   sqlx::query_scalar("SELECT o.id FROM mdm_planning.configuration_operations AS o INNER JOIN rss_device_command.commands AS d ON d.tenant_id = o.tenant_id AND d.command_id = CAST(o.id AS text) WHERE o.tenant_id = CAST($1 AS uuid) AND o.device = $2 AND o.gateway_accepted AND d.status IN ('published', 'received') AND CAST(o.input_context ->> 'deadline' AS bigint) > EXTRACT(EPOCH FROM clock_timestamp()) AND o.input_context ->> 'platform' = 'macos' AND o.dispatch_failure IS NULL AND o.id > $3 ORDER BY o.id LIMIT 64")
    .bind(tenant).bind(device).bind(after).fetch_all(c).await
  })).await?;
        let next = if ids.len() == 64 {
            ids.last().copied()
        } else {
            None
        };
        let now = storage::now(tx).await?;
        let mut commands = Vec::new();
        for id in ids {
            let op = storage::load(tx, &self.protection, id).await?;
            if storage::authority_decision(&self.source, &self.protection, tx, &op, now)
                .await?
                .is_authorized()
            {
                commands.push((id, op.request.target.user_key().to_owned()));
            }
        }
        Ok(WakePage { next, commands })
    }
}

impl Transactions {
    pub async fn apple_asset_authority_in(
        &self,
        tx: &mut PgTransaction<'_>,
        p: &DevicePrincipal,
        operation: Uuid,
    ) -> Result<(rss_mdm_apple_mdm::native::request::Request, NativeTarget)> {
        self.runtime.validate_transaction(tx)?;
        storage::lock_device(tx, p.device()).await?;
        let op = storage::load(tx, &self.protection, operation).await?;
        if op.device != p.device() || op.device != p.device() {
            return Err(Error::Unauthorized.into());
        }
        let now = storage::now(tx).await?;
        if !storage::authority_decision(&self.source, &self.protection, tx, &op, now)
            .await?
            .is_authorized()
        {
            return Err(Error::Forbidden.into());
        }
        let progress = self.required_command(tx, &op).await?.status();
        if (progress.is_terminal() && progress != dc::Status::Applied)
            || (!progress.is_terminal() && now >= op.request.deadline)
        {
            return Err(Error::Forbidden.into());
        }
        let Task::Macos { request } = op.request.task else {
            return Err(Error::Malformed.into());
        };
        Ok((request, op.request.target))
    }
}
