//! Business admission and reducers borrowed by the Apple protocol transaction.
use crate::native::device::DevicePrincipal;
use crate::native::*;
use rss_mdm_apple_mdm::native::evidence::Settlement;
pub struct AppleAdmission {
    pub command: apple_facts::AppleCommand,
    pub target: apple_facts::AppleRegistration,
    pub eligible: bool,
    pub dispatch: bool,
}
async fn eligible(
    service: &crate::native::Transactions,
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
        && storage::authority_valid(service.materials.clone(), tx, op).await?)
}

impl Service {
    pub async fn apple_settle_failures_in(
        &self,
        tx: &mut PgTransaction<'_>,
        p: &DevicePrincipal,
        audit: &RequestAudit,
    ) -> Result<()> {
        self.transactions.runtime.validate_transaction(tx)?;
        crate::native::protocol::settle_dispatch_failures(self, tx, p, audit).await
    }

    pub async fn apple_prepare_in(
        &self,
        tx: &mut PgTransaction<'_>,
        p: &DevicePrincipal,
        audit: &RequestAudit,
    ) -> Result<()> {
        self.transactions.runtime.validate_transaction(tx)?;
        storage::lock_device(tx, p.device()).await?;
        crate::native::transaction::prepare_audit_in(&self.transactions.audit_store, tx, audit, &[])
            .await
            .map_err(Into::into)
    }
    pub async fn apple_command_in(
        &self,
        tx: &mut PgTransaction<'_>,
        p: &DevicePrincipal,
        id: Uuid,
    ) -> Result<AppleAdmission> {
        self.transactions.runtime.validate_transaction(tx)?;
        let op = storage::load(tx, &self.transactions.protection, id).await?;
        let accepted = eligible(&self.transactions, tx, p, &op).await?;
        admission(self, op, accepted, accepted)
    }
    pub async fn apple_candidates_in(
        &self,
        tx: &mut PgTransaction<'_>,
        p: &DevicePrincipal,
        user: &str,
        after: Uuid,
    ) -> Result<Vec<Uuid>> {
        self.transactions.runtime.validate_transaction(tx)?;
        let tenant = tx.tenant_id().to_string();
        let registration = p.device().to_string();

        let scope = user.to_owned();
        let cursor = after;
        Ok(tx.with_connection(move|c|Box::pin(async move {
        sqlx::query_scalar::<_,Uuid>("SELECT o.id FROM mdm_recovery_tasks.operations AS o INNER JOIN rss_device_command.commands AS d ON d.tenant_id = o.tenant_id AND d.command_id = CAST(o.id AS text) WHERE o.tenant_id = CAST($1 AS uuid) AND o.device = CAST($2 AS text) AND o.gateway_accepted AND o.dispatch_failure IS NULL AND o.input_context ->> 'platform' = 'macos' AND d.status IN ('published', 'received') AND o.id > $3 AND ($4 = '' OR (o.input_context -> 'target' ->> 'kind' = 'user' AND o.input_context -> 'target' ->> 'userId' = $4)) AND CAST(o.input_context ->> 'deadline' AS bigint) > EXTRACT(EPOCH FROM clock_timestamp()) ORDER BY o.id LIMIT 64")
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
        self.transactions.runtime.validate_transaction(tx)?;
        let service = self;
        let op = storage::load(tx, &self.transactions.protection, id).await?;
        if op.request.input_version != input_version {
            return Err(Error::Conflict.into());
        }
        if !eligible(&self.transactions, tx, p, &op).await? {
            return Ok(());
        }
        let previous = self.transactions.required_command(tx, &op).await?.version();
        let event = match fact {
            Settlement::Waiting => return Ok(()),
            Settlement::Received => dc::DeviceEvent::Received,
            Settlement::Reported => dc::DeviceEvent::Reported(op.request.digest(
                &service.transactions.protection,
                service.transactions.tenant,
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
            && service
                .transactions
                .required_command(tx, &op)
                .await?
                .status()
                == dc::Status::Published
        {
            // A correlated recovery query establishes receipt of native evidence. The
            // failed mutation's own receipt stays unchanged and separately visible.
            let received = dc::DeviceReport {
                event: dc::DeviceEvent::Received,
                ..report.clone()
            };
            if service
                .transactions
                .store
                .report(tx, &received)
                .await?
                .outcome
                == dc::Outcome::OutOfOrder
            {
                return Err(Error::Conflict.into());
            }
        }
        let transition = service.transactions.store.report(tx, &report).await?;
        if transition.outcome == dc::Outcome::OutOfOrder {
            return Err(Error::Conflict.into());
        }
        if transition.command.version() != previous {
            crate::native::timeline::native_fact_in(
                service,
                tx,
                &op,
                transition.command.status(),
                transition.command.version(),
                audit,
            )
            .await?;
        }
        let withdrawal_received = transition.command.status() == dc::Status::Received
            && matches!(&op.request.task,Task::Macos{request:rss_mdm_apple_mdm::native::request::Request::Declarations{declarations,..}} if declarations.is_empty());
        if transition.command.status().is_terminal() || withdrawal_received {
            // Logical publication withdrawal can release desired claims without claiming an OS effect.
            crate::native::wake::wake_native_in(
                &service.transactions.reconcile_messaging,
                tx,
                &op.device,
            )
            .await?;
        }
        Ok(())
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "synchronization binds operation, input version and exact user/registration/generation in the borrowed transaction"
    )]
    pub async fn apple_rejected_in(
        &self,
        tx: &mut PgTransaction<'_>,
        p: &DevicePrincipal,
        id: Uuid,
        reason: String,
    ) -> Result<()> {
        self.transactions.runtime.validate_transaction(tx)?;
        let tenant = tx.tenant_id().to_string();
        let registration = p.device().to_owned();

        tx.with_connection(move|c|Box::pin(async move{sqlx::query("UPDATE mdm_recovery_tasks.operations SET dispatch_failure = $3, revision = revision + 1 WHERE tenant_id = CAST($1 AS uuid) AND id = $2 AND device = $4 AND dispatch_failure IS NULL").bind(tenant).bind(id).bind(sqlx::types::Json(crate::native::DispatchFailure::Macos{reason})).bind(&registration).execute(c).await?;Ok(())})).await?;
        Ok(())
    }
}
fn admission(
    s: &Service,
    op: storage::Operation,
    eligible: bool,
    dispatch: bool,
) -> Result<AppleAdmission> {
    let Task::Macos { request } = &op.request.task;
    Ok(AppleAdmission {
        eligible,
        dispatch,
        target: apple_facts::AppleRegistration {
            tenant: s.transactions.tenant.to_string(),
            device: op.device,
        },
        command: apple_facts::AppleCommand {
            operation: op.id,
            authorized_declarations: Vec::new(),
            owner: op.authority.apple_owner(op.id)?,
            assets: Vec::new(),
            deadline: op.request.deadline,
            input_version: op.request.input_version,
            target: op.request.target,
            request: request.clone(),
        },
    })
}

pub struct WakePage {
    pub next: Option<Uuid>,
    pub commands: Vec<(Uuid, String)>,
}
impl Service {
    pub async fn apple_prepare_wake_in(
        &self,
        tx: &mut PgTransaction<'_>,
        mut devices: Vec<String>,
        audit: &RequestAudit,
    ) -> Result<()> {
        self.transactions.runtime.validate_transaction(tx)?;
        devices.sort();
        devices.dedup();
        for device in devices {
            storage::lock_device(tx, &device).await?;
        }
        crate::native::transaction::prepare_audit_in(&self.transactions.audit_store, tx, audit, &[])
            .await
            .map_err(Into::into)
    }
    pub async fn apple_wake_commands_in(
        &self,
        tx: &mut PgTransaction<'_>,
        registration: String,
        after: Uuid,
    ) -> Result<WakePage> {
        self.transactions.runtime.validate_transaction(tx)?;
        let tenant = tx.tenant_id().to_string();
        let ids:Vec<Uuid>=tx.with_connection(move|c|Box::pin(async move {
   sqlx::query_scalar("SELECT o.id FROM mdm_recovery_tasks.operations AS o INNER JOIN rss_device_command.commands AS d ON d.tenant_id = o.tenant_id AND d.command_id = CAST(o.id AS text) WHERE o.tenant_id = CAST($1 AS uuid) AND o.device = $2 AND o.gateway_accepted AND d.status IN ('published', 'received') AND CAST(o.input_context ->> 'deadline' AS bigint) > EXTRACT(EPOCH FROM clock_timestamp()) AND o.input_context ->> 'platform' = 'macos' AND o.dispatch_failure IS NULL AND o.id > $3 ORDER BY o.id LIMIT 64")
    .bind(tenant).bind(&registration).bind(after).fetch_all(c).await
  })).await?;
        let next = if ids.len() == 64 {
            ids.last().copied()
        } else {
            None
        };
        let _now = storage::now(tx).await?;
        let mut commands = Vec::new();
        for id in ids {
            let op = storage::load(tx, &self.transactions.protection, id).await?;
            if storage::authority_valid(self.transactions.materials.clone(), tx, &op).await? {
                commands.push((id, op.request.target.user_key().to_owned()));
            }
        }
        Ok(WakePage { next, commands })
    }
}
