//! Business admission and reducers borrowed by the Apple protocol transaction.
use crate::device::DevicePrincipal;
use crate::*;
use rss_mdm_apple_mdm::native::evidence::Settlement;
pub struct AppleAdmission {
    pub command: apple_facts::AppleCommand,
    pub target: apple_facts::AppleRegistration,
    pub eligible: bool,
    pub dispatch: bool,
}
async fn eligible(
    service: &crate::transactions::ExecutionTransactions,
    tx: &mut PgTransaction<'_>,
    p: &DevicePrincipal,
    op: &storage::Operation,
) -> Result<bool> {
    if op.registration != p.registration()
        || op.registration_generation != p.generation()
        || !matches!(op.request.task, Task::Macos { .. })
    {
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

impl ExecutionService {
    pub async fn apple_settle_failures_in(
        &self,
        tx: &mut PgTransaction<'_>,
        p: &DevicePrincipal,
        audit: &RequestAudit,
    ) -> Result<()> {
        self.transactions.runtime.validate_transaction(tx)?;
        crate::protocol::settle_dispatch_failures(self, tx, p, audit).await
    }

    pub async fn apple_prepare_in(
        &self,
        tx: &mut PgTransaction<'_>,
        p: &DevicePrincipal,
        audit: &RequestAudit,
    ) -> Result<()> {
        self.transactions.runtime.validate_transaction(tx)?;
        actions::native_recovery::lock_device(tx, p.device()).await?;
        crate::transaction::prepare_audit_in(&self.transactions.audit_store, tx, audit, &[])
            .await
            .map_err(Into::into)
    }
    pub async fn apple_authenticated_in(
        &self,
        tx: &mut PgTransaction<'_>,
        p: &DevicePrincipal,
    ) -> Result<()> {
        self.transactions.runtime.validate_transaction(tx)?;
        actions::native_recovery::record(&self.transactions.reconcile_messaging, tx, p).await
    }
    pub async fn apple_finish_in(
        &self,
        tx: &mut PgTransaction<'_>,
        p: &DevicePrincipal,
        collection: Option<Uuid>,
        audit: &RequestAudit,
    ) -> Result<()> {
        self.transactions.runtime.validate_transaction(tx)?;
        if let Some(id) = collection {
            actions::recovery::recover_one(self, tx, id).await?;
        }
        self.transactions
            .reconcile_agent_install_in(tx, p.device(), audit)
            .await?;
        Ok(())
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
        let authority = op.authority.clone();
        let source = self.transactions.source.clone();
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
        self.transactions.runtime.validate_transaction(tx)?;
        let tenant = tx.tenant_id().to_string();
        let registration = p.registration().to_string();
        let generation = p.generation();
        let scope = user.to_owned();
        let cursor = after;
        Ok(tx.with_connection(move|c|Box::pin(async move {
        sqlx::query_scalar::<_,Uuid>("SELECT o.id FROM mdm_commands.operations o JOIN rss_device_command.commands d ON d.tenant_id=o.tenant_id AND d.command_id=o.id::text WHERE o.tenant_id=$1::uuid AND o.registration=$2::uuid AND o.registration_generation=$3 AND o.gateway_accepted AND o.dispatch_failure IS NULL AND o.input_context->>'platform'='macos' AND d.status IN ('published','received') AND o.id>$4 AND ($5='' OR (o.input_context->'target'->>'kind'='user' AND o.input_context->'target'->>'userId'=$5)) AND (o.input_context->>'deadline')::bigint>extract(epoch FROM clock_timestamp()) ORDER BY o.id LIMIT 64")
            .bind(tenant).bind(registration).bind(generation).bind(cursor).bind(scope).fetch_all(c).await
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
            crate::timeline::native_fact_in(
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
            crate::wake::wake_native_in(
                &service.transactions.reconcile_messaging,
                service.transactions.source.clone(),
                tx,
                &op.device,
            )
            .await?;
        }
        Ok(())
    }
    pub async fn apple_synchronized_in(
        &self,
        tx: &mut PgTransaction<'_>,
        p: &DevicePrincipal,
        id: Uuid,
        input_version: &str,
        user: &str,
        registration: Uuid,
        generation: i64,
    ) -> Result<()> {
        self.transactions.runtime.validate_transaction(tx)?;
        if registration != p.registration() || generation != p.generation() {
            return Err(Error::Unauthorized.into());
        }
        let op = storage::load(tx, &self.transactions.protection, id).await?;
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
        if eligible(&self.transactions, tx, p, &op).await? {
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
        self.transactions.runtime.validate_transaction(tx)?;
        let tenant = tx.tenant_id().to_string();
        let registration = p.registration();
        let generation = p.generation();
        tx.with_connection(move|c|Box::pin(async move{sqlx::query("UPDATE mdm_commands.operations SET dispatch_failure=$3,revision=revision+1 WHERE tenant_id=$1::uuid AND id=$2 AND registration=$4 AND registration_generation=$5 AND dispatch_failure IS NULL").bind(tenant).bind(id).bind(sqlx::types::Json(crate::DispatchFailure::Macos{reason})).bind(registration).bind(generation).execute(c).await?;Ok(())})).await?;
        Ok(())
    }
    pub async fn apple_declarations_in(
        &self,
        tx: &mut PgTransaction<'_>,
        p: &DevicePrincipal,
        user: &str,
        ids: Vec<Uuid>,
    ) -> Result<Vec<AppleAdmission>> {
        self.transactions.runtime.validate_transaction(tx)?;
        let now = storage::now(tx).await?;
        let mut output = Vec::new();
        for id in ids {
            let op = storage::load(tx, &self.transactions.protection, id).await?;
            let status = self.transactions.required_command(tx, &op).await?.status();
            if (status == dc::Status::Applied
                || (!status.is_terminal() && now < op.request.deadline))
                && op.registration == p.registration()
                && op.registration_generation == p.generation()
                && op.request.target.user_key() == user
                && storage::authority_decision(
                    &self.transactions.source,
                    &self.transactions.protection,
                    tx,
                    &op,
                    now,
                )
                .await?
                .is_authorized()
            {
                output.push(admission(self, op, true, false)?);
            }
        }
        Ok(output)
    }
    pub async fn apple_collection_eligible_on(
        &self,
        c: &mut sqlx::PgConnection,
        p: &DevicePrincipal,
        id: Uuid,
        delivery: bool,
    ) -> std::result::Result<bool, Error> {
        if delivery {
            actions::native_collection::delivery_eligible_on(
                self.transactions.source.as_ref(),
                c,
                p,
                id,
            )
            .await
        } else {
            actions::native_collection::eligible_on(self.transactions.source.as_ref(), c, p, id)
                .await
        }
    }
}
fn admission(
    s: &ExecutionService,
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
        target: apple_facts::AppleRegistration {
            tenant: s.transactions.tenant.to_string(),
            device: op.device,
            registration: op.registration,
            generation: op.registration_generation,
        },
        command: apple_facts::AppleCommand {
            recovery: s.transactions.recovery_credentials.clone(),
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
async fn complete_ddm(
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    op: &storage::Operation,
) -> Result<()> {
    if service
        .transactions
        .required_command(tx, op)
        .await?
        .status()
        == dc::Status::Published
    {
        let transition = service
            .transactions
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
        .transactions
        .store
        .report(
            tx,
            &dc::DeviceReport {
                scope: op.scope,
                command_id: op.command_id()?,
                coordinate: op.coordinate,
                event: dc::DeviceEvent::Reported(op.request.digest(
                    &service.transactions.protection,
                    service.transactions.tenant,
                    &op.device,
                )?),
            },
        )
        .await?;
    if transition.outcome == dc::Outcome::OutOfOrder {
        return Err(Error::Conflict.into());
    }
    crate::wake::wake_native_in(
        &service.transactions.reconcile_messaging,
        service.transactions.source.clone(),
        tx,
        &op.device,
    )
    .await?;
    Ok(())
}

pub struct WakePage {
    pub next: Option<Uuid>,
    pub commands: Vec<(Uuid, String)>,
}
impl ExecutionService {
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
            actions::native_recovery::lock_device(tx, &device).await?;
        }
        crate::transaction::prepare_audit_in(&self.transactions.audit_store, tx, audit, &[])
            .await
            .map_err(Into::into)
    }
    pub async fn apple_wake_commands_in(
        &self,
        tx: &mut PgTransaction<'_>,
        registration: Uuid,
        generation: i64,
        after: Uuid,
    ) -> Result<WakePage> {
        self.transactions.runtime.validate_transaction(tx)?;
        let tenant = tx.tenant_id().to_string();
        let ids:Vec<Uuid>=tx.with_connection(move|c|Box::pin(async move {
   sqlx::query_scalar("SELECT o.id FROM mdm_commands.operations o JOIN rss_device_command.commands d ON d.tenant_id=o.tenant_id AND d.command_id=o.id::text WHERE o.tenant_id=$1::uuid AND o.registration=$2 AND o.registration_generation=$3 AND o.gateway_accepted AND d.status IN ('published','received') AND (o.input_context->>'deadline')::bigint>extract(epoch FROM clock_timestamp()) AND o.input_context->>'platform'='macos' AND o.dispatch_failure IS NULL AND o.id>$4 ORDER BY o.id LIMIT 64")
    .bind(tenant).bind(registration).bind(generation).bind(after).fetch_all(c).await
  })).await?;
        let next = if ids.len() == 64 {
            ids.last().copied()
        } else {
            None
        };
        let now = storage::now(tx).await?;
        let mut commands = Vec::new();
        for id in ids {
            let op = storage::load(tx, &self.transactions.protection, id).await?;
            if storage::authority_decision(
                &self.transactions.source,
                &self.transactions.protection,
                tx,
                &op,
                now,
            )
            .await?
            .is_authorized()
            {
                commands.push((id, op.request.target.user_key().to_owned()));
            }
        }
        Ok(WakePage { next, commands })
    }
}
