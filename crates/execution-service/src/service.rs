use super::*;
use crate::{
    authority::ExecutionAuthority, authorization::Permission,
    authorization::context::AuthorizedPrincipal,
};
use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
use rss_mdm_audit_integration::Fact;
use rss_transactional_messaging::{message::*, outbox::PendingMessage};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub fn target(tenant: TenantId, device: &str) -> rss_reconcile::Target {
    rss_reconcile::Target::new(
        recovery_scope(tenant),
        format!("{:x}", Sha256::digest(device.as_bytes())),
    )
    .expect("bounded digest")
}
impl ExecutionService {
    pub async fn create_control(
        &self,
        proof: &AuthorizedPrincipal,
        device: &str,
        input: &crate::device_control::Input,
        audit: &RequestAudit,
    ) -> std::result::Result<Value, Error> {
        input.action.confirmation()?;
        proof.require(input.action.kind().permission(), Some(device))?;
        let failure = Mutex::new(None);
        let timer = recovery::Timer::new();
        let cancel = tokio_util::sync::CancellationToken::new();
        let control = rss_reconcile::Control::new(&timer, Duration::from_secs(6), &cancel);
        let attempt = self
            .runtime
            .local_tx_with_context(
                self.tenant,
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                    control.remaining(),
                ),
                (
                    self,
                    target(self.tenant, device).clone(),
                    (self, proof, device, input, audit, &failure),
                ),
                |(service, target, context), tx| {
                    Box::pin(async move {
                        if let Err(error) = service.audit_store.lock_in(tx).await {
                            return Err(rejection(Error::from(error).into(), context.5));
                        }
                        rss_reconcile_postgres::messaging::wake_in(
                            tx,
                            target,
                            context,
                            |ctx, tx| {
                                Box::pin(async move {
                                    let (service, proof, device, input, audit, failure) = **ctx;
                                    match service
                                        .create_control_in(tx, proof, device, input, audit)
                                        .await
                                    {
                                        Ok(v) => {
                                            audit.mark_commit_started();
                                            Ok(v)
                                        }
                                        Err(e) => Err(rejection(e, failure)),
                                    }
                                })
                            },
                        )
                        .await
                    })
                },
            )
            .await;
        settle(attempt, audit, failure)
    }
    async fn create_control_in(
        &self,
        tx: &mut PgTransaction<'_>,
        proof: &AuthorizedPrincipal,
        device: &str,
        input: &crate::device_control::Input,
        audit: &RequestAudit,
    ) -> Result<Value> {
        storage::admit(tx).await?;
        require_tenant(self.tenant, proof)?;
        let action = input.action.kind();
        let auth = storage::authorized_native(tx, proof, device, &[action.permission()]).await?;
        storage::lock(tx, &format!("request:{}", input.operation_id)).await?;
        storage::lock(tx, device).await?;
        let fingerprint = create_fingerprint(self, proof, device, input)?;
        if let Some(value) = replay(tx, input.operation_id, &fingerprint, audit).await? {
            audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);
            let fact = Fact::business(
                audit,
                &format!(
                    "command:{}:{}:accept",
                    audit.snapshot().actor.ok_or(Error::Malformed)?,
                    input.operation_id
                ),
                &fingerprint,
                202,
                "success",
                None,
            )?;
            self.audit_store.append_in(tx, &fact, true).await?;
            return Ok(value);
        }
        input.validate(self.store.now(tx).await? / 1_000_000)?;
        let (registration, generation) = storage::current_registration(
            tx,
            device,
            rss_mdm_registration_service::Purpose::Primary,
        )
        .await?;
        let confirmation = input.action.confirmation()?;
        if let Some(confirmation) = confirmation {
            confirmation.check(registration, generation)?;
        }
        let tenant = self.tenant.to_string();
        let sources = tx.with_connection(move |c| Box::pin(async move {
            sqlx::query_scalar::<_, String>("SELECT source FROM mdm_access.report_sources WHERE tenant_id=$1::uuid AND registration=$2 AND enabled AND source IN('mdm.apple','mdm.windows') ORDER BY source")
                .bind(tenant).bind(registration).fetch_all(c).await
        })).await?;
        let source = match sources.as_slice() {
            [source] if source == "mdm.apple" => rss_mdm_inventory::ReportSource::MdmApple,
            [source] if source == "mdm.windows" => rss_mdm_inventory::ReportSource::MdmWindows,
            _ => return Err(Error::Unsupported.into()),
        };
        let native = input.native(source)?;
        self.validate_control_in(tx, device, registration, generation, &native, action)
            .await?;
        let approval = ExecutionAuthority::for_control(&auth, proof, device, action, confirmation)?;
        let response = self
            .queue_authorized_in(tx, device, &native, approval, fingerprint, audit)
            .await?;
        proof.check_live()?;
        Ok(response)
    }
    pub async fn queue_authorized_in(
        &self,
        tx: &mut PgTransaction<'_>,
        device: &str,
        input: &Create,
        mut approval: ExecutionAuthority,
        fingerprint: Vec<u8>,
        audit: &RequestAudit,
    ) -> Result<Value> {
        if approval.retired() {
            return Err(Error::Unsupported.into());
        }
        let now = self.store.now(tx).await? / 1_000_000;
        input.validate(now)?;
        let diagnostic_progress = if let Some(log) = crate::native::diagnostic::input(&input.task) {
            let content = self.content.as_ref().ok_or(Error::Unsupported)?;
            Some(checked_input(serde_json::to_value(
                crate::native::diagnostic::State::new(log, &content.config),
            ))?)
        } else {
            None
        };
        if input
            .task
            .permissions()?
            .contains(&Permission::SoftwareDeploy)
        {
            if let Some(package) = approval.agent_package() {
                if input.target != NativeTarget::Device
                    || checked_input(serde_json::to_vec(&input.task))?
                        != checked_input(serde_json::to_vec(
                            &package.native_task(input.operation_id)?,
                        ))?
                {
                    return Err(Error::Unsupported.into());
                }
            } else if !matches!(input.task, Task::Macos { .. }) {
                return Err(Error::Unsupported.into());
            }
        }
        let (registration, registration_generation) =
            storage::current_registration(tx, device, input.task.purpose()?).await?;
        if matches!(approval, ExecutionAuthority::DeviceControl { .. })
            && !approval.control_matches(input, registration, registration_generation)?
        {
            return Err(Error::Unsupported.into());
        }
        if input.task.purpose()? == rss_mdm_registration_service::Purpose::Primary {
            storage::require_source(tx, registration, input.task.source()).await?;
        }
        if matches!(input.task, Task::Windows { .. })
            && matches!(input.target, NativeTarget::User { .. })
        {
            let tenant = self.tenant.to_string();
            let target = input.target.clone();
            let allowed = tx.with_connection(move |c| Box::pin(async move {
                let (profile, context): (Option<String>, Uuid) = sqlx::query_as("SELECT q.windows_profile,coalesce(r.parent_id,r.id) FROM mdm_access.registrations r JOIN mdm_access.requests q ON(q.tenant_id,q.id)=(r.tenant_id,r.request_id) WHERE r.tenant_id=$1::uuid AND r.id=$2 AND r.generation=$3 AND r.state='active'")
                    .bind(tenant).bind(registration).bind(registration_generation).fetch_one(c).await?;
                Ok(target.matches_windows_context((profile.as_deref()==Some("Full")).then_some(context)))
            })).await?;
            if !allowed {
                return Err(Error::Forbidden.into());
            }
        }
        let (scope, coordinate) =
            storage::authority(self, tx, device, registration, registration_generation).await?;
        let spec = dc::CommandSpec::new(
            scope,
            checked_input(dc::CommandId::parse(&input.operation_id.to_string()))?,
            coordinate,
            input.digest(&self.protection, self.tenant, device)?,
            input.deadline * 1_000_000,
        );
        let message = dispatch(self.tenant, device, input, coordinate, now)?;
        let dispatch_fingerprint = message.fingerprint().as_bytes().to_vec();
        self.store.queue(tx, spec, message).await?;
        let tenant = self.tenant.to_string();
        let name = device.to_owned();
        let id = input.operation_id.to_string();
        let (input_context, request) = super::input_storage::seal(
            &self.protection,
            self.tenant,
            &super::input_storage::Identity {
                operation: input.operation_id,
                device,
                registration,
                generation: registration_generation,
            },
            input,
        )?;
        let required = apple::required(
            tx,
            &self.protection,
            self.apple_profiles.clone(),
            device,
            input,
            Some(approval.apple_owner(input.operation_id)?),
        )
        .await?;
        approval.bind_required(required.clone());
        if required != input.task.permissions()? {
            let check = approval.clone();
            let key = self.protection.clone();
            let source = self.source.clone();
            if !tx
                .with_connection(move |c| {
                    Box::pin(async move {
                        Ok(check.valid(source.as_ref(), c, &key, &required, now).await)
                    })
                })
                .await??
            {
                return Err(Error::Forbidden.into());
            }
        }
        let (source, policy_version, remote_operation): (&str, Option<Uuid>, Option<Uuid>) =
            match &approval {
                ExecutionAuthority::DeviceControl { .. } => ("direct", None, None),
                ExecutionAuthority::AgentInstall { version, .. }
                | ExecutionAuthority::Policy { version, .. } => ("policy", Some(*version), None),
                ExecutionAuthority::User { .. } | ExecutionAuthority::RemoteOperation { .. } => {
                    return Err(Error::Unsupported.into());
                }
            };
        let approval = checked_input(serde_json::to_string(&approval))?;
        let digest = fingerprint.clone();
        tx.with_connection(move|c|Box::pin(async move {sqlx::query("INSERT INTO mdm_commands.operations(tenant_id,id,device,request,fingerprint,registration,registration_generation,generation,epoch,approval,dispatch_fingerprint,source_kind,policy_version,remote_operation,input_context,diagnostic_progress) VALUES($1::uuid,$2::uuid,$3,$4,$5,$6::uuid,$7,$8,$9,$10::jsonb,$11,$12,$13,$14,$15,$16)").bind(tenant).bind(id).bind(name).bind(request).bind(digest).bind(registration.to_string()).bind(registration_generation).bind(coordinate.generation()).bind(coordinate.epoch()).bind(approval).bind(dispatch_fingerprint).bind(source).bind(policy_version).bind(remote_operation).bind(input_context).bind(diagnostic_progress).execute(c).await?;Ok(())})).await?;
        apple::own(
            tx,
            self.apple_profiles.clone(),
            device,
            registration,
            registration_generation,
            input,
        )
        .await?;
        let response = created(
            tx,
            &self.audit_store,
            audit,
            input.operation_id,
            fingerprint,
        )
        .await?;
        crate::worker_wake::notify_in(tx, crate::worker_wake::Work::CommandRelay).await?;
        crate::worker_wake::notify_in(tx, crate::worker_wake::Work::CommandRecovery).await?;
        Ok(response)
    }
    pub async fn change(
        &self,
        proof: &AuthorizedPrincipal,
        device: &str,
        id: Uuid,
        change: &Change,
        control_approval: Option<&crate::device_control::Approval>,
        audit: &RequestAudit,
    ) -> std::result::Result<Value, Error> {
        if change.request_id.is_nil() || change.expected_revision < 1 {
            return Err(Error::Malformed);
        }
        crate::transaction::run(&self.audit_store,&self.runtime,self.tenant,audit,(self,proof,device,id,change,control_approval,audit),|ctx,tx|Box::pin(async move {
            let (service,proof,device,id,change,control_approval,audit) = *ctx;
            let approve = control_approval.is_some();
            let op=storage::load(tx,&service.protection,id).await?;
            if op.device != device { return Err(Error::Forbidden.into()); }
            if !matches!(op.approval, ExecutionAuthority::DeviceControl { .. } | ExecutionAuthority::User { .. }) {
                return Err(Error::Conflict.into());
            }
            if let Some(input) = control_approval {
                let ExecutionAuthority::DeviceControl { action, confirmation, .. } = &op.approval else { return Err(Error::Conflict.into()) };
                if !op.approval.control_matches(&op.request, op.registration, op.registration_generation)? { return Err(Error::Conflict.into()); }
                if input.registration()? != *confirmation { return Err(Error::Conflict.into()); }
                service.validate_control_in(tx, device, op.registration, op.registration_generation, &op.request, *action).await?;
            }
            let permissions=if approve {op.approval.required().to_vec()}else{vec![Permission::OperationCancel]};
            let auth=storage::authorized_native(tx,proof,device,&permissions).await?;
            storage::lock(tx,&format!("request:{}",change.request_id)).await?;storage::lock(tx,device).await?;
            let fingerprint=Sha256::digest(checked_input(serde_json::to_vec(&("mdm.command-change/v4",proof.user(),device,id,change,control_approval)))?).to_vec();
            let event_key = format!("command-change:{}:{}", audit.snapshot().actor.ok_or(Error::Malformed)?, change.request_id);
            if let Some(value)=replay(tx,change.request_id,&fingerprint,audit).await? {audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);let fact = Fact::business(audit, &event_key, &fingerprint, 200, "success", None)?; service.audit_store.append_in(tx, &fact, true).await?;return Ok(value);}
            let op=storage::load(tx,&service.protection,id).await?;
            if op.device!=device{return Err(Error::Forbidden.into());}
            if op.revision!=change.expected_revision{return Err(Error::Conflict.into());}
            let command=service.required_command(tx,&op).await?;
            let now=storage::now(tx).await?;
            let mut diagnostic = if native::diagnostic::input(&op.request.task).is_some() {
                let tenant=service.tenant;let id=op.id;
                Some(tx.with_connection(move|c|Box::pin(async move {Ok(native::diagnostic::load(c,tenant,id).await)})).await??)
            } else {None};
            let cancel_pending = !approve && diagnostic.as_ref().is_some_and(native::diagnostic::State::pending);
            if (command.status().is_terminal() && !cancel_pending) || now>=op.request.deadline {return Err(Error::Conflict.into());}
            let approval=if approve {
                let ExecutionAuthority::DeviceControl { action, confirmation, .. } = &op.approval else {return Err(Error::Conflict.into());};
                if storage::current_registration(tx,device,op.request.task.purpose()?).await? != (op.registration,op.registration_generation) {return Err(Error::Conflict.into());}
                ExecutionAuthority::for_control(&auth,proof,device,*action,*confirmation)?
            } else {
                if cancel_pending {
                    let state=diagnostic.as_mut().expect("pending diagnostic");
                    state.transfer=native::diagnostic::Transfer::Abandoned;
                    state.reason=Some("diagnostic_cancelled".into());
                }
                // A completed device output remains Applied; cancellation stops only its pending transfer.
                if !command.status().is_terminal() {
                    let transition=service.store.cancel(tx,op.scope,&op.command_id()?,op.coordinate).await?;
                    if transition.outcome==dc::Outcome::OutOfOrder {return Err(Error::Conflict.into());}
                }
                op.approval
            };
            let approval=checked_input(serde_json::to_string(&approval))?;let tenant=service.tenant.to_string();let operation_key=id.to_string();
            let diagnostic=diagnostic.map(|state|checked_input(serde_json::to_value(state))).transpose()?;
            tx.with_connection(move|c|Box::pin(async move {sqlx::query("UPDATE mdm_commands.operations SET approval=$3::jsonb,diagnostic_progress=coalesce($4::jsonb,diagnostic_progress),revision=revision+1 WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(tenant).bind(operation_key).bind(approval).bind(diagnostic).execute(c).await?;Ok(())})).await?;
            crate::worker_wake::notify_in(tx, crate::worker_wake::Work::CommandRecovery).await?;
            crate::worker_wake::notify_in(tx, crate::worker_wake::Work::Apple).await?;
            let result=json!({"operationId":id,"revision":op.revision+1});
            let fact = Fact::business(audit, &event_key, &fingerprint, 200, "success", None)?;
            service.audit_store.append_in(tx, &fact, false).await?;receipt(tx,change.request_id,id,fingerprint,&result,audit).await?;proof.check_live()?;Ok(result)
        })).await
    }
}
async fn replay(
    tx: &mut PgTransaction<'_>,
    id: Uuid,
    fingerprint: &[u8],
    audit: &RequestAudit,
) -> Result<Option<Value>> {
    let tenant = tx.tenant_id().to_string();
    let actor = audit.snapshot().actor.ok_or(Error::Malformed)?;
    let old = tx
        .with_connection(move |c| {
            Box::pin(async move { storage::read_on(c, &tenant, id, &actor).await })
        })
        .await?;
    match old {
        Some((digest, value)) if digest == fingerprint => Ok(Some(value)),
        Some(_) => Err(Error::Conflict.into()),
        None => Ok(None),
    }
}
async fn receipt(
    tx: &mut PgTransaction<'_>,
    id: Uuid,
    operation: Uuid,
    fingerprint: Vec<u8>,
    value: &Value,
    audit: &RequestAudit,
) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    let response = value.to_string();
    let actor = audit.snapshot().actor.ok_or(Error::Malformed)?;
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO mdm_commands.requests(tenant_id,id,operation,fingerprint,response,actor) VALUES($1::uuid,$2::uuid,$3::uuid,$4,$5::jsonb,$6)",
            )
            .bind(tenant)
            .bind(id.to_string())
            .bind(operation.to_string())
            .bind(fingerprint)
            .bind(response).bind(actor)
            .execute(c)
            .await?;
            Ok(())
        })
    })
    .await?;
    Ok(())
}
fn dispatch(
    tenant: TenantId,
    device: &str,
    input: &Create,
    coordinate: dc::Coordinate,
    now: i64,
) -> Result<PendingMessage<Vec<u8>>> {
    let payload = checked_input(serde_json::to_vec(&DispatchV3 {
        device: device.into(),
        operation_id: input.operation_id,
        generation: coordinate.generation(),
        epoch: coordinate.epoch(),
    }))?;
    Ok(PendingMessage::new(MessageEnvelope::new(
        checked_input(MessageId::parse(&format!(
            "dispatch.{}",
            input.operation_id
        )))?,
        MessageMetadata::new(
            AuthoredMessageMetadata::new(
                tenant,
                checked_input(Timepoint::try_from(now))?,
                messaging_domain(),
                checked_input(MessageRoute::parse("device.command"))?,
                ContractIdentity::new(
                    checked_input(ContractId::parse("mdm.command-dispatch"))?,
                    checked_input(ContractVersion::from_major(3))?,
                    checked_input(SchemaDigest::parse(&format!(
                        "sha256:{:x}",
                        Sha256::digest(include_bytes!("dispatch-v3.json"))
                    )))?,
                ),
            ),
            MessageMetadataExtensions::default(),
        ),
        payload,
    )))
}
pub fn status(status: dc::Status) -> &'static str {
    match status {
        dc::Status::Queued => "queued",
        dc::Status::Published => "published",
        dc::Status::Received => "received",
        dc::Status::Applied => "applied",
        dc::Status::Rejected => "rejected",
        dc::Status::TimedOut => "timed_out",
        dc::Status::Superseded => "superseded",
        dc::Status::Cancelled => "cancelled",
    }
}

fn create_fingerprint(
    service: &ExecutionService,
    proof: &AuthorizedPrincipal,
    device: &str,
    input: &crate::device_control::Input,
) -> Result<Vec<u8>> {
    Ok(crate::protection::fingerprint(
        &service.protection,
        service.tenant,
        device,
        "device-control-create/v1",
        &(proof.user(), input),
    )?)
}

fn require_tenant(
    tenant: rss_request_context::TenantId,
    proof: &AuthorizedPrincipal,
) -> Result<()> {
    if proof.tenant_id() != tenant.to_string() {
        return Err(Error::Forbidden.into());
    }
    Ok(())
}

async fn created(
    tx: &mut PgTransaction<'_>,
    store: &rss_mdm_audit_integration::AuditStore,
    audit: &RequestAudit,
    id: Uuid,
    fingerprint: Vec<u8>,
) -> Result<Value> {
    let response = json!({"operationId":id,"commandId":id,"revision":1,"accepted":true});
    let fact = Fact::business(
        audit,
        &format!(
            "command:{}:{id}:accept",
            audit.snapshot().actor.ok_or(Error::Malformed)?
        ),
        &fingerprint,
        202,
        "success",
        None,
    )?;
    store.append_in(tx, &fact, false).await?;
    receipt(tx, id, id, fingerprint, &response, audit).await?;
    Ok(response)
}

impl ExecutionService {
    /// Reconcile the accepted command under the same audited execution owner.
    #[cfg(feature = "integration")]
    pub async fn recover_operation(
        &self,
        id: Uuid,
        audit: &RequestAudit,
    ) -> std::result::Result<(), Error> {
        crate::transaction::run(
            &self.audit_store,
            &self.runtime,
            self.tenant,
            audit,
            (self, id),
            |ctx, tx| {
                Box::pin(async move {
                    let (service, id) = *ctx;
                    let operation = storage::load(tx, &service.protection, id).await?;
                    let _page = service
                        .store
                        .recover(
                            tx,
                            operation.scope,
                            dc::BatchLimit::new(64).expect("fixed bounded page"),
                            None,
                        )
                        .await?;
                    Ok(())
                })
            },
        )
        .await
    }
}
