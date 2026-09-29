use super::*;
use crate::{
    authorization::context::AuthorizedPrincipal,
    authorization::{ExecutionAuthority, Permission},
};
use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
use rss_mdm_audit_integration::Fact;
use rss_transactional_messaging::{message::*, outbox::PendingMessage};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub(super) fn target(tenant: TenantId, device: &str) -> rss_reconcile::Target {
    rss_reconcile::Target::new(
        recovery_scope(tenant),
        format!("{:x}", Sha256::digest(device.as_bytes())),
    )
    .expect("bounded digest")
}
impl ExecutionService {
    pub(super) async fn create(
        &self,
        proof: &AuthorizedPrincipal,
        device: &str,
        input: &Create,
        audit: &RequestAudit,
    ) -> std::result::Result<Value, Error> {
        proof.require(input.task.permission(), Some(device))?;
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
                            return Err(rejection(
                                Error::from(error).into(),
                                context.5,
                                crate::transaction::TransactionOwner::Execution,
                            ));
                        }
                        rss_reconcile_postgres::messaging::wake_in(
                            tx,
                            target,
                            context,
                            |ctx, tx| {
                                Box::pin(async move {
                                    let (service, proof, device, input, audit, failure) = **ctx;
                                    match service.create_in(tx, proof, device, input, audit).await {
                                        Ok(v) => {
                                            audit.mark_commit_started();
                                            Ok(v)
                                        }
                                        Err(e) => Err(rejection(
                                            e,
                                            failure,
                                            crate::transaction::TransactionOwner::Execution,
                                        )),
                                    }
                                })
                            },
                        )
                        .await
                    })
                },
            )
            .await;
        settle(
            attempt,
            audit,
            failure,
            crate::transaction::TransactionOwner::Execution,
        )
    }
    pub(super) async fn create_in(
        &self,
        tx: &mut PgTransaction<'_>,
        proof: &AuthorizedPrincipal,
        device: &str,
        input: &Create,
        audit: &RequestAudit,
    ) -> Result<Value> {
        storage::admit(tx).await?;
        require_tenant(self.tenant, proof)?;
        let auth = storage::authorized(tx, proof, device, input.task.permission()).await?;
        storage::lock(tx, &format!("request:{}", input.operation_id)).await?;
        storage::lock(tx, device).await?;
        let fingerprint = create_fingerprint(proof, device, input)?;
        if let Some(value) = replay(tx, input.operation_id, &fingerprint).await? {
            audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);
            let fact = Fact::business(
                audit,
                &format!("command:{0}:accept", input.operation_id),
                &fingerprint,
                202,
                "success",
                None,
            )?;
            self.audit_store.append_in(tx, &fact, true).await?;
            return Ok(value);
        }
        let approval =
            ExecutionAuthority::from_proof(&auth, proof, device, input.task.permission())?;
        let response = self
            .queue_authorized_in(tx, device, input, approval, fingerprint, audit)
            .await?;
        proof.check_live()?;
        Ok(response)
    }
    pub(super) async fn queue_authorized_in(
        &self,
        tx: &mut PgTransaction<'_>,
        device: &str,
        input: &Create,
        approval: ExecutionAuthority,
        fingerprint: Vec<u8>,
        audit: &RequestAudit,
    ) -> Result<Value> {
        let now = storage::now(tx).await?;
        input.validate(now)?;
        let (registration, registration_generation) =
            storage::current_registration(tx, device).await?;
        storage::require_source(tx, registration, input.task.source()).await?;
        let (scope, coordinate) =
            storage::authority(self, tx, device, registration, registration_generation).await?;
        let spec = dc::CommandSpec::new(
            scope,
            checked_input(dc::CommandId::parse(&input.operation_id.to_string()))?,
            coordinate,
            input.digest(&self.tenant.to_string(), device)?,
            input.deadline * 1_000_000,
        );
        let message = dispatch(self.tenant, device, input, coordinate, now)?;
        let dispatch_fingerprint = message.fingerprint().as_bytes().to_vec();
        self.store.queue(tx, spec, message).await?;
        let tenant = self.tenant.to_string();
        let name = device.to_owned();
        let id = input.operation_id.to_string();
        let request = checked_input(serde_json::to_string(input))?;
        let (source, policy_version, remote_operation) = match &approval {
            ExecutionAuthority::User { .. } => ("direct", None, None),
            ExecutionAuthority::Policy { version, .. } => ("policy", Some(*version), None),
            ExecutionAuthority::RemoteOperation { operation, .. } => {
                ("remote_operation", None, Some(*operation))
            }
        };
        let approval = checked_input(serde_json::to_string(&approval))?;
        let digest = fingerprint.clone();
        tx.with_connection(move|c|Box::pin(async move {sqlx::query("INSERT INTO mdm_commands.operations(tenant_id,id,device,request,fingerprint,registration,registration_generation,generation,epoch,approval,dispatch_fingerprint,source_kind,policy_version,remote_operation) VALUES($1::uuid,$2::uuid,$3,$4::jsonb,$5,$6::uuid,$7,$8,$9,$10::jsonb,$11,$12,$13,$14)").bind(tenant).bind(id).bind(name).bind(request).bind(digest).bind(registration.to_string()).bind(registration_generation).bind(coordinate.generation()).bind(coordinate.epoch()).bind(approval).bind(dispatch_fingerprint).bind(source).bind(policy_version).bind(remote_operation).execute(c).await?;Ok(())})).await?;
        apple::own(tx, device, registration, input).await?;
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
    pub(super) async fn read(
        &self,
        proof: &AuthorizedPrincipal,
        device: &str,
        id: Uuid,
        audit: &RequestAudit,
    ) -> std::result::Result<Value, Error> {
        crate::transaction::run(&self.audit_store,&self.runtime,self.tenant,audit,(self,proof,device,id,audit),|ctx,tx|Box::pin(async move {
            let (service,proof,device,id,audit) = *ctx;
            storage::authorized(tx,proof,device,Permission::OperationRead).await?;
            let op=storage::load(tx,id).await?;
            if op.device!=device{return Err(Error::Forbidden.into());}
            let command=service.required_command(tx,&op).await?;
            let now=storage::now(tx).await?;let approved=storage::approval_valid(tx,&op,now).await?;
            let observation=protocol::observation(tx,&op,command.status()).await?;
            service.audit_store.append_request_in(tx,audit,200,"success").await?;
            Ok(json!({"operationId":op.id,"commandId":op.id,"revision":op.revision,"task":op.request.task,"deadline":op.request.deadline,"authorization":if approved{"approved"}else{"blocked"},"commandStatus":status(command.status()),"observation":observation}))
        }),crate::transaction::TransactionOwner::Execution).await
    }
    pub(super) async fn change(
        &self,
        proof: &AuthorizedPrincipal,
        device: &str,
        id: Uuid,
        change: &Change,
        approve: bool,
        audit: &RequestAudit,
    ) -> std::result::Result<Value, Error> {
        if change.request_id.is_nil() || change.expected_revision < 1 {
            return Err(Error::Malformed);
        }
        crate::transaction::run(&self.audit_store,&self.runtime,self.tenant,audit,(self,proof,device,id,change,approve,audit),|ctx,tx|Box::pin(async move {
            let (service,proof,device,id,change,approve,audit) = *ctx;
            let op=storage::load(tx,id).await?;
            let permission=if approve {op.request.task.permission()}else{Permission::OperationCancel};
            let auth=storage::authorized(tx,proof,device,permission).await?;
            storage::lock(tx,&format!("request:{}",change.request_id)).await?;storage::lock(tx,device).await?;
            let fingerprint=Sha256::digest(checked_input(serde_json::to_vec(&("mdm.command-change/v2",proof.user(),device,id,change,approve)))?).to_vec();
            let event_key = format!("command-change:{}", change.request_id);
            if let Some(value)=replay(tx,change.request_id,&fingerprint).await? {audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);let fact = Fact::business(audit, &event_key, &fingerprint, 200, "success", None)?; service.audit_store.append_in(tx, &fact, true).await?;return Ok(value);}
            let op=storage::load(tx,id).await?;
            if op.device!=device{return Err(Error::Forbidden.into());}
            if op.revision!=change.expected_revision{return Err(Error::Conflict.into());}
            let command=service.required_command(tx,&op).await?;
            let now=storage::now(tx).await?;
            if command.status().is_terminal() || now>=op.request.deadline {return Err(Error::Conflict.into());}
            let approval=if approve {
                if !matches!(op.approval,ExecutionAuthority::User {..}) {return Err(Error::Conflict.into());}
                if storage::current_registration(tx,device).await? != (op.registration,op.registration_generation) {return Err(Error::Conflict.into());}
                ExecutionAuthority::from_proof(&auth,proof,device,op.request.task.permission())?
            } else {
                let transition=service.store.cancel(tx,op.scope,&op.command_id()?,op.coordinate).await?;
                if transition.outcome==dc::Outcome::OutOfOrder {return Err(Error::Conflict.into());}
                op.approval
            };
            let approval=checked_input(serde_json::to_string(&approval))?;let tenant=service.tenant.to_string();let operation_key=id.to_string();
            tx.with_connection(move|c|Box::pin(async move {sqlx::query("UPDATE mdm_commands.operations SET approval=$3::jsonb,revision=revision+1 WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(tenant).bind(operation_key).bind(approval).execute(c).await?;Ok(())})).await?;
            crate::worker_wake::notify_in(tx, crate::worker_wake::Work::CommandRecovery).await?;
            crate::worker_wake::notify_in(tx, crate::worker_wake::Work::Apple).await?;
            let result=json!({"operationId":id,"revision":op.revision+1});
            let fact = Fact::business(audit, &event_key, &fingerprint, 200, "success", None)?; service.audit_store.append_in(tx, &fact, false).await?;receipt(tx,change.request_id,id,fingerprint,&result).await?;proof.check_live()?;Ok(result)
        }),crate::transaction::TransactionOwner::Execution).await
    }
}
async fn replay(tx: &mut PgTransaction<'_>, id: Uuid, fingerprint: &[u8]) -> Result<Option<Value>> {
    let tenant = tx.tenant_id().to_string();
    let old = tx
        .with_connection(move |c| Box::pin(async move { storage::read_on(c, &tenant, id).await }))
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
) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    let response = value.to_string();
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO mdm_commands.requests(tenant_id,id,operation,fingerprint,response) VALUES($1::uuid,$2::uuid,$3::uuid,$4,$5::jsonb)",
            )
            .bind(tenant)
            .bind(id.to_string())
            .bind(operation.to_string())
            .bind(fingerprint)
            .bind(response)
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
    let payload = checked_input(serde_json::to_vec(&DispatchV2 {
        device: device.into(),
        request: input.clone(),
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
                    checked_input(ContractVersion::from_major(2))?,
                    checked_input(SchemaDigest::parse(&format!(
                        "sha256:{:x}",
                        Sha256::digest(include_bytes!("dispatch-v2.json"))
                    )))?,
                ),
            ),
            MessageMetadataExtensions::default(),
        ),
        payload,
    )))
}
pub(super) fn status(status: dc::Status) -> &'static str {
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
    proof: &AuthorizedPrincipal,
    device: &str,
    input: &Create,
) -> Result<Vec<u8>> {
    Ok(Sha256::digest(checked_input(serde_json::to_vec(&(
        "mdm.command-create/v2",
        proof.user(),
        device,
        input,
    )))?)
    .to_vec())
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
        &format!("command:{id}:accept"),
        &fingerprint,
        202,
        "success",
        None,
    )?;
    store.append_in(tx, &fact, false).await?;
    receipt(tx, id, id, fingerprint, &response).await?;
    Ok(response)
}
