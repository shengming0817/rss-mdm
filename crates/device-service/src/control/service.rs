use super::*;
use crate::control::{
    authority::Authority, authorization::Permission, authorization::context::AuthorizedPrincipal,
};
use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
use rss_mdm_audit_integration::Fact;
use rss_transactional_messaging::{message::*, outbox::PendingMessage};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub fn target(tenant: TenantId, device: &str) -> rss_reconcile::Target {
    rss_reconcile::Target::new(
        recovery_scope(tenant),
        format!("{:x}", Sha256::digest(device.as_bytes())),
    )
    .expect("bounded digest")
}
impl Service {
    pub async fn create_control(
        &self,
        proof: &AuthorizedPrincipal,
        device: &str,
        input: &crate::control::device_control::Input,
        audit: &RequestAudit,
    ) -> std::result::Result<AcceptedReceipt, Error> {
        input.action.confirmation()?;
        proof.require(input.action.kind().permission(), Some(device))?;
        crate::control::transaction::run(
            &self.transactions.audit_store,
            &self.transactions.runtime,
            self.transactions.tenant,
            audit,
            (self, proof, device, input, audit),
            |ctx, tx| {
                Box::pin(async move {
                    ctx.0
                        .create_control_in(tx, ctx.1, ctx.2, ctx.3, ctx.4)
                        .await
                })
            },
        )
        .await
    }
    async fn create_control_in(
        &self,
        tx: &mut PgTransaction<'_>,
        proof: &AuthorizedPrincipal,
        device: &str,
        input: &crate::control::device_control::Input,
        audit: &RequestAudit,
    ) -> Result<AcceptedReceipt> {
        require_tenant(self.transactions.tenant, proof)?;

        let action = input.action.kind();
        let auth = storage::authorized_native(tx, proof, device, &[action.permission()]).await?;
        storage::lock_request(tx, input.operation_id).await?;
        actions::run_recovery::lock_device(tx, device).await?;
        crate::control::transaction::prepare_audit_in(
            &self.transactions.audit_store,
            tx,
            audit,
            &[],
        )
        .await?;
        let fingerprint = create_fingerprint(self, proof, device, input)?;
        if let Some(value) = replay(tx, input.operation_id, &fingerprint, audit).await? {
            audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);

            return stored(serde_json::from_value(value));
        }
        reject_existing_operation(tx, input.operation_id).await?;
        input.validate(self.transactions.store.now(tx).await? / 1_000_000)?;
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
        let tenant = self.transactions.tenant;
        let source = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    Ok(crate::control::device_control::source_on(c, tenant, registration).await)
                })
            })
            .await??
            .ok_or(Error::Conflict)?;
        if let crate::control::device_control::Action::Lock { pin, .. } = &input.action
            && source == rss_mdm_inventory::ReportSource::MdmApple
        {
            let custody = self
                .transactions
                .lock_pins
                .as_ref()
                .ok_or(Error::Unsupported)?
                .clone();
            let tenant = Uuid::parse_str(&self.transactions.tenant.to_string())
                .map_err(|_| Error::Malformed)?;
            let device = device.to_owned();
            let operation = input.operation_id;
            let pin = zeroize::Zeroizing::new(pin.clone());
            tx.with_connection(move |c| {
                Box::pin(async move {
                    Ok(custody
                        .hold_in(
                            c,
                            tenant,
                            &Target {
                                device,
                                registration,
                                generation,
                            },
                            operation,
                            &pin,
                        )
                        .await)
                })
            })
            .await??;
        }
        let native = input.native(source)?;
        self.validate_control_in(tx, device, registration, generation, &native, action)
            .await?;
        let authority = Authority::for_control(&auth, proof, device, action, confirmation)?;
        let response = self
            .transactions
            .queue_authorized_in(tx, device, &native, authority, fingerprint, audit)
            .await?;
        proof.check_live()?;
        Ok(response)
    }

    pub async fn change(
        &self,
        proof: &AuthorizedPrincipal,
        device: &str,
        id: Uuid,
        change: &Change,
        reauthorization: Option<&crate::control::device_control::Reauthorization>,
        audit: &RequestAudit,
    ) -> std::result::Result<ChangedReceipt, Error> {
        if change.request_id.is_nil() || change.expected_revision < 1 {
            return Err(Error::Malformed);
        }
        crate::control::transaction::run(&self.transactions.audit_store,&self.transactions.runtime,self.transactions.tenant,audit,(self,proof,device,id,change,reauthorization,audit),|ctx,tx|Box::pin(async move {
            let (service,proof,device,id,change,reauthorization,audit) = *ctx;

            let reauthorize = reauthorization.is_some();
            let op=storage::load(tx,&service.transactions.protection,id).await?;
            if op.device != device { return Err(Error::Forbidden.into()); }
            if !matches!(op.authority, Authority::DeviceControl { .. }) {
                return Err(Error::Conflict.into());
            }
            if let Some(input) = reauthorization {
                let Authority::DeviceControl { action, confirmation, .. } = &op.authority else { return Err(Error::Conflict.into()) };
                if !op.authority.control_matches(&op.request, op.registration, op.registration_generation)? { return Err(Error::Conflict.into()); }
                if input.registration()? != *confirmation { return Err(Error::Conflict.into()); }
                service.validate_control_in(tx, device, op.registration, op.registration_generation, &op.request, *action).await?;
            }
            let permissions=if reauthorize {op.authority.required().to_vec()}else{vec![Permission::OperationCancel]};
            let auth=storage::authorized_native(tx,proof,device,&permissions).await?;
            storage::lock_request(tx, change.request_id).await?;actions::run_recovery::lock_device(tx,device).await?;
            crate::control::transaction::prepare_audit_in(&service.transactions.audit_store,tx,audit,&[]).await?;
            let fingerprint=Sha256::digest(checked_input(serde_json::to_vec(&("mdm.command-change/v1",proof.actor(),device,id,change,reauthorization)))?).to_vec();
            let event_key = format!("command-change:{}:{}", audit.snapshot().actor.ok_or(Error::Malformed)?, change.request_id);
            if let Some(value)=replay(tx,change.request_id,&fingerprint,audit).await? {audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed); return stored(serde_json::from_value(value));}
            let op=storage::load(tx,&service.transactions.protection,id).await?;
            if op.device!=device{return Err(Error::Forbidden.into());}
            if op.revision!=change.expected_revision{return Err(Error::Conflict.into());}
            let command=service.transactions.required_command(tx,&op).await?;
            let now=storage::now(tx).await?;
            if command.status().is_terminal() || (reauthorize && command.status() == dc::Status::Received) || now>=op.request.deadline {return Err(Error::Conflict.into());}
            let authority=if reauthorize {
                let Authority::DeviceControl { action, confirmation, .. } = &op.authority else {return Err(Error::Conflict.into());};
                let registration=storage::current_registration(tx,device,op.request.task.purpose()?).await?;
                let eligibility=crate::control::authorization_decision::reauthorization(&op,command.status(),now,Some(registration),true,true)?;
                if !matches!(eligibility,crate::control::authorization_decision::Reauthorization::Available {..}) {return Err(Error::Conflict.into());}
                Authority::for_control(&auth,proof,device,*action,*confirmation)?
            } else {
                if !command.status().is_terminal() {
                    let transition=service.transactions.store.cancel(tx,op.scope,&op.command_id()?,op.coordinate).await?;
                    if transition.outcome==dc::Outcome::OutOfOrder {return Err(Error::Conflict.into());}
                }
                op.authority
            };
            let authority=checked_input(serde_json::to_string(&authority))?;let tenant=service.transactions.tenant.to_string();let operation_key=id.to_string();
            tx.with_connection(move|c|Box::pin(async move {sqlx::query("UPDATE mdm_devices.control_operations SET authority=$3::jsonb,revision=revision+1 WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(tenant).bind(operation_key).bind(authority).execute(c).await?;Ok(())})).await?;
            crate::control::worker_wake::notify_in(tx, crate::control::worker_wake::Work::CommandRecovery).await?;
            crate::control::worker_wake::notify_in(tx, crate::control::worker_wake::Work::Apple).await?;
            let result=ChangedReceipt {operation_id:id,revision:op.revision+1};
            let current=storage::load(tx,&service.transactions.protection,id).await?;
            if matches!(&current.request.task, crate::control::Task::Windows { .. }) {
                crate::control::worker_wake::notify_in(tx, crate::control::worker_wake::Work::WindowsPush).await?;
            }
            let command=service.transactions.required_command(tx,&current).await?;
            let mut activity=crate::control::timeline::native_activity(&current,command.status(),rss_mdm_audit_integration::activity::ActivityPhase::Changed);
            activity.links.request=Some(change.request_id);
            let fact = Fact::business(audit, rss_mdm_audit_integration::operation::OperationOwner::DeviceControlRequest, &event_key, 200, "success", None)?.with_activity(&activity)?;
            service.transactions.audit_store.append_in(tx, &fact).await?;receipt(tx,change.request_id,id,fingerprint,&result,audit).await?;proof.check_live()?;Ok(result)
        })).await
    }
}
pub(crate) async fn replay(
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
        Some(value)
            if value.fingerprint == fingerprint
                && value.instance.map(|v| v.to_string()) == audit.snapshot().instance =>
        {
            Ok(Some(value.response))
        }
        Some(_) => Err(Error::Conflict.into()),
        None => Ok(None),
    }
}
async fn receipt<T: serde::Serialize + ?Sized>(
    tx: &mut PgTransaction<'_>,
    id: Uuid,
    operation: Uuid,
    fingerprint: Vec<u8>,
    value: &T,
    audit: &RequestAudit,
) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    let response = stored(serde_json::to_string(value))?;
    let actor = audit.snapshot().actor.ok_or(Error::Malformed)?;
    let instance = audit.snapshot().instance;
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO mdm_devices.control_requests(tenant_id,id,operation,fingerprint,response,actor,instance) VALUES($1::uuid,$2::uuid,$3::uuid,$4,$5::jsonb,$6,$7::uuid)",
            )
            .bind(tenant)
            .bind(id.to_string())
            .bind(operation.to_string())
            .bind(fingerprint)
            .bind(response).bind(actor).bind(instance)
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
    let payload = checked_input(serde_json::to_vec(&DispatchV1 {
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
                    checked_input(ContractVersion::from_major(1))?,
                    checked_input(SchemaDigest::parse(&format!(
                        "sha256:{:x}",
                        Sha256::digest(include_bytes!("dispatch-v1.json"))
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
    service: &Service,
    proof: &AuthorizedPrincipal,
    device: &str,
    input: &crate::control::device_control::Input,
) -> Result<Vec<u8>> {
    Ok(crate::control::protection::fingerprint(
        &service.transactions.protection,
        service.transactions.tenant,
        device,
        "device-control-create/v1",
        &(proof.actor(), input),
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
    service: &crate::control::transactions::Transactions,
    audit: &RequestAudit,
    id: Uuid,
    fingerprint: Vec<u8>,
) -> Result<AcceptedReceipt> {
    let response = AcceptedReceipt {
        operation_id: id,
        command_id: id,
        revision: 1,
        accepted: true,
    };
    let fact = Fact::business(
        audit,
        rss_mdm_audit_integration::operation::OperationOwner::DeviceControl,
        &format!(
            "command:{}:{id}:accept",
            audit.snapshot().actor.ok_or(Error::Malformed)?
        ),
        202,
        "success",
        None,
    )?;
    let op = storage::load(tx, &service.protection, id).await?;
    let fact = fact.with_activity(&crate::control::timeline::native_activity(
        &op,
        dc::Status::Queued,
        rss_mdm_audit_integration::activity::ActivityPhase::Accepted,
    ))?;
    service.audit_store.append_in(tx, &fact).await?;
    receipt(tx, id, id, fingerprint, &response, audit).await?;
    Ok(response)
}

impl Service {}

/// A request receipt is actor-bound; a different actor cannot probe another operation's secret input.
pub(crate) async fn reject_existing_operation(tx: &mut PgTransaction<'_>, id: Uuid) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    let exists:bool=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_devices.control_operations WHERE tenant_id=$1::uuid AND id=$2)").bind(tenant).bind(id).fetch_one(c).await})).await?;
    if exists {
        Err(Error::Conflict.into())
    } else {
        Ok(())
    }
}

#[derive(serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AcceptedReceipt {
    pub operation_id: Uuid,
    pub command_id: Uuid,
    pub revision: i64,
    pub accepted: bool,
}
#[derive(serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChangedReceipt {
    pub operation_id: Uuid,
    pub revision: i64,
}

impl crate::control::transactions::Transactions {
    pub async fn queue_authorized_in(
        &self,
        tx: &mut PgTransaction<'_>,
        device: &str,
        input: &Create,
        mut authority: Authority,
        fingerprint: Vec<u8>,
        audit: &RequestAudit,
    ) -> Result<AcceptedReceipt> {
        // Every producer, including bootstrap cleanup, must durably wake command
        // publication; a relay notification alone does not advance queued commands.
        self.reconcile_messaging
            .wake_in(
                tx,
                &target(self.tenant, device),
                &rss_reconcile::ResourceSet::empty(self.tenant),
                (),
                |_, _| Box::pin(async { Ok(()) }),
            )
            .await?;

        if matches!(&input.task,Task::Macos{request:rss_mdm_apple_mdm::native::request::Request::Command{command}} if command.request_type=="DeviceLock")
            && !matches!(
                &authority,
                Authority::DeviceControl {
                    action: crate::control::device_control::Kind::Lock,
                    ..
                }
            )
        {
            return Err(Error::Unsupported.into());
        }

        let tenant = tx.tenant_id().to_string();
        let name = device.to_owned();
        let id = input.operation_id;
        let allowed = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    Ok(
                        crate::lifecycle::execution_allowed_in(c, &tenant, &name, id)
                            .await
                            .map_err(Error::from),
                    )
                })
            })
            .await??;
        if !allowed {
            return Err(Error::Forbidden.into());
        }
        let now = self.store.now(tx).await? / 1_000_000;
        input.validate(now)?;
        let (registration, registration_generation) =
            storage::current_registration(tx, device, input.task.purpose()?).await?;
        if matches!(authority, Authority::DeviceControl { .. })
            && !authority.control_matches(input, registration, registration_generation)?
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
        let command_authority = rss_mdm_registration_service::command_authority::resolve_in(
            &self.store,
            tx,
            device,
            registration,
            registration_generation,
        )
        .await?;
        let (scope, coordinate) = (command_authority.scope, command_authority.coordinate);
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
        let binding = rss_mdm_registration_service::command_authority::CommandBinding {
            operation: input.operation_id,
            registration,
            generation: registration_generation,
        };
        let tenant = self.tenant;
        if matches!(input.task, Task::Windows { .. }) {
            let channel = self.windows_results.clone();
            tx.with_connection(move |c| {
                Box::pin(async move { Ok(channel.bind_command(c, tenant, binding).await) })
            })
            .await??;
        } else {
            let channel = self.apple_profiles.clone();
            tx.with_connection(move |c| {
                Box::pin(async move { Ok(channel.bind_command(c, tenant, binding).await) })
            })
            .await??;
        }

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
        )
        .await?;
        authority.bind_required(required.clone());
        if required != input.task.permissions()? {
            let check = authority.clone();
            let key = self.protection.clone();
            if !tx
                .with_connection(move |c| {
                    Box::pin(async move { Ok(check.valid(c, &key, &required, now).await) })
                })
                .await??
            {
                return Err(Error::Forbidden.into());
            }
        }
        let (source, policy_version): (&str, Option<Uuid>) = match &authority {
            Authority::DeviceControl { .. } => ("direct", None),
            Authority::Retirement { version, .. } => ("policy", Some(*version)),
        };
        let authority = checked_input(serde_json::to_string(&authority))?;
        let digest = fingerprint.clone();
        tx.with_connection(move|c|Box::pin(async move {sqlx::query("INSERT INTO mdm_devices.control_operations(tenant_id,id,device,request,fingerprint,registration,registration_generation,generation,epoch,authority,dispatch_fingerprint,source_kind,policy_version,input_context) VALUES($1::uuid,$2::uuid,$3,$4,$5,$6::uuid,$7,$8,$9,$10::jsonb,$11,$12,$13,$14)").bind(tenant).bind(id).bind(name).bind(request).bind(digest).bind(registration.to_string()).bind(registration_generation).bind(coordinate.generation()).bind(coordinate.epoch()).bind(authority).bind(dispatch_fingerprint).bind(source).bind(policy_version).bind(input_context).execute(c).await?;Ok(())})).await?;
        apple::own(
            tx,
            self.apple_profiles.clone(),
            device,
            registration,
            registration_generation,
            input,
        )
        .await?;
        let response = created(tx, self, audit, input.operation_id, fingerprint).await?;
        crate::control::worker_wake::notify_in(tx, crate::control::worker_wake::Work::CommandRelay)
            .await?;
        crate::control::worker_wake::notify_in(
            tx,
            crate::control::worker_wake::Work::CommandRecovery,
        )
        .await?;
        Ok(response)
    }
}
