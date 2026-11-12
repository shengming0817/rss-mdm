use super::*;
use crate::native::authority::Authority;
use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
use rss_mdm_audit_integration::Fact;
use rss_transactional_messaging::{message::*, outbox::PendingMessage};
use sha2::{Digest, Sha256};

pub fn target(tenant: TenantId, device: &rss_mdm_agent_wire::DeviceId) -> rss_reconcile::Target {
    rss_reconcile::Target::new(
        recovery_scope(tenant),
        format!("{:x}", Sha256::digest(device.to_string().as_bytes())),
    )
    .expect("bounded digest")
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
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO mdm_recovery_tasks.requests(tenant_id,id,operation,fingerprint,response,actor) VALUES($1::uuid,$2::uuid,$3::uuid,$4,$5::jsonb,$6)",
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
    device: &rss_mdm_agent_wire::DeviceId,
    input: &Create,
    coordinate: dc::Coordinate,
    now: i64,
) -> Result<PendingMessage<Vec<u8>>> {
    let payload = checked_input(serde_json::to_vec(&DispatchV1 {
        device: *device,
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

async fn created(
    tx: &mut PgTransaction<'_>,
    service: &crate::native::Transactions,
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
        rss_mdm_audit_integration::operation::OperationOwner::RecoveryCommand,
        &format!(
            "command:{}:{id}:accept",
            audit.snapshot().actor.ok_or(Error::Malformed)?
        ),
        202,
        "success",
        None,
    )?;
    let op = storage::load(tx, &service.protection, id).await?;
    let fact = fact.with_activity(&crate::native::timeline::native_activity(
        &op,
        dc::Status::Queued,
        rss_mdm_audit_integration::activity::ActivityPhase::Accepted,
    ))?;
    service.audit_store.append_in(tx, &fact).await?;
    receipt(tx, id, id, fingerprint, &response, audit).await?;
    Ok(response)
}

#[derive(serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AcceptedReceipt {
    pub operation_id: Uuid,
    pub command_id: Uuid,
    pub revision: i64,
    pub accepted: bool,
}

impl Transactions {
    pub async fn queue_authorized_in(
        &self,
        tx: &mut PgTransaction<'_>,
        device: &rss_mdm_agent_wire::DeviceId,
        input: &Create,
        authority: Authority,
        fingerprint: Vec<u8>,
        audit: &RequestAudit,
    ) -> Result<AcceptedReceipt> {
        // Every credential producer must durably wake command
        // publication; a relay notification alone does not advance queued commands.
        self.reconcile_messaging
            .wake_in(
                tx,
                &target(self.tenant, device),
                &rss_mdm_registration_service::lifecycle::resources::device(
                    self.tenant,
                    device,
                    rss_mdm_registration_service::lifecycle::resources::Work::Exclusive,
                ),
                (),
                |_, _| Box::pin(async { Ok(()) }),
            )
            .await?;
        self.validate_in(tx)?;
        let now = self.store.now(tx).await? / 1_000_000;
        input.validate(now)?;
        if *device != authority.device || input.target != NativeTarget::Device {
            return Err(Error::Forbidden.into());
        }
        let registration = storage::current_registration(tx, device).await?;
        if registration != authority.device {
            return Err(Error::Conflict.into());
        }
        let materials = self.materials.clone();
        let check = authority.clone();
        let tenant = self.tenant;
        if !tx
            .with_connection(move |c| {
                Box::pin(async move { Ok(check.valid(&materials, c, tenant).await) })
            })
            .await??
        {
            return Err(Error::Forbidden.into());
        }
        let command_authority =
            rss_mdm_registration_service::command_authority::resolve_in(&self.store, tx, device)
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
            device: registration,
        };
        let tenant = self.tenant;
        let channel = self.apple_profiles.clone();
        tx.with_connection(move |c| {
            Box::pin(async move { Ok(channel.bind_command(c, tenant, binding).await) })
        })
        .await??;

        let tenant = self.tenant.to_string();
        let name = device.to_owned();
        let id = input.operation_id.to_string();
        let (input_context, request) = crate::native::input_storage::seal(
            &self.protection,
            self.tenant,
            &crate::native::input_storage::Identity {
                operation: input.operation_id,
                device,
            },
            input,
        )?;
        let required = apple::required(
            tx,
            &self.protection,
            self.apple_profiles.clone(),
            device,
            input,
            Some(authority.apple_owner(input.operation_id)?),
        )
        .await?;
        if required.iter().any(|p| !authority.required.contains(p)) {
            return Err(Error::Forbidden.into());
        }
        let authority = checked_input(serde_json::to_string(&authority))?;
        let digest = fingerprint.clone();
        tx.with_connection(move|c|Box::pin(async move {sqlx::query("INSERT INTO mdm_recovery_tasks.operations (tenant_id, id, device, request, fingerprint, generation, epoch, authority, dispatch_fingerprint, input_context) VALUES (CAST($1 AS uuid), CAST($2 AS uuid), $3, $4, $5, $6, $7, CAST($8 AS jsonb), $9, $10)").bind(tenant).bind(id).bind(name.into_uuid()).bind(request).bind(digest).bind(coordinate.generation()).bind(coordinate.epoch()).bind(authority).bind(dispatch_fingerprint).bind(input_context).execute(c).await?;Ok(())})).await?;
        apple::own(tx, self.apple_profiles.clone(), device, input).await?;
        let response = created(tx, self, audit, input.operation_id, fingerprint).await?;
        crate::native::worker_wake::notify_in(tx, crate::native::worker_wake::Work::CommandRelay)
            .await?;
        crate::native::worker_wake::notify_in(
            tx,
            crate::native::worker_wake::Work::CommandRecovery,
        )
        .await?;
        Ok(response)
    }
}

pub(crate) async fn replay(
    tx: &mut PgTransaction<'_>,
    id: Uuid,
    fingerprint: &[u8],
    audit: &RequestAudit,
) -> Result<Option<serde_json::Value>> {
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

pub(crate) async fn reject_existing_operation(tx: &mut PgTransaction<'_>, id: Uuid) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    let exists:bool=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_recovery_tasks.operations WHERE tenant_id=$1::uuid AND id=$2)").bind(tenant).bind(id).fetch_one(c).await})).await?;
    if exists {
        Err(Error::Conflict.into())
    } else {
        Ok(())
    }
}
