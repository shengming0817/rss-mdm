use super::*;
use crate::{
    authorization::{Approval, Permission},
    identity::Principal,
};
use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
use rss_transactional_messaging::{message::*, outbox::PendingMessage};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub(super) fn target(tenant: TenantId, device: &str) -> rss_reconcile::Target {
    rss_reconcile::Target::new(
        rss_reconcile::Scope::new(tenant, "mdm.commands.v1").expect("fixed name"),
        format!("{:x}", Sha256::digest(device.as_bytes())),
    )
    .expect("bounded digest")
}
impl Commands {
    pub(super) async fn create(
        &self,
        proof: &Principal,
        device: &str,
        input: &Create,
        audit: &Audit,
    ) -> std::result::Result<Value, Error> {
        proof.require(Permission::StateVerify, Some(device))?;
        let failure = Mutex::new(None);
        let timer = recovery::Timer::new();
        let cancel = tokio_util::sync::CancellationToken::new();
        let control = rss_reconcile::Control::new(&timer, Duration::from_secs(6), &cancel);
        let attempt = rss_reconcile_postgres::messaging::wake_with(
            &self.runtime,
            &target(self.tenant, device),
            &control,
            (self, proof, device, input, audit, &failure),
            |ctx, tx| {
                Box::pin(async move {
                    match ctx.0.create_in(tx, ctx.1, ctx.2, ctx.3, ctx.4).await {
                        Ok(v) => {
                            ctx.4.mark_commit_started();
                            Ok(v)
                        }
                        Err(e) => Err(rejection(e, ctx.5)),
                    }
                })
            },
        )
        .await;
        settle(attempt, audit, failure)
    }
    async fn create_in(
        &self,
        tx: &mut PgTransaction<'_>,
        proof: &Principal,
        device: &str,
        input: &Create,
        audit: &Audit,
    ) -> Result<Value> {
        storage::admit(tx).await?;
        if proof.tenant_id() != self.tenant.to_string() {
            return Err(Error::Forbidden.into());
        }
        let auth = storage::authorized(tx, proof, device, Permission::StateVerify).await?;
        storage::lock(tx, &format!("request:{}", input.operation_id)).await?;
        storage::lock(tx, device).await?;
        let fingerprint =
            Sha256::digest(invalid(serde_json::to_vec(&(proof.user(), device, input)))?).to_vec();
        if let Some(value) = replay(tx, input.operation_id, &fingerprint).await? {
            audit.management_result(crate::audit::ManagementResult::Replayed);
            storage::audit(tx, audit, 202).await?;
            return Ok(value);
        }
        let now = storage::now(tx).await?;
        input.validate(now)?;
        let (registration, registration_generation) =
            storage::current_registration(tx, device).await?;
        let (scope, coordinate) =
            storage::authority(self, tx, device, registration, registration_generation).await?;
        let approval = Approval::from_proof(&auth, proof, device)?;
        let spec = dc::CommandSpec::new(
            scope,
            invalid(dc::CommandId::parse(&input.operation_id.to_string()))?,
            coordinate,
            input.field.digest(&input.expected_value)?,
            input.deadline * 1_000_000,
        );
        let message = dispatch(self.tenant, device, input, coordinate, now)?;
        let dispatch_fingerprint = message.fingerprint().as_bytes().to_vec();
        self.store.queue(tx, spec, message).await?;
        let tenant = self.tenant.to_string();
        let name = device.to_owned();
        let id = input.operation_id.to_string();
        let request = invalid(serde_json::to_string(input))?;
        let approval = invalid(serde_json::to_string(&approval))?;
        let digest = fingerprint.clone();
        tx.with_connection(move|c|Box::pin(async move {sqlx::query("INSERT INTO mdm_commands.operations(tenant_id,id,device,request,fingerprint,registration,registration_generation,generation,epoch,approval,dispatch_fingerprint) VALUES($1::uuid,$2::uuid,$3,$4::jsonb,$5,$6::uuid,$7,$8,$9,$10::jsonb,$11)").bind(tenant).bind(id).bind(name).bind(request).bind(digest).bind(registration.to_string()).bind(registration_generation).bind(coordinate.generation()).bind(coordinate.epoch()).bind(approval).bind(dispatch_fingerprint).execute(c).await?;Ok(())})).await?;
        let response = json!({"operationId":input.operation_id,"commandId":input.operation_id,"revision":1,"accepted":true});
        receipt(
            tx,
            input.operation_id,
            input.operation_id,
            fingerprint,
            &response,
        )
        .await?;
        storage::audit(tx, audit, 202).await?;
        proof.check_live()?;
        Ok(response)
    }
    pub(super) async fn read(
        &self,
        proof: &Principal,
        device: &str,
        id: Uuid,
        audit: &Audit,
    ) -> std::result::Result<Value, Error> {
        self.transact((self,proof,device,id,audit),audit,|ctx,tx|Box::pin(async move {
            storage::authorized(tx,ctx.1,ctx.2,Permission::OperationRead).await?;
            let op=storage::load(tx,ctx.3).await?;
            if op.device!=ctx.2{return Err(Error::Forbidden.into());}
            let command=ctx.0.store.load(tx,op.scope,&op.command_id()?).await?.ok_or(Error::NotFound)?;
            let now=storage::now(tx).await?;let approved=storage::approval_valid(tx,&op,now).await?;
            let observation=protocol::observation(tx,&op).await?;
            storage::audit(tx,ctx.4,200).await?;
            Ok(json!({"operationId":op.id,"commandId":op.id,"revision":op.revision,"deadline":op.request.deadline,"authorization":if approved{"approved"}else{"blocked"},"commandStatus":status(command.status()),"observation":observation}))
        })).await
    }
    pub(super) async fn change(
        &self,
        proof: &Principal,
        device: &str,
        id: Uuid,
        change: &Change,
        approve: bool,
        audit: &Audit,
    ) -> std::result::Result<Value, Error> {
        if change.request_id.is_nil() || change.expected_revision < 1 {
            return Err(Error::Malformed);
        }
        self.transact((self,proof,device,id,change,approve,audit),audit,|ctx,tx|Box::pin(async move {
            let permission=if ctx.5 {Permission::StateVerify}else{Permission::OperationCancel};
            let auth=storage::authorized(tx,ctx.1,ctx.2,permission).await?;
            storage::lock(tx,&format!("request:{}",ctx.4.request_id)).await?;storage::lock(tx,ctx.2).await?;
            let fingerprint=Sha256::digest(invalid(serde_json::to_vec(&(ctx.1.user(),ctx.2,ctx.3,ctx.4,ctx.5)))?).to_vec();
            if let Some(value)=replay(tx,ctx.4.request_id,&fingerprint).await? {ctx.6.management_result(crate::audit::ManagementResult::Replayed);storage::audit(tx,ctx.6,200).await?;return Ok(value);}
            let op=storage::load(tx,ctx.3).await?;
            if op.device!=ctx.2{return Err(Error::Forbidden.into());}
            if op.revision!=ctx.4.expected_revision{return Err(Error::Conflict.into());}
            let command=ctx.0.store.load(tx,op.scope,&op.command_id()?).await?.ok_or(Error::NotFound)?;
            let now=storage::now(tx).await?;
            if command.status().is_terminal() || now>=op.request.deadline {return Err(Error::Conflict.into());}
            let approval=if ctx.5 {
                if storage::current_registration(tx,ctx.2).await? != (op.registration,op.registration_generation) {return Err(Error::Conflict.into());}
                Approval::from_proof(&auth,ctx.1,ctx.2)?
            } else {
                let transition=ctx.0.store.cancel(tx,op.scope,&op.command_id()?,op.coordinate).await?;
                if transition.outcome==dc::Outcome::OutOfOrder {return Err(Error::Conflict.into());}
                op.approval
            };
            let approval=invalid(serde_json::to_string(&approval))?;let tenant=ctx.0.tenant.to_string();let id=ctx.3.to_string();
            tx.with_connection(move|c|Box::pin(async move {sqlx::query("UPDATE mdm_commands.operations SET approval=$3::jsonb,revision=revision+1 WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(tenant).bind(id).bind(approval).execute(c).await?;Ok(())})).await?;
            let result=json!({"operationId":ctx.3,"revision":op.revision+1});
            receipt(tx,ctx.4.request_id,ctx.3,fingerprint,&result).await?;storage::audit(tx,ctx.6,200).await?;ctx.1.check_live()?;Ok(result)
        })).await
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
                "INSERT INTO mdm_commands.requests VALUES($1::uuid,$2::uuid,$3::uuid,$4,$5::jsonb)",
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
    let payload = invalid(serde_json::to_vec(&(
        device,
        input,
        coordinate.generation(),
        coordinate.epoch(),
    )))?;
    Ok(PendingMessage::new(MessageEnvelope::new(
        invalid(MessageId::parse(&format!(
            "dispatch.{}",
            input.operation_id
        )))?,
        MessageMetadata::new(
            AuthoredMessageMetadata::new(
                tenant,
                invalid(Timepoint::try_from(now))?,
                invalid(MessagingDomain::parse("mdm.commands.v1"))?,
                invalid(MessageRoute::parse("windows.verify"))?,
                ContractIdentity::new(
                    invalid(ContractId::parse("mdm.state-verify"))?,
                    invalid(ContractVersion::from_major(1))?,
                    invalid(SchemaDigest::parse(&format!(
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
