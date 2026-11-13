use super::*;
use authority::Authority;
use model::DispatchV1;
use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
use rss_mdm_audit_integration::{Fact, activity::*};
use rss_transactional_messaging::{message::*, outbox::PendingMessage};
use sha2::{Digest, Sha256};
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
impl Transactions {
    pub(crate) async fn queue_authorized_in(
        &self,
        tx: &mut PgTransaction<'_>,
        device: &rss_mdm_agent_wire::DeviceId,
        input: &Create,
        mut authority: Authority,
        fingerprint: Vec<u8>,
        audit: &RequestAudit,
    ) -> Result<()> {
        self.runtime.validate_transaction(tx)?;
        let tenant = self.tenant;
        let name = device.to_owned();
        let id = input.operation_id;
        let allowed = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    Ok(rss_mdm_device_service::lifecycle::execution_allowed_in(
                        c,
                        &tenant.to_string(),
                        &name,
                        id,
                    )
                    .await
                    .map_err(Error::from))
                })
            })
            .await??;
        if !allowed {
            return Err(Error::Forbidden.into());
        }
        let now = self.store.now(tx).await? / 1_000_000;
        input.validate(now)?;
        let registration = storage::current_registration(tx, device, input.task.purpose()?).await?;
        if input.task.purpose()? == rss_mdm_registration_service::Purpose::Primary {
            storage::require_source(tx, registration, input.task.source()).await?;
        }
        if matches!(input.task, Task::Windows { .. })
            && matches!(input.target, NativeTarget::EnrolledUser)
        {
            let target = input.target.clone();

            let allowed=tx.with_connection(move|c| Box::pin(async move {
                let profile: Option<String> = sqlx::query_scalar("SELECT q.windows_profile FROM mdm_access.devices d JOIN mdm_access.requests q ON(q.tenant_id,q.id)=(d.tenant_id,d.request_id) WHERE d.tenant_id=$1::uuid AND d.id=$2 AND d.state='active'").bind(tenant.to_string()).bind(registration.into_uuid()).fetch_one(c).await?;
                Ok(target.matches_windows_context(profile.as_deref() == Some("Full")))
            })).await?;
            if !allowed {
                return Err(Error::Forbidden.into());
            }
        }
        let bound =
            rss_mdm_registration_service::command_authority::resolve_in(&self.store, tx, device)
                .await?;
        let spec = dc::CommandSpec::new(
            bound.scope,
            checked_input(dc::CommandId::parse(&id.to_string()))?,
            bound.coordinate,
            input.digest(&self.protection, tenant, device)?,
            input.deadline * 1_000_000,
        );
        let message = dispatch(tenant, device, input, bound.coordinate, now)?;
        let dispatch_fingerprint = message.fingerprint().as_bytes().to_vec();
        self.store.queue(tx, spec, message).await?;
        let binding = rss_mdm_registration_service::command_authority::CommandBinding {
            operation: id,
            device: registration,
        };
        let windows = matches!(input.task, Task::Windows { .. });
        let value = binding.clone();
        tx.with_connection_context(&mut (self,), move |service, c| {
            Box::pin(async move {
                Ok(service
                    .0
                    .channels
                    .bind_command(c, tenant, value, windows)
                    .await)
            })
        })
        .await??;
        let mut required = input.task.permissions()?;
        let owner = authority.apple_owner();
        required.extend(
            tx.with_connection_context(&mut (self, device, input, owner), move |ctx, c| {
                Box::pin(async move {
                    Ok(ctx
                        .0
                        .channels
                        .previous_permissions(c, tenant, ctx.1, ctx.2, ctx.3.clone())
                        .await)
                })
            })
            .await??,
        );
        required.sort();
        required.dedup();
        authority.bind_required(required.clone());
        let valid = tx
            .with_connection_context(&mut (self, &authority, &required), move |ctx, c| {
                Box::pin(async move {
                    Ok(ctx
                        .1
                        .valid(&ctx.0.source, c, &ctx.0.protection, ctx.2, now)
                        .await)
                })
            })
            .await??;
        if !valid {
            return Err(Error::Forbidden.into());
        }
        let (input_context, request) = input_storage::seal(
            &self.protection,
            tenant,
            &input_storage::Identity {
                operation: id,
                device,
            },
            input,
        )?;
        let policy_version = authority.version();
        let authority = checked_input(serde_json::to_value(&authority))?;
        let name = device.to_owned();
        let digest = fingerprint.clone();
        tx.with_connection(move|c|Box::pin(async move {
            sqlx::query("INSERT INTO mdm_planning.configuration_operations (tenant_id, id, device, request, fingerprint, generation, epoch, authority, dispatch_fingerprint, policy_version, input_context) VALUES (CAST($1 AS uuid), $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)").bind(tenant.to_string()).bind(id).bind(name.into_uuid()).bind(request).bind(digest).bind(bound.coordinate.generation()).bind(bound.coordinate.epoch()).bind(authority).bind(dispatch_fingerprint).bind(policy_version).bind(input_context).execute(c).await?;
            Ok(())
        })).await?;
        if input.profile_target().is_some() {
            let Task::Macos { request } = &input.task else {
                return Err(Error::Malformed.into());
            };
            let reservation = channels::Reservation {
                device: *device,
                binding,
                target: input.target.clone(),
                request: request.clone(),
                deadline: input.deadline,
                input_version: input.input_version.clone(),
            };
            tx.with_connection_context(&mut (self,), move |service, c| {
                Box::pin(async move {
                    Ok(service
                        .0
                        .channels
                        .reserve_profile(c, tenant, reservation)
                        .await)
                })
            })
            .await??;
        }
        let operation = storage::load(tx, &self.protection, id).await?;
        let activity = recovery::activity(&operation, dc::Status::Queued, ActivityPhase::Accepted);
        let actor = audit.snapshot().actor.ok_or(Error::Malformed)?;
        let fact = Fact::business(
            audit,
            rss_mdm_audit_integration::operation::OperationOwner::Configuration,
            &format!("command:{actor}:{id}:accept"),
            202,
            "success",
            None,
        )?
        .with_activity(&activity)?;
        self.audit_store.append_in(tx, &fact).await?;
        tx.with_connection(move|c|Box::pin(async move {
            sqlx::query("INSERT INTO mdm_planning.configuration_receipts(tenant_id,id,actor,fingerprint) VALUES($1::uuid,$2,$3,$4)").bind(tenant.to_string()).bind(id).bind(actor).bind(fingerprint).execute(c).await?;
            Ok(())
        })).await?;
        let target = target(tenant, device);
        self.reconcile_messaging
            .wake_in(
                tx,
                &target,
                &rss_mdm_registration_service::lifecycle::resources::device(
                    tenant,
                    device,
                    rss_mdm_registration_service::lifecycle::resources::Work::Exclusive,
                ),
                (),
                |_, _| Box::pin(async { Ok(()) }),
            )
            .await?;
        Ok(())
    }
}
