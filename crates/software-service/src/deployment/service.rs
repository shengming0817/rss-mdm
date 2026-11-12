use super::*;
use crate::deployment::{authority::Authority, authorization::Permission};
use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
use rss_mdm_audit_integration::Fact;
use rss_transactional_messaging::{message::*, outbox::PendingMessage};
use sha2::{Digest, Sha256};

pub fn target(tenant: TenantId, device: &str) -> rss_reconcile::Target {
    rss_reconcile::Target::new(
        recovery_scope(tenant),
        format!("{:x}", Sha256::digest(device.as_bytes())),
    )
    .expect("bounded digest")
}
impl SoftwareService {}

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
                "INSERT INTO mdm_software_deployment.requests(tenant_id,id,operation,fingerprint,response,actor) VALUES($1::uuid,$2::uuid,$3::uuid,$4,$5::jsonb,$6)",
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

async fn created(
    tx: &mut PgTransaction<'_>,
    service: &crate::deployment::transactions::Transactions,
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
        rss_mdm_audit_integration::operation::OperationOwner::SoftwareDeployment,
        &format!(
            "command:{}:{id}:accept",
            audit.snapshot().actor.ok_or(Error::Malformed)?
        ),
        202,
        "success",
        None,
    )?;
    let op = storage::load(tx, &service.protection, id).await?;
    let fact = fact.with_activity(&crate::deployment::timeline::native_activity(
        &op,
        dc::Status::Queued,
        rss_mdm_audit_integration::activity::ActivityPhase::Accepted,
    ))?;
    service.audit_store.append_in(tx, &fact).await?;
    receipt(tx, id, id, fingerprint, &response, audit).await?;
    Ok(response)
}

impl SoftwareService {}

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

impl crate::deployment::transactions::Transactions {
    #[expect(
        clippy::cognitive_complexity,
        reason = "native command authority, idempotency, outbox and audit are one atomic admission"
    )]
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
                &rss_mdm_registration_service::lifecycle::resources::device(
                    self.tenant,
                    device,
                    rss_mdm_registration_service::lifecycle::resources::Work::Exclusive,
                ),
                (),
                |_, _| Box::pin(async { Ok(()) }),
            )
            .await?;
        if let Authority::AgentInstall {
            version,
            source_objects,
            ..
        } = &mut authority
        {
            let (policy, _) =
                crate::deployment::sources::storage::version_in(&self.policy_reader, tx, *version)
                    .await?;
            let source = self.source.clone();
            let tenant = tx.tenant_id();
            let scope = policy.definition.scope;
            let device = device.to_owned();
            *source_objects = tx
                .with_connection(move |c| {
                    Box::pin(async move {
                        Ok(source
                            .evidence_on(c, tenant, scope, rss_mdm_inventory::Channel::Mdm, &device)
                            .await)
                    })
                })
                .await??;
        }

        let tenant = tx.tenant_id().to_string();
        let name = device.to_owned();
        let id = input.operation_id;
        let lifecycle = self.lifecycle.clone();
        let allowed = tx
            .with_connection(move |c| {
                Box::pin(
                    async move { Ok(lifecycle.execution_allowed_on(c, &tenant, &name, id).await) },
                )
            })
            .await??;
        if !allowed {
            return Err(Error::Forbidden.into());
        }
        let now = self.store.now(tx).await? / 1_000_000;
        input.validate(now)?;
        if input
            .task
            .permissions()?
            .contains(&Permission::SoftwareDeploy)
        {
            if let Authority::AgentInstall {
                package,
                download_origin,
                ..
            } = &authority
            {
                if input.target != NativeTarget::Device
                    || checked_input(serde_json::to_vec(&input.task))?
                        != checked_input(serde_json::to_vec(
                            &package.native_task(input.operation_id, download_origin)?,
                        ))?
                {
                    return Err(Error::Unsupported.into());
                }
            } else if let Authority::Software {
                version, operation, ..
            } = &authority
            {
                let (_, frozen) = crate::deployment::sources::storage::version_in(
                    &self.policy_reader,
                    tx,
                    *version,
                )
                .await?;
                let crate::deployment::frozen::Published::Software { action } = frozen else {
                    return Err(Error::Unsupported.into());
                };
                let crate::deployment::native_software::TargetAdmission::Eligible(
                    crate::deployment::native_software::NativeTarget {
                        platform,
                        architecture,
                        ..
                    },
                ) = crate::deployment::native_software::target_admission_in(
                    self.inventory.clone(),
                    tx,
                    device,
                )
                .await?
                else {
                    return Err(Error::Unsupported.into());
                };
                let package = action
                    .native_packages
                    .get(&rss_mdm_policy::SoftwareTarget::new(platform, architecture))
                    .ok_or(Error::Unsupported)?;
                if !self.inputs.materials.software_distribution.mdm_enabled
                    || *operation != input.operation_id
                    || input.target != NativeTarget::Device
                    || checked_input(serde_json::to_vec(&input.task))?
                        != checked_input(serde_json::to_vec(&package.task(
                            *operation,
                            &self.protection,
                            self.tenant,
                        )?))?
                {
                    return Err(Error::Unsupported.into());
                }
            } else {
                return Err(Error::Unsupported.into());
            }
        }
        let registration = storage::current_registration(tx, device, input.task.purpose()?).await?;

        if input.task.purpose()? == rss_mdm_registration_service::Purpose::Primary {
            storage::require_source(tx, registration.clone(), input.task.source()).await?;
        }
        if matches!(input.task, Task::Windows { .. })
            && matches!(input.target, NativeTarget::EnrolledUser)
        {
            let tenant = self.tenant.to_string();
            let target = input.target.clone();
            let registration = registration.clone();
            let allowed = tx.with_connection(move |c| Box::pin(async move {
                let profile: Option<String> = sqlx::query_scalar("SELECT q.windows_profile FROM mdm_access.devices d JOIN mdm_access.requests q ON(q.tenant_id,q.id)=(d.tenant_id,d.request_id) WHERE d.tenant_id=$1::uuid AND d.id=$2 AND d.state='active'").bind(tenant).bind(&registration).fetch_one(c).await?;
                Ok(target.matches_windows_context(profile.as_deref() == Some("Full")))
            })).await?;
            if !allowed {
                return Err(Error::Forbidden.into());
            }
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
            device: registration.to_string(),
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
        let (input_context, request) = crate::deployment::input_storage::seal(
            &self.protection,
            self.tenant,
            &crate::deployment::input_storage::Identity {
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
        authority.bind_required(required.clone());
        if required != input.task.permissions()? {
            let check = authority.clone();
            let key = self.protection.clone();
            let source = self.source.clone();
            let lifecycle = self.lifecycle.clone();
            if !tx
                .with_connection(move |c| {
                    Box::pin(async move {
                        Ok(check
                            .valid(source.as_ref(), lifecycle.as_ref(), c, &key, &required, now)
                            .await)
                    })
                })
                .await??
            {
                return Err(Error::Forbidden.into());
            }
        }
        let (source, policy_version): (&str, Option<Uuid>) = match &authority {
            Authority::Software { version, .. } | Authority::AgentInstall { version, .. } => {
                ("policy", Some(*version))
            }
        };
        let authority = checked_input(serde_json::to_string(&authority))?;
        let digest = fingerprint.clone();
        tx.with_connection(move|c|Box::pin(async move {sqlx::query("INSERT INTO mdm_software_deployment.operations (tenant_id, id, device, request, fingerprint, generation, epoch, authority, dispatch_fingerprint, source_kind, policy_version, input_context) VALUES (CAST($1 AS uuid), CAST($2 AS uuid), $3, $4, $5, $6, $7, CAST($8 AS jsonb), $9, $10, $11, $12)").bind(tenant).bind(id).bind(name).bind(request).bind(digest).bind(coordinate.generation()).bind(coordinate.epoch()).bind(authority).bind(dispatch_fingerprint).bind(source).bind(policy_version).bind(input_context).execute(c).await?;Ok(())})).await?;
        apple::own(tx, self.apple_profiles.clone(), device, input).await?;
        let response = created(tx, self, audit, input.operation_id, fingerprint).await?;
        crate::deployment::worker_wake::notify_in(
            tx,
            crate::deployment::worker_wake::Work::CommandRelay,
        )
        .await?;
        crate::deployment::worker_wake::notify_in(
            tx,
            crate::deployment::worker_wake::Work::CommandRecovery,
        )
        .await?;
        Ok(response)
    }
}
