//! Native configuration is desired state. Work is created only for changed device inputs.
use super::*;
use crate::planning::policies::{self, Frozen, Policy};
use rss_mdm_policy::{Behavior, Exit};
use sqlx::Row;

/// Closed durable reasons used by the native reconciler and Scope wakeup query.
#[derive(Clone, Copy)]
pub enum Diagnosis {
    WaitingScope,
    WaitingRegistration,
    WaitingCapability,
    NotApplicable,
    Conflict,
    Removing,
    Unassigned,
}
impl Diagnosis {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WaitingScope => "waiting_scope",
            Self::WaitingRegistration => "waiting_registration",
            Self::WaitingCapability => "waiting_capability",
            Self::NotApplicable => "not_applicable",
            Self::Conflict => "configuration_conflict",
            Self::Removing => "removing",
            Self::Unassigned => "unassigned",
        }
    }
}

pub async fn pending(tx: &mut PgTransaction<'_>, device: &str) -> Result<bool> {
    let tenant = tx.tenant_id().to_string();
    let device = device.to_owned();
    Ok(tx.with_connection(move|c|Box::pin(async move {
        sqlx::query_scalar("SELECT coalesce((SELECT input_revision>observed_revision FROM mdm_planning.configuration_devices WHERE tenant_id=$1::uuid AND device=$2),false)").bind(tenant).bind(device).fetch_one(c).await
    })).await?)
}
impl ExecutionService {
    pub async fn reconcile_configuration(
        &self,
        tx: &mut PgTransaction<'_>,
        device: &str,
        audit: &RequestAudit,
    ) -> Result<()> {
        storage::lock(tx, device).await?;
        let tenant = tx.tenant_id().to_string();
        let name = device.to_owned();
        let state=tx.with_connection(move|c|Box::pin(async move {
            sqlx::query("SELECT input_revision,operation::text,digest FROM mdm_planning.configuration_devices WHERE tenant_id=$1::uuid AND device=$2 FOR UPDATE").bind(tenant).bind(name).fetch_one(c).await
        })).await?;
        let input: i64 = state.try_get("input_revision")?;
        let previous_operation = state
            .try_get::<Option<String>, _>("operation")?
            .map(|id| stored(Uuid::parse_str(&id)))
            .transpose()?;
        let previous_digest: Option<Vec<u8>> = state.try_get("digest")?;
        let (mut desired, waiting) = desired_in(&self.policy_reader, tx, device).await?;
        let prior = prior_claims(&self.policy_reader, tx, device).await?;
        if !waiting.is_empty()
            && (desired.is_empty()
                || waiting
                    .iter()
                    .any(|(_, f)| !same_configuration(&desired[0].1, f)))
        {
            desired.extend(waiting);
            replace_claims(tx, device, &desired, previous_operation).await?;
            return settle_input(
                tx,
                device,
                input,
                previous_operation,
                previous_digest,
                Some(Diagnosis::WaitingScope),
            )
            .await;
        }
        // A known owner can apply an identical effect while another source is
        // pending. Keep both claims so later withdrawal cannot remove it early.
        desired.extend(waiting);
        if uncertain_prior_in(tx, device, &prior, &desired).await? {
            return settle_input(
                tx,
                device,
                input,
                previous_operation,
                previous_digest,
                Some(Diagnosis::WaitingScope),
            )
            .await;
        }
        let state = DeviceState {
            revision: input,
            operation: previous_operation,
            digest: previous_digest,
        };
        if desired.is_empty() {
            self.remove_configuration(tx, device, &state, &prior, audit)
                .await
        } else {
            self.apply_configuration(tx, device, &state, &desired, audit)
                .await
        }
    }
    async fn remove_configuration(
        &self,
        tx: &mut PgTransaction<'_>,
        device: &str,
        state: &DeviceState,
        prior: &[(Policy, Frozen)],
        audit: &RequestAudit,
    ) -> Result<()> {
        let removal = prior.iter().find(|(_, f)| {
            matches!(
                f,
                Frozen::Configuration {
                    platform: rss_mdm_policy::Platform::Macos,
                    exit: Exit::Remove,
                    ..
                }
            )
        });
        let (Some((policy, _)), Some(old_id)) = (removal, state.operation) else {
            replace_claims(tx, device, &[], None).await?;
            return settle_input(
                tx,
                device,
                state.revision,
                state.operation,
                state.digest.clone(),
                Some(Diagnosis::Unassigned),
            )
            .await;
        };
        let old = storage::load(tx, old_id).await?;
        let Some((profile, present)) = old.request.profile_target() else {
            replace_claims(tx, device, &[], None).await?;
            return settle_input(
                tx,
                device,
                state.revision,
                state.operation,
                state.digest.clone(),
                Some(Diagnosis::Unassigned),
            )
            .await;
        };
        let command = self.required_command(tx, &old).await?;
        if !present && command.status() == dc::Status::Applied {
            replace_claims(tx, device, &[], None).await?;
            return settle_input(
                tx,
                device,
                state.revision,
                Some(old_id),
                None,
                Some(Diagnosis::Unassigned),
            )
            .await;
        }
        if !present && !command.status().is_terminal() {
            return settle_input(
                tx,
                device,
                state.revision,
                Some(old_id),
                None,
                Some(Diagnosis::Removing),
            )
            .await;
        }
        if present
            && !command.status().is_terminal()
            && self
                .store
                .cancel(tx, old.scope, &old.command_id()?, old.coordinate)
                .await?
                .outcome
                == dc::Outcome::OutOfOrder
        {
            return Err(Error::Conflict.into());
        }
        let op = Create {
            operation_id: Uuid::new_v4(),
            deadline: storage::now(tx)
                .await?
                .checked_add(3600)
                .ok_or(Error::Malformed)?,
            task: Task::ProfileRemove { profile },
        };
        self.queue_policy_configuration(tx, device, policy, &op, true, audit)
            .await?;
        // Keep ownership until removal is observed, including expiry/rejection retries.
        replace_claims(tx, device, prior, Some(op.operation_id)).await?;
        settle_input(
            tx,
            device,
            state.revision,
            Some(op.operation_id),
            None,
            Some(Diagnosis::Removing),
        )
        .await
    }
    async fn apply_configuration(
        &self,
        tx: &mut PgTransaction<'_>,
        device: &str,
        state: &DeviceState,
        desired: &[(Policy, Frozen)],
        audit: &RequestAudit,
    ) -> Result<()> {
        let (first, frozen) = &desired[0];
        if desired.iter().any(|(_, f)| !same_configuration(frozen, f)) {
            replace_claims(tx, device, desired, state.operation).await?;
            return settle_input(
                tx,
                device,
                state.revision,
                state.operation,
                state.digest.clone(),
                Some(Diagnosis::Conflict),
            )
            .await;
        }
        let native = match native_configuration_in(tx, device, frozen).await? {
            Ok(native) => native,
            Err(reason) => {
                replace_claims(tx, device, desired, None).await?;
                return settle_input(tx, device, state.revision, None, None, Some(reason)).await;
            }
        };
        if let Some(id) = state.operation
            && self
                .reuse_configuration_in(tx, id, &native.digest, state.digest.as_deref())
                .await?
        {
            replace_claims(tx, device, desired, Some(id)).await?;
            return settle_input(
                tx,
                device,
                state.revision,
                Some(id),
                Some(native.digest),
                None,
            )
            .await;
        }
        let op = Create {
            operation_id: Uuid::new_v4(),
            deadline: storage::now(tx)
                .await?
                .checked_add(3600)
                .ok_or(Error::Malformed)?,
            task: native.task,
        };
        self.queue_policy_configuration(tx, device, first, &op, false, audit)
            .await?;
        replace_claims(tx, device, desired, Some(op.operation_id)).await?;
        settle_input(
            tx,
            device,
            state.revision,
            Some(op.operation_id),
            Some(native.digest),
            None,
        )
        .await
    }
    async fn reuse_configuration_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        digest: &[u8],
        previous: Option<&[u8]>,
    ) -> Result<bool> {
        let old = storage::load(tx, id).await?;
        let command = self.required_command(tx, &old).await?;
        let now = storage::now(tx).await?;
        if previous == Some(digest)
            && (command.status() == dc::Status::Applied
                || storage::approval_valid(tx, &old, now).await?)
            && !matches!(
                command.status(),
                dc::Status::TimedOut
                    | dc::Status::Cancelled
                    | dc::Status::Superseded
                    | dc::Status::Rejected
            )
        {
            return Ok(true);
        }
        if !command.status().is_terminal()
            && self
                .store
                .cancel(tx, old.scope, &old.command_id()?, old.coordinate)
                .await?
                .outcome
                == dc::Outcome::OutOfOrder
        {
            return Err(Error::Conflict.into());
        }
        Ok(false)
    }
    async fn queue_policy_configuration(
        &self,
        tx: &mut PgTransaction<'_>,
        device: &str,
        policy: &Policy,
        input: &Create,
        remove: bool,
        audit: &RequestAudit,
    ) -> Result<()> {
        let authority = crate::execution::authority::ExecutionAuthority::Policy {
            tenant: tx.tenant_id().to_string(),
            policy: policy.id,
            version: policy.version,
            device: device.into(),
            remove,
        };
        let fingerprint =
            crate::transaction::fingerprint(&(device, input, policy.id, policy.version, remove))?;
        let fact_audit = audit.transaction_copy();
        fact_audit.identify_service("configuration-policy");
        fact_audit.operation(input.operation_id, "command_accept");
        fact_audit.target(device);
        let result = self
            .queue_authorized_in(tx, device, input, authority, fingerprint, &fact_audit)
            .await;
        fact_audit.finalize(
            result
                .as_ref()
                .err()
                .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
        );
        result?;
        let target = service::target(tx.tenant_id(), device);
        rss_reconcile_postgres::messaging::wake_in(tx, &target, (), |_, _| {
            Box::pin(async { Ok(()) })
        })
        .await?;
        Ok(())
    }
}
fn same_configuration(a: &Frozen, b: &Frozen) -> bool {
    match (a, b) {
        (
            Frozen::Configuration {
                enabled: a,
                platform: ap,
                ..
            },
            Frozen::Configuration {
                enabled: b,
                platform: bp,
                ..
            },
        ) => a == b && std::mem::discriminant(ap) == std::mem::discriminant(bp),
        _ => false,
    }
}
async fn prior_claims(
    reader: &rss_mdm_policy_postgres::PolicyReader,
    tx: &mut PgTransaction<'_>,
    device: &str,
) -> Result<Vec<(Policy, Frozen)>> {
    let tenant = tx.tenant_id().to_string();
    let device = device.to_owned();
    let versions=tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar::<_,Uuid>("SELECT version FROM mdm_planning.configuration_claims WHERE tenant_id=$1::uuid AND device=$2 ORDER BY policy").bind(tenant).bind(device).fetch_all(c).await})).await?;
    let mut result = Vec::new();
    for id in versions {
        let (mut p, f) = policies::storage::version_in(reader, tx, id).await?;
        p.version = id;
        result.push((p, f));
    }
    Ok(result)
}
async fn replace_claims(
    tx: &mut PgTransaction<'_>,
    device: &str,
    desired: &[(Policy, Frozen)],
    operation: Option<Uuid>,
) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    let device = device.to_owned();
    let policies = desired.iter().map(|(p, _)| p.id).collect::<Vec<_>>();
    let versions = desired.iter().map(|(p, _)| p.version).collect::<Vec<_>>();
    tx.with_connection(move|c|Box::pin(async move {
        sqlx::query("DELETE FROM mdm_planning.configuration_claims WHERE tenant_id=$1::uuid AND device=$2 AND NOT(policy=ANY($3))").bind(&tenant).bind(&device).bind(&policies).execute(&mut *c).await?;
        sqlx::query("INSERT INTO mdm_planning.configuration_claims(tenant_id,device,policy,version,operation) SELECT $1::uuid,$2,p,v,$5 FROM unnest($3::uuid[],$4::uuid[]) a(p,v) ON CONFLICT(tenant_id,policy,device) DO UPDATE SET version=EXCLUDED.version,operation=EXCLUDED.operation").bind(tenant).bind(device).bind(policies).bind(versions).bind(operation).execute(c).await?;Ok(())
    })).await?;
    Ok(())
}
async fn settle_input(
    tx: &mut PgTransaction<'_>,
    device: &str,
    revision: i64,
    operation: Option<Uuid>,
    digest: Option<Vec<u8>>,
    diagnosis: Option<Diagnosis>,
) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    let device = device.to_owned();
    let diagnosis = diagnosis.map(Diagnosis::as_str);
    tx.with_connection(move|c|Box::pin(async move {
        sqlx::query("UPDATE mdm_planning.configuration_devices SET observed_revision=$3,operation=$4,digest=$5,diagnosis=$6 WHERE tenant_id=$1::uuid AND device=$2").bind(tenant).bind(device).bind(revision).bind(operation).bind(digest).bind(diagnosis).execute(c).await?;Ok(())
    })).await?;
    Ok(())
}

struct DeviceState {
    revision: i64,
    operation: Option<Uuid>,
    digest: Option<Vec<u8>>,
}
struct NativeConfiguration {
    task: Task,
    digest: Vec<u8>,
}
async fn native_configuration_in(
    tx: &mut PgTransaction<'_>,
    device: &str,
    frozen: &Frozen,
) -> Result<std::result::Result<NativeConfiguration, Diagnosis>> {
    let Frozen::Configuration {
        enabled, platform, ..
    } = frozen
    else {
        return Err(Error::Malformed.into());
    };
    let (registration, generation) = match storage::current_registration(tx, device).await {
        Ok(value) => value,
        Err(Fault::Request(Error::Conflict)) => return Ok(Err(Diagnosis::WaitingRegistration)),
        Err(error) => return Err(error),
    };
    let task = match platform {
        rss_mdm_policy::Platform::Macos => Task::ProfileInstall { enabled: *enabled },
        rss_mdm_policy::Platform::Windows => {
            let tenant = tx.tenant_id().to_string();
            let capability=tx.with_connection(move|c|Box::pin(async move {sqlx::query_as::<_,(String,i32)>("SELECT os_version,edition FROM mdm_commands.capabilities WHERE tenant_id=$1::uuid AND registration=$2::uuid AND generation=$3").bind(tenant).bind(registration.to_string()).bind(generation).fetch_optional(c).await})).await?;
            let Some((os_version, edition)) = capability else {
                return Ok(Err(Diagnosis::WaitingCapability));
            };
            if rss_mdm_windows_mdm::configuration::Platform::new(&os_version, edition as u32)
                .and_then(|p| rss_mdm_windows_mdm::configuration::Firewall::compile(*enabled, &p))
                .is_err()
            {
                return Ok(Err(Diagnosis::NotApplicable));
            }
            Task::Firewall {
                enabled: *enabled,
                os_version,
                edition: edition as u32,
            }
        }
    };
    let capability = match &task {
        Task::Firewall {
            os_version,
            edition,
            ..
        } => Some((os_version, *edition)),
        _ => None,
    };
    let digest = crate::transaction::fingerprint(&(
        enabled,
        platform,
        registration,
        generation,
        capability,
    ))?;
    Ok(Ok(NativeConfiguration { task, digest }))
}
async fn desired_in(
    reader: &rss_mdm_policy_postgres::PolicyReader,
    tx: &mut PgTransaction<'_>,
    device: &str,
) -> Result<(Claims, Claims)> {
    let mut desired = Vec::new();
    let mut waiting = Vec::new();
    let mut after = Uuid::nil();
    loop {
        let tenant = tx.tenant_id().to_string();
        let name = device.to_owned();
        let ids=tx.with_connection(move|c|Box::pin(async move {
                sqlx::query_scalar::<_,Uuid>("SELECT p.id FROM mdm_policy.policies p WHERE p.tenant_id=$1::uuid AND p.enabled AND p.id>$3 AND p.definition->'behavior'->>'kind'='configuration' AND (mdm_planning.scope_admission((p.definition->>'scope')::uuid,$2)->>'state'<>'excluded') ORDER BY p.id LIMIT 64")
                    .bind(tenant).bind(name).bind(after).fetch_all(c).await
            })).await?;
        if ids.is_empty() {
            break;
        }
        for id in ids {
            after = id;
            let p = policies::storage::read_in(reader, tx, id)
                .await?
                .ok_or(Error::NotFound)?;
            let eligible = policies::storage::eligible_in(tx, &p, device)
                .await?
                .is_some();
            let (_, frozen) = policies::storage::version_in(reader, tx, p.version).await?;
            if eligible {
                desired.push((p, frozen));
            } else {
                waiting.push((p, frozen));
            }
        }
    }
    Ok((desired, waiting))
}
async fn uncertain_prior_in(
    tx: &mut PgTransaction<'_>,
    device: &str,
    prior: &[(Policy, Frozen)],
    desired: &[(Policy, Frozen)],
) -> Result<bool> {
    for (p, _) in prior {
        if p.enabled
            && matches!(p.definition.behavior, Behavior::Configuration { .. })
            && !desired.iter().any(|(d, _)| d.id == p.id)
            && !policies::storage::withdrawn_in(tx, p, device).await?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

type Claims = Vec<(Policy, Frozen)>;
