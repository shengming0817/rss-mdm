//! Apple tasks share the command reducer, authority, outbox and operation authority.
use super::*;

/// Freeze old and new object authority under the existing device/authorization locks.
pub async fn required(
    tx: &mut PgTransaction<'_>,
    _key: &rss_mdm_native_protection::Protector,
    owner: Arc<dyn super::apple_facts::AppleProfiles>,
    device: &rss_mdm_agent_wire::DeviceId,
    input: &Create,
    declaration_owner: Option<String>,
) -> Result<Vec<crate::deployment::authorization::Permission>> {
    let mut required = input.task.permissions()?;
    let tenant = tx.tenant_id().to_string();
    let device = device.to_owned();
    let user = input.target.user_key().to_owned();
    let lookup = owner.clone();
    let old = if let Some((identifier, _, _)) = input.profile_target() {
        let identifier = identifier.to_owned();
        tx.with_connection(move |c| {
            Box::pin(async move {
                Ok(owner
                    .previous_profiles(c, tenant, device, user, identifier)
                    .await)
            })
        })
        .await??
    } else if matches!(
        input.task,
        Task::Macos {
            request: rss_mdm_apple_mdm::native::request::Request::Declarations { .. }
        }
    ) {
        let name = declaration_owner.ok_or(Error::Malformed)?;
        tx.with_connection(move |c| {
            Box::pin(async move {
                Ok(owner
                    .previous_declarations(c, tenant, device, user, name)
                    .await)
            })
        })
        .await??
    } else {
        return Ok(required);
    };
    let tenant = tx.tenant_id();
    required.extend(
        tx.with_connection(move |c| {
            Box::pin(async move { Ok(lookup.operation_permissions(c, tenant, old).await) })
        })
        .await??,
    );
    required.sort();
    required.dedup();
    Ok(required)
}
pub async fn own(
    tx: &mut PgTransaction<'_>,
    owner: Arc<dyn super::apple_facts::AppleProfiles>,
    device: &rss_mdm_agent_wire::DeviceId,
    input: &Create,
) -> Result<()> {
    if input.profile_target().is_none() {
        return Ok(());
    }
    let Task::Macos { request } = &input.task else {
        return Err(Error::Malformed.into());
    };
    let target = super::apple_facts::AppleRegistration {
        tenant: tx.tenant_id().to_string(),
        device: *device,
    };
    let command = super::apple_facts::AppleCommand {
        operation: input.operation_id,
        authorized_declarations: Vec::new(),
        owner: String::new(),
        assets: Vec::new(),
        deadline: input.deadline,
        input_version: input.input_version.clone(),
        target: input.target.clone(),
        request: request.clone(),
    };
    tx.with_connection(move |c| {
        Box::pin(async move { Ok(owner.reserve_profile(c, target, command).await) })
    })
    .await??;
    Ok(())
}
pub async fn observation_on(
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    apple_results: Arc<dyn super::apple_facts::AppleResults>,
    op: &storage::Operation,
    status: dc::Status,
    native_values: bool,
) -> Result<crate::deployment::queries::records::NativeObservation> {
    observations_on(c, tenant, apple_results, &[(op, status)], native_values)
        .await?
        .remove(&op.id)
        .ok_or(Error::Conflict.into())
}
pub(crate) async fn observations_on(
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    apple_results: Arc<dyn super::apple_facts::AppleResults>,
    ops: &[(&storage::Operation, dc::Status)],
    native_values: bool,
) -> Result<std::collections::BTreeMap<Uuid, crate::deployment::queries::records::NativeObservation>>
{
    use crate::deployment::queries::records::NativeObservation;
    if ops.is_empty() {
        return Ok(Default::default());
    }
    let tenant = tenant.to_string();
    let requests = ops
        .iter()
        .map(|(op, _)| match &op.request.task {
            Task::Macos { request } => Ok((op.id, request.clone())),
            _ => Err(Error::Malformed),
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut page = apple_results
        .evidence_page(c, tenant, requests, native_values)
        .await?;
    ops.iter()
        .map(|(op, status)| {
            let progress = crate::deployment::queries::records::CommandStatus(*status);
            let value = match page.remove(&op.id).ok_or(Error::Conflict)? {
                apple_facts::AppleEvidence::Declarations(facts) => {
                    NativeObservation::Declarations {
                        facts: facts.map(|v| *v),
                        progress,
                    }
                }
                apple_facts::AppleEvidence::Observations(rows) => NativeObservation::Apple {
                    facts: rss_mdm_apple_mdm::native::evidence::summarize(
                        rows,
                        op.request.profile_target().is_some(),
                    ),
                    progress,
                    effect_confirmed: *status == dc::Status::Applied,
                },
            };
            Ok((op.id, value))
        })
        .collect()
}
