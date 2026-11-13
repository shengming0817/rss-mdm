//! One current authorization result; a read never grants permission to a later write.
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BlockReason {
    LifecycleBlocked,
    DeviceInactive,
    InputMismatch,
    SourceInvalid,
}
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum Authorization {
    Authorized,
    Blocked { reason: BlockReason },
    NotApplicable,
}
impl Authorization {
    pub fn is_authorized(&self) -> bool {
        matches!(self, Self::Authorized)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReauthorizationReason {
    PermissionDenied,
    Terminal,
    AlreadyReceived,
    Expired,
    DeviceInactive,
    InputMismatch,
    Unsupported,
}
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(
    tag = "state",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum Reauthorization {
    Available { confirmation_required: bool },
    Unavailable { reason: ReauthorizationReason },
    NotApplicable,
}

use crate::control::{authority::Authority, storage::Operation, *};
use std::collections::BTreeMap;

pub(crate) fn decide(
    operation: &Operation,
    lifecycle: bool,
    registration: Option<rss_mdm_agent_wire::DeviceId>,
    source: bool,
) -> Result<Authorization> {
    let reason = if !lifecycle {
        Some(BlockReason::LifecycleBlocked)
    } else if matches!(operation.authority, Authority::DeviceControl { .. })
        && !operation.authority.control_matches(&operation.request)?
    {
        Some(BlockReason::InputMismatch)
    } else if registration != Some(operation.device) {
        Some(BlockReason::DeviceInactive)
    } else if !source {
        Some(BlockReason::SourceInvalid)
    } else {
        None
    };
    Ok(match reason {
        Some(reason) => Authorization::Blocked { reason },
        None => Authorization::Authorized,
    })
}

/// Shared business preflight; caller still owns live permission, locks, CAS and confirmation.
pub(crate) fn reauthorization(
    operation: &Operation,
    status: dc::Status,
    now: i64,
    registration: Option<rss_mdm_agent_wire::DeviceId>,
    supported: bool,
    permitted: bool,
) -> Result<Reauthorization> {
    use ReauthorizationReason as R;
    let Authority::DeviceControl { confirmation, .. } = &operation.authority else {
        return Ok(Reauthorization::NotApplicable);
    };
    let reason = if !operation.authority.control_matches(&operation.request)? {
        Some(R::InputMismatch)
    } else if !permitted {
        Some(R::PermissionDenied)
    } else if status.is_terminal() {
        Some(R::Terminal)
    } else if status == dc::Status::Received {
        Some(R::AlreadyReceived)
    } else if now >= operation.request.deadline {
        Some(R::Expired)
    } else if registration != Some(operation.device) {
        Some(R::DeviceInactive)
    } else if !supported {
        Some(R::Unsupported)
    } else {
        None
    };
    Ok(match reason {
        Some(reason) => Reauthorization::Unavailable { reason },
        None => Reauthorization::Available {
            confirmation_required: *confirmation,
        },
    })
}

#[derive(Clone, Debug, Serialize)]
pub struct Decision {
    pub authorization: Authorization,
    pub reauthorization: Reauthorization,
}
impl Decision {
    pub fn not_applicable() -> Self {
        Self {
            authorization: Authorization::NotApplicable,
            reauthorization: Reauthorization::NotApplicable,
        }
    }
}

/// Batch facts never take per-device mutation locks. The read caller supplies one consistent snapshot.
pub(crate) async fn batch(
    queries: &crate::control::queries::Queries,
    c: &mut sqlx::PgConnection,
    proof: &authorization::context::AuthorizedPrincipal,
    grant: &authorization::Snapshot,
    operations: &BTreeMap<Uuid, Operation>,
    statuses: &BTreeMap<Uuid, dc::Status>,
    now: i64,
) -> Result<BTreeMap<Uuid, Decision>> {
    if operations.is_empty() {
        return Ok(BTreeMap::new());
    }
    let tenant = queries.tenant.to_string();
    let targets = operations
        .values()
        .map(|o| (o.id, o.device))
        .collect::<Vec<_>>();
    let t = tenant.clone();
    let lifecycle = crate::lifecycle::execution_permissions_in(c, &t, &targets)
        .await
        .map_err(Error::from)?;
    let mut registrations = BTreeMap::new();
    for purpose in [
        rss_mdm_registration_service::Purpose::Primary,
        rss_mdm_registration_service::Purpose::WindowsDeclared,
    ] {
        let devices = operations
            .values()
            .filter_map(|o| match o.request.task.purpose() {
                Ok(p) if p == purpose => Some(Ok(o.device)),
                Ok(_) => None,
                Err(e) => Some(Err(crate::control::transaction::Fault::from(e))),
            })
            .collect::<Result<Vec<_>>>()?;
        if devices.is_empty() {
            continue;
        }
        let t = tenant.clone();
        let rows = {
            let c = &mut *c;
            device::read::active_channel_in(
                rss_mdm_install_support::StorageProfile::Mdm,
                c,
                t,
                devices,
                rss_mdm_inventory::Channel::Mdm,
                purpose,
            )
            .await
        }?;
        for device in rows {
            registrations.insert((device, purpose.as_str()), Some(device));
        }
    }
    let mut permissions = BTreeMap::new();
    let mut controls = Vec::new();
    for operation in operations.values() {
        let mut permitted = !operation.authority.required().is_empty();
        for permission in operation.authority.required() {
            match grant.require(
                proof,
                *permission,
                permission.device().then_some(&operation.device),
            ) {
                Ok(()) => {}
                Err(authorization::error::AuthorizationError::Forbidden) => permitted = false,
                Err(e) => return Err(Error::from(e).into()),
            }
        }
        permissions.insert(operation.id, permitted);
        let registration = registrations
            .get(&(operation.device, operation.request.task.purpose()?.as_str()))
            .cloned()
            .flatten();
        let status = *statuses
            .get(&operation.id)
            .ok_or(Error::Unavailable(Failure::CommandInvariant))?;
        if matches!(
            reauthorization(operation, status, now, registration, true, permitted)?,
            Reauthorization::Available { .. }
        ) && let Authority::DeviceControl { action, .. } = operation.authority
            && device_control::matches(action, &operation.request)?
        {
            controls.push((
                operation.id,
                device_control::Check {
                    device: operation.device,

                    source: operation.request.task.source(),
                    action,
                },
            ));
        }
    }
    let supported = if controls.is_empty() {
        BTreeMap::new()
    } else {
        device_control::applicability_on(
            c,
            queries.tenant,
            queries.apple_results.clone(),
            queries.windows_results.clone(),
            &controls
                .iter()
                .map(|(_, check)| check.clone())
                .collect::<Vec<_>>(),
        )
        .await?
        .into_iter()
        .zip(controls.iter())
        .map(|(state, (id, _))| (*id, state))
        .collect()
    };
    let mut decisions = BTreeMap::new();
    let mut source_ids = Vec::new();
    let mut requests = Vec::new();
    for operation in operations.values() {
        let registration = registrations
            .get(&(operation.device, operation.request.task.purpose()?.as_str()))
            .cloned()
            .flatten();
        let decision = decide(
            operation,
            lifecycle.get(&operation.id) == Some(&true),
            registration,
            true,
        )?;
        if decision.is_authorized() {
            source_ids.push(operation.id);
            requests.push((
                operation.authority.clone(),
                operation.request.task.permissions()?,
            ));
        }
        decisions.insert(operation.id, decision);
    }
    if !requests.is_empty() {
        let key = queries.protection.clone();
        let validity = Authority::valid_many(c, &key, &requests, now).await?;
        for (id, valid) in source_ids.into_iter().zip(validity) {
            if !valid {
                decisions.insert(
                    id,
                    Authorization::Blocked {
                        reason: BlockReason::SourceInvalid,
                    },
                );
            }
        }
    }
    let mut results = BTreeMap::new();
    for operation in operations.values() {
        let registration = registrations
            .get(&(operation.device, operation.request.task.purpose()?.as_str()))
            .cloned()
            .flatten();
        let authorization = decisions.remove(&operation.id).ok_or(Error::Conflict)?;
        let permitted = permissions.get(&operation.id) == Some(&true);
        let status = *statuses
            .get(&operation.id)
            .ok_or(Error::Unavailable(Failure::CommandInvariant))?;
        results.insert(
            operation.id,
            Decision {
                authorization,
                reauthorization: reauthorization(
                    operation,
                    status,
                    now,
                    registration,
                    supported.get(&operation.id) == Some(&device_control::Applicability::Supported),
                    permitted,
                )?,
            },
        );
    }
    Ok(results)
}
