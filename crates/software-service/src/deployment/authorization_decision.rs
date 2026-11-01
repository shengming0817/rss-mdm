//! One current authorization result; a read never grants permission to a later write.
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BlockReason {
    LifecycleBlocked,
    RegistrationChanged,
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
    RegistrationChanged,
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

use crate::deployment::{authority::Authority, storage::Operation, *};
use std::collections::BTreeMap;

pub(crate) fn decide(
    operation: &Operation,
    lifecycle: bool,
    registration: Option<(Uuid, i64)>,
    source: bool,
) -> Result<Authorization> {
    let reason = if !lifecycle {
        Some(BlockReason::LifecycleBlocked)
    } else if registration != Some((operation.registration, operation.registration_generation)) {
        Some(BlockReason::RegistrationChanged)
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
    queries: &crate::deployment::queries::Queries,
    c: &mut sqlx::PgConnection,
    _proof: &authorization::context::AuthorizedPrincipal,
    _grant: &authorization::Snapshot,
    operations: &BTreeMap<Uuid, Operation>,
    _statuses: &BTreeMap<Uuid, dc::Status>,
    now: i64,
) -> Result<BTreeMap<Uuid, Decision>> {
    if operations.is_empty() {
        return Ok(BTreeMap::new());
    }
    let tenant = queries.tenant.to_string();
    let targets = operations
        .values()
        .map(|o| (o.id, o.device.clone()))
        .collect::<Vec<_>>();
    let t = tenant.clone();
    let lifecycle = queries
        .lifecycle
        .execution_permissions_on(c, &t, &targets)
        .await?;
    let mut registrations = BTreeMap::new();
    for purpose in [
        rss_mdm_registration_service::Purpose::Primary,
        rss_mdm_registration_service::Purpose::WindowsDeclared,
    ] {
        let devices = operations
            .values()
            .filter_map(|o| match o.request.task.purpose() {
                Ok(p) if p == purpose => Some(Ok(o.device.clone())),
                Ok(_) => None,
                Err(e) => Some(Err(crate::deployment::transaction::Fault::from(e))),
            })
            .collect::<Result<Vec<_>>>()?;
        if devices.is_empty() {
            continue;
        }
        let t = tenant.clone();
        let rows = {
            let c = &mut *c;
            device::read::active_channel_in(c, t, devices, rss_mdm_inventory::Channel::Mdm, purpose)
                .await
        }?;
        let mut current = BTreeMap::<String, Option<(Uuid, i64)>>::new();
        for (device, id, generation) in rows {
            current
                .entry(device)
                .and_modify(|v| *v = None)
                .or_insert(Some((id, generation)));
        }
        for (device, value) in current {
            registrations.insert((device, purpose.as_str()), value);
        }
    }
    let mut decisions = BTreeMap::new();
    let mut source_ids = Vec::new();
    let mut requests = Vec::new();
    for operation in operations.values() {
        let registration = registrations
            .get(&(
                operation.device.clone(),
                operation.request.task.purpose()?.as_str(),
            ))
            .copied()
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
        let source = queries.source.clone();
        let validity = Authority::valid_many(
            source.as_ref(),
            queries.lifecycle.as_ref(),
            c,
            &key,
            &requests,
            now,
        )
        .await?;
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
    Ok(decisions
        .into_iter()
        .map(|(id, authorization)| {
            (
                id,
                Decision {
                    authorization,
                    reauthorization: Reauthorization::NotApplicable,
                },
            )
        })
        .collect())
}
