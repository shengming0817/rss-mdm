//! Configuration read models borrow the caller's authorized consistent snapshot.
use super::*;
use crate::authorization::{Permission, Snapshot, context::AuthorizedPrincipal};
use sqlx::PgConnection;
use std::collections::BTreeMap;
mod assignments;
mod evidence;
pub mod records;
use records::*;
impl Transactions {
    pub async fn classify_on(
        &self,
        c: &mut PgConnection,
        proof: &AuthorizedPrincipal,
        grant: &Snapshot,
        ids: Vec<Uuid>,
        _now: i64,
    ) -> Result<BTreeMap<Uuid, Authorization>> {
        let operations = storage::load_many_on(c, self.tenant, &self.protection, ids).await?;
        let targets = operations
            .values()
            .map(|o| (o.id, o.device))
            .collect::<Vec<_>>();
        let lifecycle = rss_mdm_device_service::lifecycle::execution_permissions_in(
            c,
            &self.tenant.to_string(),
            &targets,
        )
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
                    Err(e) => Some(Err(e)),
                })
                .collect::<std::result::Result<Vec<_>, _>>()?;
            if devices.is_empty() {
                continue;
            }
            let rows = rss_mdm_registration_service::device::read::active_channel_in(
                rss_mdm_install_support::StorageProfile::Mdm,
                c,
                self.tenant.to_string(),
                devices,
                rss_mdm_inventory::Channel::Mdm,
                purpose,
            )
            .await?;
            for device in rows {
                registrations
                    .entry((device, purpose.as_str()))
                    .and_modify(|v| *v = None)
                    .or_insert(Some(device));
            }
        }
        let mut results = BTreeMap::new();
        let mut pending = Vec::new();
        let mut authorities = Vec::new();
        for op in operations.values() {
            grant.require(proof, Permission::OperationRead, Some(&op.device))?;
            let current = registrations
                .get(&(op.device, op.request.task.purpose()?.as_str()))
                .cloned()
                .flatten();
            let reason = if lifecycle.get(&op.id) != Some(&true) {
                Some(BlockReason::LifecycleBlocked)
            } else if current != Some(op.device) {
                Some(BlockReason::DeviceInactive)
            } else {
                pending.push(op.id);
                authorities.push((op.authority.clone(), op.request.task.permissions()?));
                continue;
            };
            results.insert(
                op.id,
                reason.map_or(Authorization::Authorized, |reason| Authorization::Blocked {
                    reason,
                }),
            );
        }
        let valid = authority::many(&self.source, c, &self.protection, &authorities).await?;
        for (id, valid) in pending.into_iter().zip(valid) {
            results.insert(
                id,
                if valid {
                    Authorization::Authorized
                } else {
                    Authorization::Blocked {
                        reason: BlockReason::SourceInvalid,
                    }
                },
            );
        }
        Ok(results)
    }
    pub async fn detail_on(
        &self,
        c: &mut PgConnection,
        proof: &AuthorizedPrincipal,
        grant: &Snapshot,
        now: i64,
        device: &rss_mdm_agent_wire::DeviceId,
        id: Uuid,
    ) -> Result<Detail> {
        grant.require(proof, Permission::OperationRead, Some(device))?;
        let op = storage::load_on(c, self.tenant, &self.protection, id).await?;
        if op.device != *device {
            return Err(Error::Forbidden.into());
        }
        let authorization = self
            .classify_on(c, proof, grant, vec![id], now)
            .await?
            .remove(&id)
            .ok_or(Error::Conflict)?;
        let status = self.status_on(c, id).await?;
        let values = native_values(grant, proof, &op)?;
        let observation = self
            .observations_on(c, &[(&op, status)], values)
            .await?
            .remove(&id)
            .ok_or(Error::Conflict)?;
        Ok(Detail {
            operation_id: id,
            command_id: id,
            revision: op.revision,
            task: op.request.task.summary()?,
            target: op.request.target,
            input_version: op.request.input_version,
            deadline: op.request.deadline,
            dispatch_failure: op.dispatch_failure,
            authorization,
            command_status: status,
            observation,
        })
    }
    pub async fn evidence_on(
        &self,
        c: &mut PgConnection,
        proof: &AuthorizedPrincipal,
        grant: &Snapshot,
        ids: Vec<Uuid>,
    ) -> Result<BTreeMap<Uuid, Evidence>> {
        let operations = storage::load_many_on(c, self.tenant, &self.protection, ids).await?;
        let mut statuses = BTreeMap::new();
        for op in operations.values() {
            grant.require(proof, Permission::OperationRead, Some(&op.device))?;
            statuses.insert(op.id, self.status_on(c, op.id).await?);
        }
        let selected = operations
            .values()
            .map(|o| (o, statuses[&o.id]))
            .collect::<Vec<_>>();
        let mut evidence = self.observations_on(c, &selected, false).await?;
        operations
            .into_iter()
            .map(|(id, op)| {
                Ok((
                    id,
                    Evidence {
                        command_status: statuses[&id],
                        observation: evidence.remove(&id).ok_or(Error::Conflict)?,
                        dispatch_failure: op.dispatch_failure,
                    },
                ))
            })
            .collect()
    }
    pub async fn declarations_on(
        &self,
        c: &mut PgConnection,
        proof: &AuthorizedPrincipal,
        grant: &Snapshot,
        target: &rss_mdm_registration_service::device::endpoints::PrimaryRegistration,
        ids: Vec<Uuid>,
    ) -> Result<BTreeMap<Uuid, Declaration>> {
        let device = &target.device;
        let registration = &target.device;

        grant.require(proof, Permission::OperationRead, Some(device))?;
        let operations = storage::load_many_on(c, self.tenant, &self.protection, ids).await?;
        let mut result = BTreeMap::new();
        for (id, op) in operations {
            if op.device != *device {
                return Err(Error::Conflict.into());
            }
            let allowed = native_values(grant, proof, &op)?;
            let status = self.status_on(c, id).await?;
            let observation = self
                .observations_on(c, &[(&op, status)], allowed)
                .await?
                .remove(&id)
                .ok_or(Error::Conflict)?;
            result.insert(
                id,
                Declaration {
                    device: *registration,

                    redacted: !allowed,
                    observation,
                },
            );
        }
        Ok(result)
    }
    async fn status_on(&self, c: &mut PgConnection, id: Uuid) -> Result<dc::Status> {
        let status:Option<String>=sqlx::query_scalar("SELECT status FROM rss_device_command.commands WHERE tenant_id=$1::uuid AND command_id=$2").bind(self.tenant.to_string()).bind(id.to_string()).fetch_optional(c).await?;
        stored(dc::Status::restore(
            &status.ok_or(Error::Unavailable(Failure::CommandInvariant))?,
        ))
    }
}
fn native_values(
    snapshot: &Snapshot,
    proof: &AuthorizedPrincipal,
    op: &storage::Operation,
) -> Result<bool> {
    let mut values = true;
    if matches!(
        op.request.task,
        Task::Macos {
            request: rss_mdm_apple_mdm::native::request::Request::Command { .. }
                | rss_mdm_apple_mdm::native::request::Request::Declarations { .. }
        }
    ) {
        let mut required = op.request.task.permissions()?;
        required.extend_from_slice(op.authority.required());
        required.sort();
        required.dedup();
        if required.is_empty() {
            return Err(Error::Forbidden.into());
        }
        for p in required {
            snapshot.require(proof, p, p.device().then_some(&op.device))?;
        }
    }
    if op.request.profile_target().is_some() {
        let mut required = op.request.task.permissions()?;
        required.extend_from_slice(op.authority.required());
        required.push(Permission::InventoryCollect);
        required.sort();
        required.dedup();
        for p in required {
            match snapshot.require(proof, p, p.device().then_some(&op.device)) {
                Ok(()) => {}
                Err(crate::authorization::error::AuthorizationError::Forbidden) => values = false,
                Err(e) => return Err(Error::from(e).into()),
            }
        }
    }
    Ok(values)
}
