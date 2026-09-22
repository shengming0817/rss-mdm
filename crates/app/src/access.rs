//! Inventory access capabilities and independent Identity management configuration.
use crate::authorization::Permission;
use crate::device::DeviceService;
use crate::identity::Principal;
use crate::{ConfigIssue, Error};
use rss_mdm_inventory::ReportSource;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityManagementGrant {
    pub tenant_id: String,
    pub instance_id: String,
    pub principal_id: String,
    pub permissions: BTreeSet<IdentityPermission>,
}
pub(crate) struct IdentityManagementPolicy {
    tenant: String,
    instance: String,
    grants: BTreeMap<String, IdentityManagementGrant>,
}
impl IdentityManagementPolicy {
    pub(crate) fn new(
        tenant: &str,
        instance: &str,
        grants: Vec<IdentityManagementGrant>,
    ) -> Result<Self, Error> {
        let invalid = || Error::Configuration(ConfigIssue::IdentityConfiguration);
        crate::authorization::canonical_uuid(tenant).map_err(|_| invalid())?;
        crate::authorization::canonical_uuid(instance).map_err(|_| invalid())?;
        if grants.len() > 10000 {
            return Err(invalid());
        }
        let mut entries = BTreeMap::new();
        for grant in grants {
            crate::authorization::canonical_uuid(&grant.principal_id).map_err(|_| invalid())?;
            if grant.tenant_id != tenant
                || grant.instance_id != instance
                || grant.permissions.is_empty()
                || entries.insert(grant.principal_id.clone(), grant).is_some()
            {
                return Err(invalid());
            }
        }
        Ok(Self {
            tenant: tenant.into(),
            instance: instance.into(),
            grants: entries,
        })
    }
    pub(crate) fn identity_navigation(
        &self,
        proof: &Principal,
    ) -> Result<IdentityNavigation, Error> {
        proof.check_live()?;
        if proof.tenant_id() != self.tenant || proof.instance_id() != self.instance {
            return Err(Error::Unauthorized);
        }
        let grant = self.grants.get(proof.principal_id());
        Ok(IdentityNavigation {
            manage_accounts: grant
                .is_some_and(|g| g.permissions.contains(&IdentityPermission::Accounts)),
            manage_providers: grant
                .is_some_and(|g| g.permissions.contains(&IdentityPermission::Providers)),
        })
    }
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IdentityNavigation {
    pub(crate) manage_accounts: bool,
    pub(crate) manage_providers: bool,
}
#[derive(Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Coordinates {
    pub source: ReportSource,
}
pub(crate) struct InventoryRead<'a> {
    proof: &'a Principal,
    device: String,
    coordinates: Coordinates,
}
pub(crate) struct DangerousAction<'a> {
    _proof: &'a Principal,
}
impl Principal {
    pub(crate) fn enrollment(&self, device: &str) -> Result<EnrollmentPermission<'_>, Error> {
        self.require(Permission::Enrollment, Some(device))?;
        Ok(EnrollmentPermission {
            proof: self,
            device: device.into(),
        })
    }
    pub(crate) fn inventory(
        &self,
        device: &str,
        coordinates: Coordinates,
    ) -> Result<InventoryRead<'_>, Error> {
        self.require(Permission::InventoryRead, Some(device))?;
        Ok(InventoryRead {
            proof: self,
            device: device.into(),
            coordinates,
        })
    }
    pub(crate) fn credentials(&self, device: &str) -> Result<(), Error> {
        self.require(Permission::Credentials, Some(device))
    }
    pub(crate) fn manage(&self, permission: Permission) -> Result<(), Error> {
        self.require(permission, None)
    }
    pub(crate) fn dangerous(&self, device: &str) -> Result<DangerousAction<'_>, Error> {
        self.require(Permission::DeviceWipe, Some(device))?;
        Ok(DangerousAction { _proof: self })
    }
}
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum TimeBasis {
    ServerReceived,
}
#[derive(Serialize)]
struct RunSummary {
    run_id: uuid::Uuid,
    sequence: u64,
    result: crate::collection::RunResult,
    reason: Option<crate::collection::FinishReason>,
    started_at: i64,
    finished_at: Option<i64>,
    time_basis: TimeBasis,
}
#[derive(Serialize)]
struct RunField {
    field: &'static str,
    quality: crate::collection::Quality,
    status: Option<u16>,
    received_at: Option<i64>,
    time_basis: TimeBasis,
}
#[derive(Serialize)]
pub(crate) struct CollectionResponse {
    run: RunSummary,
    registration: String,
    source: ReportSource,
    epoch: String,
    coverage: rss_observation::Coverage,
    fields: Vec<RunField>,
    delivery: crate::inventory_runtime::DeliveryStatus,
}

pub(crate) struct CollectionService {
    devices: std::sync::Arc<DeviceService>,
    access: std::sync::Arc<crate::AccessStore>,
    runtime: std::sync::Arc<crate::inventory_runtime::InventoryRuntime>,
}
impl CollectionService {
    pub(super) fn new(
        devices: std::sync::Arc<DeviceService>,
        access: std::sync::Arc<crate::AccessStore>,
        runtime: std::sync::Arc<crate::inventory_runtime::InventoryRuntime>,
    ) -> Self {
        Self {
            devices,
            access,
            runtime,
        }
    }
    pub(crate) async fn run(
        &self,
        grant: InventoryRead<'_>,
        id: uuid::Uuid,
    ) -> Result<CollectionResponse, Error> {
        let scope = self
            .devices
            .current_scope(grant.proof, &grant.device, grant.coordinates)
            .await?;
        let run = self
            .access
            .collection(&scope, Some(id))
            .await?
            .ok_or(Error::NotFound)?;
        let fields = rss_mdm_inventory::FieldKey::observed()
            .zip(&run.attempts.fields)
            .map(|(key, attempt)| RunField {
                field: key.as_str(),
                quality: attempt.quality,
                status: attempt.status,
                received_at: attempt.received_at,
                time_basis: TimeBasis::ServerReceived,
            })
            .collect();
        grant.proof.inventory(&grant.device, grant.coordinates)?;
        Ok(CollectionResponse {
            run: run_summary(&run),
            registration: scope.registration().as_str().to_owned(),
            source: grant.coordinates.source,
            epoch: scope.epoch().as_str().to_owned(),
            coverage: rss_mdm_inventory::coverage(),
            fields,
            delivery: self.runtime.inspect(&run).await?,
        })
    }
    pub(crate) async fn inspect_agent(
        &self,
        report: &crate::collection::DurableReport,
    ) -> Result<crate::inventory_runtime::DeliveryStatus, Error> {
        self.runtime
            .inspect_report(report.scope(), report.batch())
            .await
    }
}
fn run_summary(run: &crate::collection::Run) -> RunSummary {
    RunSummary {
        run_id: run.id,
        sequence: run.sequence,
        result: run.result,
        reason: run.reason,
        started_at: run.started_at,
        finished_at: run.sealed_at,
        time_basis: TimeBasis::ServerReceived,
    }
}

pub(crate) struct EnrollmentPermission<'a> {
    proof: &'a Principal,
    device: String,
}
impl EnrollmentPermission<'_> {
    pub(super) fn proof(&self) -> &Principal {
        self.proof
    }
    pub(super) fn device(&self) -> &str {
        &self.device
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn current_inventory_rejects_caller_selected_generation() {
        assert!(
            serde_json::from_str::<Coordinates>(
                r#"{"registration":"old","source":"mdm.windows","epoch":"old"}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<Coordinates>(r#"{"channel":"mdm","source":"mdm.windows"}"#)
                .is_err()
        );
        assert!(serde_json::from_str::<Coordinates>(r#"{"source":"mdm.windows"}"#).is_ok());
        assert!(serde_json::from_str::<Coordinates>(r#"{"source":"invented"}"#).is_err());
    }
}

/// Product-owned grants for the embedded account and provider management interfaces.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "snake_case")]
pub enum IdentityPermission {
    Accounts,
    Providers,
}
impl rss_identity_postgres::ManagementPolicy for IdentityManagementPolicy {
    fn authorize(
        &self,
        context: &rss_identity_postgres::ManagementContext<'_>,
    ) -> Result<
        rss_identity_postgres::ReauthenticationRequirement,
        rss_identity_postgres::ManagementDenied,
    > {
        use rss_identity_postgres::{
            ManagementDenied, ManagementOperation as Op, ReauthenticationRequirement as Auth,
        };
        if context.instance().to_string() != self.instance
            || context.actor().tenant.to_string() != self.tenant
            || context
                .target()
                .is_some_and(|target| target.tenant != context.actor().tenant)
        {
            return Err(ManagementDenied);
        }
        if context.operation() == Op::ChangeOwnPassword {
            return if context.target() == Some(context.actor()) {
                Ok(Auth::Recent(std::time::Duration::from_secs(300)))
            } else {
                Err(ManagementDenied)
            };
        }
        let actor = self
            .grants
            .get(&context.actor().principal.as_uuid().to_string())
            .ok_or(ManagementDenied)?;
        let permission = match context.operation() {
            Op::ListProviders
            | Op::CreateProvider
            | Op::UpdateProvider(_)
            | Op::SetProviderEnabled(_, _)
            | Op::TestProvider(_) => IdentityPermission::Providers,
            _ => IdentityPermission::Accounts,
        };
        if !actor.permissions.contains(&permission) {
            return Err(ManagementDenied);
        }
        // Protect every restart-owned account manager from disabling/removing membership.
        if matches!(
            context.operation(),
            Op::SetAccountEnabled(false) | Op::SetMembership(false)
        ) && context.target().is_some_and(|key| {
            self.grants
                .get(&key.principal.as_uuid().to_string())
                .is_some_and(|binding| binding.permissions.contains(&IdentityPermission::Accounts))
        }) {
            return Err(ManagementDenied);
        }
        Ok(match context.operation() {
            Op::ListAccounts | Op::ListProviders => Auth::None,
            _ => Auth::Recent(std::time::Duration::from_secs(300)),
        })
    }
}
