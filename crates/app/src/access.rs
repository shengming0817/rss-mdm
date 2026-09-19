//! MDM alone owns roles and device permissions. Identity facts never contain them.
use crate::Error;
use crate::device::{DeviceService, ReportSource};
use crate::identity::Principal;
use crate::{ConfigIssue, Failure};
use rss_observation::{Id, Scope};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    SuperAdmin,
    MdmAdmin,
    SecurityAdmin,
    HelpDesk,
    Auditor,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub tenant_id: String,
    pub instance_id: String,
    pub principal_id: String,
    pub roles: BTreeSet<Role>,
    pub devices: BTreeSet<String>,
    pub management: BTreeSet<crate::management::Permission>,
    pub identity_management: BTreeSet<IdentityPermission>,
    pub allow_wipe: bool,
    pub allow_enrollment: bool,
    pub allow_manage_credentials: bool,
}
pub(crate) struct Policy {
    tenant: String,
    instance: String,
    bindings: BTreeMap<String, Binding>,
}
pub(crate) struct InventoryRead<'a> {
    proof: &'a Principal,
    device: String,
    coordinates: Coordinates,
}
pub(crate) struct DangerousAction<'a> {
    _proof: &'a Principal,
}
#[derive(Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Coordinates {
    pub source: ReportSource,
}
impl Policy {
    pub fn new(tenant: &str, instance: &str, bindings: Vec<Binding>) -> Result<Self, Error> {
        let id = rss_identity_core::InstanceId::parse(instance)
            .map_err(|_| Error::Configuration(ConfigIssue::Instance))?;
        if id.to_string() != instance || bindings.len() > 10000 {
            return Err(Error::Configuration(ConfigIssue::Instance));
        }
        let mut entries = BTreeMap::new();
        for b in bindings {
            if !rss_identity_core::PrincipalId::parse(&b.principal_id)
                .is_ok_and(|id| id.as_uuid().to_string() == b.principal_id)
                || b.tenant_id != tenant
                || b.instance_id != instance
                || b.principal_id.is_empty()
                || b.principal_id.len() > 255
                || b.principal_id.contains('*')
                || b.principal_id.chars().any(char::is_control)
                || (b.devices.is_empty()
                    && b.management.is_empty()
                    && b.identity_management.is_empty())
                || b.devices.len() > 10000
                || b.devices
                    .iter()
                    .any(|d| d != "*" && rss_observation::Id::new(d).is_err())
                || (b.devices.contains("*") && b.devices.len() != 1)
                || ((b.allow_wipe || b.allow_enrollment || b.allow_manage_credentials)
                    && !b
                        .roles
                        .iter()
                        .any(|r| matches!(r, Role::SuperAdmin | Role::MdmAdmin)))
                || entries.insert(b.principal_id.clone(), b).is_some()
            {
                return Err(Error::Configuration(ConfigIssue::Bindings));
            }
        }
        Ok(Self {
            tenant: tenant.into(),
            instance: instance.into(),
            bindings: entries,
        })
    }
    pub(crate) fn identity_navigation(&self, proof: &Principal) -> Result<(bool, bool), Error> {
        let binding = self.binding(proof)?;
        Ok((
            binding.is_some_and(|b| {
                b.identity_management
                    .contains(&IdentityPermission::Accounts)
            }),
            binding.is_some_and(|b| {
                b.identity_management
                    .contains(&IdentityPermission::Providers)
            }),
        ))
    }
    pub(crate) fn tenant(&self) -> &str {
        &self.tenant
    }
    fn binding(&self, proof: &Principal) -> Result<Option<&Binding>, Error> {
        proof.check_live()?;
        if proof.tenant_id() != self.tenant || proof.instance_id() != self.instance {
            return Err(Error::Unauthorized);
        }
        Ok(self.bindings.get(proof.principal_id()))
    }
    pub fn enrollment<'a>(
        &self,
        proof: &'a Principal,
        device: &str,
    ) -> Result<EnrollmentPermission<'a>, Error> {
        let b = self.device(proof, device)?;
        if !b.allow_enrollment
            || !b
                .roles
                .iter()
                .any(|r| matches!(r, Role::SuperAdmin | Role::MdmAdmin))
        {
            return Err(Error::Forbidden);
        }
        Ok(EnrollmentPermission {
            proof,
            device: device.to_owned(),
        })
    }
    pub(crate) fn publisher(&self, subject: &str) -> Result<(), Error> {
        if !self.bindings.get(subject).is_some_and(|b| {
            b.management
                .contains(&crate::management::Permission::ReleasePublish)
        }) {
            return Err(Error::Forbidden);
        }
        Ok(())
    }
    pub(crate) fn manage(
        &self,
        proof: &Principal,
        permission: crate::management::Permission,
    ) -> Result<(), Error> {
        let binding = self.binding(proof)?.ok_or(Error::Forbidden)?;
        if !binding.management.contains(&permission) {
            return Err(Error::Forbidden);
        }
        Ok(())
    }
    pub fn roles(&self, proof: &Principal) -> Result<Vec<Role>, Error> {
        Ok(self
            .binding(proof)?
            .map(|b| b.roles.iter().copied().collect())
            .unwrap_or_default())
    }
    fn device(&self, proof: &Principal, device: &str) -> Result<&Binding, Error> {
        let b = self.binding(proof)?.ok_or(Error::Forbidden)?;
        if b.roles.is_empty() || !(b.devices.contains(device) || b.devices.contains("*")) {
            return Err(Error::Forbidden);
        }
        Ok(b)
    }
    pub fn inventory<'a>(
        &self,
        proof: &'a Principal,
        device: &str,
        c: Coordinates,
    ) -> Result<InventoryRead<'a>, Error> {
        self.device(proof, device)?;
        Id::new(device).map_err(|_| Error::Malformed)?;
        Ok(InventoryRead {
            proof,
            device: device.into(),
            coordinates: c,
        })
    }
    pub(crate) fn credentials(&self, proof: &Principal, device: &str) -> Result<(), Error> {
        let b = self.device(proof, device)?;
        if !b.allow_manage_credentials
            || !b
                .roles
                .iter()
                .any(|r| matches!(r, Role::SuperAdmin | Role::MdmAdmin))
        {
            return Err(Error::Forbidden);
        }
        Ok(())
    }

    pub fn dangerous<'a>(
        &self,
        proof: &'a Principal,
        device: &str,
    ) -> Result<DangerousAction<'a>, Error> {
        let b = self.device(proof, device)?;
        if !b.allow_wipe
            || !b
                .roles
                .iter()
                .any(|r| matches!(r, Role::SuperAdmin | Role::MdmAdmin))
        {
            return Err(Error::Forbidden);
        }
        Ok(DangerousAction { _proof: proof })
    }
}
#[derive(Serialize)]
pub(crate) struct InventoryResponse {
    tenant_id: String,
    device_id: String,
    registration: String,
    source: ReportSource,
    epoch: String,
    coverage: rss_observation::Coverage,
    availability: Availability,
    fields: Vec<FieldResponse>,
    latest_run: Option<RunSummary>,
    delivery: Option<crate::inventory_runtime::DeliveryStatus>,
}
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum Availability {
    Current,
    LastKnown,
    Unavailable,
}
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum TimeBasis {
    ServerReceived,
}
#[derive(Serialize)]
struct LastGood {
    value: String,
    batch_id: String,
    reported_at: i64,
    received_at: i64,
}
#[derive(Serialize)]
struct LatestAttempt {
    run_id: uuid::Uuid,
    quality: crate::collection::Quality,
    status: Option<u16>,
    time_basis: TimeBasis,
    received_at: Option<i64>,
}
#[derive(Serialize)]
struct FieldResponse {
    field: &'static str,
    last_good: Option<LastGood>,
    latest_attempt: Option<LatestAttempt>,
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

pub(crate) struct InventoryService {
    reader: std::sync::Arc<rss_mdm_inventory_postgres::InventoryReader>,
    devices: std::sync::Arc<DeviceService>,
    access: std::sync::Arc<crate::AccessStore>,
    runtime: std::sync::Arc<crate::inventory_runtime::InventoryRuntime>,
}
impl InventoryService {
    pub(super) fn new(
        reader: std::sync::Arc<rss_mdm_inventory_postgres::InventoryReader>,
        devices: std::sync::Arc<DeviceService>,
        access: std::sync::Arc<crate::AccessStore>,
        runtime: std::sync::Arc<crate::inventory_runtime::InventoryRuntime>,
    ) -> Self {
        Self {
            reader,
            devices,
            access,
            runtime,
        }
    }
    pub async fn read(&self, grant: InventoryRead<'_>) -> Result<InventoryResponse, Error> {
        let scope: Scope = self
            .devices
            .current_scope(grant.proof, &grant.device, grant.coordinates)
            .await?;
        let (run, fields, delivery) = self
            .read_state(
                &scope,
                #[cfg(test)]
                std::future::ready(()),
            )
            .await?;
        let current = run.as_ref().is_some_and(|r| {
            r.result == crate::collection::RunResult::Snapshot
                && fields.len() == rss_mdm_inventory::FieldKey::ALL.len()
                && fields.iter().all(|f| f.batch_id == r.id.to_string())
        }) && delivery
            .as_ref()
            .is_some_and(|d| d.projection == crate::inventory_runtime::ProjectionStatus::Projected);
        let availability = if current {
            Availability::Current
        } else if fields.is_empty() {
            Availability::Unavailable
        } else {
            Availability::LastKnown
        };
        let fields = rss_mdm_inventory::FieldKey::ALL
            .iter()
            .enumerate()
            .map(|(index, key)| {
                let good = fields.iter().find(|f| f.field == key.as_str());
                FieldResponse {
                    field: key.as_str(),
                    last_good: good.map(|f| LastGood {
                        value: f.value.clone(),
                        batch_id: f.batch_id.clone(),
                        reported_at: f.observed_at,
                        received_at: f.received_at,
                    }),
                    latest_attempt: run.as_ref().map(|r| LatestAttempt {
                        run_id: r.id,
                        quality: r.attempts.fields[index].quality,
                        status: r.attempts.fields[index].status,
                        time_basis: TimeBasis::ServerReceived,
                        received_at: r.attempts.fields[index].received_at,
                    }),
                }
            })
            .collect();
        Ok(InventoryResponse {
            tenant_id: scope.tenant().to_string(),
            device_id: grant.device,
            registration: scope.registration().as_str().to_owned(),
            source: grant.coordinates.source,
            epoch: scope.epoch().as_str().to_owned(),
            coverage: rss_mdm_inventory::coverage(),
            availability,
            fields,
            latest_run: run.as_ref().map(run_summary),
            delivery,
        })
    }

    pub(crate) async fn read_state(
        &self,
        scope: &Scope,
        #[cfg(test)] after_run: impl std::future::Future<Output = ()>,
    ) -> Result<
        (
            Option<crate::collection::Run>,
            Vec<rss_mdm_inventory_postgres::InventoryField>,
            Option<crate::inventory_runtime::DeliveryStatus>,
        ),
        Error,
    > {
        #[cfg(test)]
        let mut after_run = Some(after_run);
        for _ in 0..3 {
            let run = self.access.collection(scope, None).await?;
            #[cfg(test)]
            if let Some(interleaving) = after_run.take() {
                interleaving.await;
            }
            let fields = self
                .reader
                .read(scope)
                .await
                .map_err(|_| Error::Unavailable(Failure::InventoryQuery))?;
            let delivery = match &run {
                Some(run) => Some(self.runtime.inspect(run).await?),
                None => None,
            };
            // Runs only advance and projected fields retain their immutable batch identity.
            // Matching reads bracket inspection at one common state across the owned stores.
            let same_run = run == self.access.collection(scope, None).await?;
            let same_fields = fields
                == self
                    .reader
                    .read(scope)
                    .await
                    .map_err(|_| Error::Unavailable(Failure::InventoryQuery))?;
            if same_run && same_fields {
                return Ok((run, fields, delivery));
            }
        }
        Err(Error::Unavailable(Failure::InventoryQuery))
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
        let fields = rss_mdm_inventory::FieldKey::ALL
            .iter()
            .zip(&run.attempts.fields)
            .map(|(key, attempt)| RunField {
                field: key.as_str(),
                quality: attempt.quality,
                status: attempt.status,
                received_at: attempt.received_at,
                time_basis: TimeBasis::ServerReceived,
            })
            .collect();
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
    const INSTANCE: &str = "33333333-3333-4333-8333-333333333333";
    #[test]
    fn instance_is_a_canonical_persistent_coordinate() {
        assert!(Policy::new("tenant", INSTANCE, vec![]).is_ok());
        assert!(Policy::new("tenant", "unscoped", vec![]).is_err());
    }
    fn binding() -> Binding {
        Binding {
            tenant_id: "tenant".into(),
            instance_id: INSTANCE.into(),
            principal_id: "44444444-4444-4444-8444-444444444444".into(),
            roles: [Role::Auditor].into(),
            devices: ["device".into()].into(),
            management: BTreeSet::new(),
            identity_management: BTreeSet::new(),
            allow_wipe: false,
            allow_enrollment: false,
            allow_manage_credentials: false,
        }
    }
    #[test]
    fn configuration_never_infers_roles_or_dangerous_grants() {
        assert!(Policy::new("tenant", INSTANCE, vec![binding()]).is_ok());
        assert!(Policy::new("tenant", INSTANCE, vec![binding(), binding()]).is_err());
        let mut b = binding();
        b.allow_wipe = true;
        assert!(Policy::new("tenant", INSTANCE, vec![b]).is_err());
        let mut b = binding();
        b.tenant_id = "other".into();
        assert!(Policy::new("tenant", INSTANCE, vec![b]).is_err());
        let mut b = binding();
        b.principal_id = "*".into();
        assert!(Policy::new("tenant", INSTANCE, vec![b]).is_err());
        let mut b = binding();
        b.devices.insert("*".into());
        assert!(Policy::new("tenant", INSTANCE, vec![b]).is_err());
        let mut b = binding();
        b.allow_manage_credentials = true;
        assert!(Policy::new("tenant", INSTANCE, vec![b]).is_err());
        assert!(serde_json::from_str::<Role>("\"administrator\"").is_err());
    }
}

/// Product-owned grants for the embedded account and provider management interfaces.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "snake_case")]
pub enum IdentityPermission {
    Accounts,
    Providers,
}
impl rss_identity_postgres::ManagementPolicy for Policy {
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
            .bindings
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
        if !actor.identity_management.contains(&permission) {
            return Err(ManagementDenied);
        }
        // Protect every restart-owned account manager from disabling/removing membership.
        if matches!(
            context.operation(),
            Op::SetAccountEnabled(false) | Op::SetMembership(false)
        ) && context.target().is_some_and(|key| {
            self.bindings
                .get(&key.principal.as_uuid().to_string())
                .is_some_and(|binding| {
                    binding
                        .identity_management
                        .contains(&IdentityPermission::Accounts)
                })
        }) {
            return Err(ManagementDenied);
        }
        Ok(match context.operation() {
            Op::ListAccounts | Op::ListProviders => Auth::None,
            _ => Auth::Recent(std::time::Duration::from_secs(300)),
        })
    }
}
