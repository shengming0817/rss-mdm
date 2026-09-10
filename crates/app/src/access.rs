//! MDM alone owns roles and device permissions. Identity facts never contain them.
use crate::Error;
use crate::device::{Channel, DeviceService};
use crate::{ConfigIssue, Failure};
use rss_identity_client::VerifiedIdentity;
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
    pub client_id: String,
    pub subject: String,
    pub roles: BTreeSet<Role>,
    pub devices: BTreeSet<String>,
    pub allow_wipe: bool,
    pub allow_enrollment: bool,
    pub allow_manage_credentials: bool,
}
pub(crate) struct Policy {
    tenant: String,
    client: String,
    bindings: BTreeMap<String, Binding>,
}
pub(crate) struct InventoryRead<'a> {
    proof: &'a VerifiedIdentity,
    device: String,
    coordinates: Coordinates,
}
pub(crate) struct DangerousAction<'a> {
    _proof: &'a VerifiedIdentity,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Coordinates {
    pub channel: Channel,
    pub source: String,
}
impl Policy {
    pub fn new(tenant: &str, client: &str, bindings: Vec<Binding>) -> Result<Self, Error> {
        if client.is_empty()
            || client.len() > 255
            || client.contains('*')
            || client.contains(':')
            || bindings.len() > 10000
        {
            return Err(Error::Configuration(ConfigIssue::ClientId));
        }
        let mut entries = BTreeMap::new();
        for b in bindings {
            if b.tenant_id != tenant
                || b.client_id != client
                || b.subject.is_empty()
                || b.subject.len() > 255
                || b.subject.contains('*')
                || b.subject.chars().any(char::is_control)
                || b.devices.is_empty()
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
                || entries.insert(b.subject.clone(), b).is_some()
            {
                return Err(Error::Configuration(ConfigIssue::Bindings));
            }
        }
        Ok(Self {
            tenant: tenant.into(),
            client: client.into(),
            bindings: entries,
        })
    }
    pub(crate) fn tenant(&self) -> &str {
        &self.tenant
    }
    fn binding(&self, proof: &VerifiedIdentity) -> Result<Option<&Binding>, Error> {
        if proof.tenant_id() != self.tenant || proof.client_id() != self.client {
            return Err(Error::Unauthorized);
        }
        Ok(self.bindings.get(proof.subject()))
    }
    pub fn enrollment<'a>(
        &self,
        proof: &'a VerifiedIdentity,
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
    pub fn roles(&self, proof: &VerifiedIdentity) -> Result<Vec<Role>, Error> {
        Ok(self
            .binding(proof)?
            .map(|b| b.roles.iter().copied().collect())
            .unwrap_or_default())
    }
    fn device(&self, proof: &VerifiedIdentity, device: &str) -> Result<&Binding, Error> {
        let b = self.binding(proof)?.ok_or(Error::Forbidden)?;
        if b.roles.is_empty() || !(b.devices.contains(device) || b.devices.contains("*")) {
            return Err(Error::Forbidden);
        }
        Ok(b)
    }
    pub fn inventory<'a>(
        &self,
        proof: &'a VerifiedIdentity,
        device: &str,
        c: Coordinates,
    ) -> Result<InventoryRead<'a>, Error> {
        self.device(proof, device)?;
        Id::new(&c.source).map_err(|_| Error::Malformed)?;
        Ok(InventoryRead {
            proof,
            device: device.into(),
            coordinates: c,
        })
    }
    pub(crate) fn credentials(&self, proof: &VerifiedIdentity, device: &str) -> Result<(), Error> {
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
        proof: &'a VerifiedIdentity,
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
    source: String,
    epoch: String,
    coverage: rss_observation::Coverage,
    fields: Vec<FieldResponse>,
}
#[derive(Serialize)]
struct FieldResponse {
    field: String,
    value: String,
    batch_id: String,
    observed_at: i64,
    received_at: i64,
}
pub(crate) struct InventoryService {
    reader: std::sync::Arc<rss_mdm_inventory_postgres::InventoryReader>,
    devices: std::sync::Arc<DeviceService>,
}
impl InventoryService {
    pub(super) fn new(
        reader: std::sync::Arc<rss_mdm_inventory_postgres::InventoryReader>,
        devices: std::sync::Arc<DeviceService>,
    ) -> Self {
        Self { reader, devices }
    }
    pub async fn read(&self, grant: InventoryRead<'_>) -> Result<InventoryResponse, Error> {
        // The request's proof is retained until the read completes; no authority cache.
        let scope: Scope = self
            .devices
            .current_scope(grant.proof, &grant.device, grant.coordinates)
            .await?;
        let fields = self.reader.read(&scope).await.map_err(|error| {
            Error::Unavailable(
                if matches!(
                    error.downcast_ref::<sqlx::Error>(),
                    Some(sqlx::Error::PoolTimedOut | sqlx::Error::PoolClosed)
                ) {
                    Failure::InventoryPool
                } else {
                    Failure::InventoryQuery
                },
            )
        })?;
        if fields.is_empty() {
            return Err(Error::NotFound);
        }
        Ok(InventoryResponse {
            tenant_id: grant.proof.tenant_id().into(),
            device_id: grant.device,
            registration: scope.registration().as_str().into(),
            source: scope.source().as_str().into(),
            epoch: scope.epoch().as_str().into(),
            coverage: rss_mdm_inventory::coverage(),
            fields: fields
                .into_iter()
                .map(|v| FieldResponse {
                    field: v.field,
                    value: v.value,
                    batch_id: v.batch_id,
                    observed_at: v.observed_at,
                    received_at: v.received_at,
                })
                .collect(),
        })
    }
}

pub(crate) struct EnrollmentPermission<'a> {
    proof: &'a VerifiedIdentity,
    device: String,
}
impl EnrollmentPermission<'_> {
    pub(super) fn proof(&self) -> &VerifiedIdentity {
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
                .is_ok()
        );
    }
    #[test]
    fn credential_permission_is_explicit_and_not_inherited() {
        let old = r#"{"tenant_id":"tenant","client_id":"mdm","subject":"subject","roles":["mdm_admin"],"devices":["device"],"allow_wipe":false,"allow_enrollment":true}"#;
        assert!(serde_json::from_str::<Binding>(old).is_err());
    }
    #[test]
    fn client_id_fits_persistent_audit_and_grants() {
        assert!(Policy::new("tenant", &"a".repeat(255), vec![]).is_ok());
        assert!(matches!(
            Policy::new("tenant", &"a".repeat(256), vec![]),
            Err(Error::Configuration(ConfigIssue::ClientId))
        ));
    }
    fn binding() -> Binding {
        Binding {
            tenant_id: "tenant".into(),
            client_id: "mdm".into(),
            subject: "subject".into(),
            roles: [Role::Auditor].into(),
            devices: ["device".into()].into(),
            allow_wipe: false,
            allow_enrollment: false,
            allow_manage_credentials: false,
        }
    }
    #[test]
    fn configuration_never_infers_roles_or_dangerous_grants() {
        assert!(Policy::new("tenant", "mdm", vec![binding()]).is_ok());
        assert!(Policy::new("tenant", "mdm", vec![binding(), binding()]).is_err());
        let mut b = binding();
        b.allow_wipe = true;
        assert!(Policy::new("tenant", "mdm", vec![b]).is_err());
        let mut b = binding();
        b.tenant_id = "other".into();
        assert!(Policy::new("tenant", "mdm", vec![b]).is_err());
        let mut b = binding();
        b.subject = "*".into();
        assert!(Policy::new("tenant", "mdm", vec![b]).is_err());
        let mut b = binding();
        b.devices.insert("*".into());
        assert!(Policy::new("tenant", "mdm", vec![b]).is_err());
        let mut b = binding();
        b.allow_manage_credentials = true;
        assert!(Policy::new("tenant", "mdm", vec![b]).is_err());
        assert!(serde_json::from_str::<Role>("\"administrator\"").is_err());
    }
}
