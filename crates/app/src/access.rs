//! MDM alone owns roles and device permissions. Identity facts never contain them.
use crate::Error;
use crate::{ConfigIssue, Failure};
use rss_identity_client::VerifiedIdentity;
use rss_observation::{Epoch, Id, Registration, Scope};
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
}
pub(crate) struct Policy {
    tenant: String,
    client: String,
    bindings: BTreeMap<String, Binding>,
}
pub(crate) struct InventoryRead<'a> {
    proof: &'a VerifiedIdentity,
    scope: Scope,
}
impl InventoryRead<'_> {
    pub(super) fn scope(&self) -> &Scope {
        &self.scope
    }
}
pub(crate) struct DangerousAction<'a> {
    _proof: &'a VerifiedIdentity,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Coordinates {
    pub registration: String,
    pub source: String,
    pub epoch: String,
}
impl Policy {
    pub fn new(tenant: &str, client: &str, bindings: Vec<Binding>) -> Result<Self, Error> {
        if client.is_empty()
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
                || ((b.allow_wipe || b.allow_enrollment)
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
        let scope = Scope::new(
            rss_request_context::TenantId::parse(proof.tenant_id())
                .map_err(|_| Error::Unauthorized)?,
            Id::new(device).map_err(|_| Error::Malformed)?,
            Registration::new(c.registration).map_err(|_| Error::Malformed)?,
            Id::new(c.source).map_err(|_| Error::Malformed)?,
            Id::new("inventory").expect("static dataset"),
            Epoch::new(c.epoch).map_err(|_| Error::Malformed)?,
        );
        Ok(InventoryRead { proof, scope })
    }
    pub fn dangerous<'a>(
        &self,
        proof: &'a VerifiedIdentity,
        device: &str,
    ) -> Result<DangerousAction<'a>, Error> {
        let b = self.device(proof, device)?;
        if !(b.allow_wipe || b.allow_enrollment)
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
}
impl InventoryService {
    pub(super) fn new(reader: std::sync::Arc<rss_mdm_inventory_postgres::InventoryReader>) -> Self {
        Self { reader }
    }
    pub async fn read(&self, grant: InventoryRead<'_>) -> Result<InventoryResponse, Error> {
        // The request's proof is retained until the read completes; no authority cache.
        let fields = self.reader.read(grant.scope()).await.map_err(|error| {
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
        let scope = grant.scope();
        Ok(InventoryResponse {
            tenant_id: grant.proof.tenant_id().into(),
            device_id: scope.object().as_str().into(),
            registration: scope.registration().as_str().into(),
            source: scope.source().as_str().into(),
            epoch: scope.epoch().as_str().into(),
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
    fn binding() -> Binding {
        Binding {
            tenant_id: "tenant".into(),
            client_id: "mdm".into(),
            subject: "subject".into(),
            roles: [Role::Auditor].into(),
            devices: ["device".into()].into(),
            allow_wipe: false,
            allow_enrollment: false,
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
        assert!(serde_json::from_str::<Role>("\"administrator\"").is_err());
    }
}
