//! Product installation and host application facts, without a general workflow engine.
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(schemars::JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Reserved,
    DatabaseReady,
    AccountsReady,
    HostPending,
    Enabled,
}
#[derive(schemars::JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockedReason {
    Capacity,
    Database,
    Authentication,
    Authorization,
    HostUnavailable,
    MaterialMissing,
    MaterialExpired,
    MaterialRevoked,
    ExternalAuthorization,
    OutcomeUnknown,
}
/// A host can only report the revision it actually loaded in its current process generation.
#[derive(schemars::JsonSchema, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Application {
    pub requested_revision: u64,
    pub material_digest: String,
    pub operation_id: Uuid,
    pub observation: Option<Observation>,
}
#[derive(schemars::JsonSchema, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Observation {
    pub host_id: Uuid,
    pub process_generation: Uuid,
    pub applied_revision: u64,
    pub material_digest: String,
    pub observed_at: i64,
    pub failure: Option<BlockedReason>,
}
impl Application {
    /// History remains inspectable, but never proves the current process loaded these materials.
    pub fn applied(&self, host: Uuid, generation: Uuid, material_valid: bool) -> bool {
        !host.is_nil()
            && !generation.is_nil()
            && !self.operation_id.is_nil()
            && self.material_digest.len() == 64
            && self
                .material_digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && self.requested_revision > 0
            && material_valid
            && self.observation.as_ref().is_some_and(|o| {
                o.host_id == host
                    && o.process_generation == generation
                    && o.applied_revision == self.requested_revision
                    && o.material_digest == self.material_digest
                    && o.observed_at >= 0
                    && o.failure.is_none()
            })
    }
}
/// Public provisioning progress. No password, storage path or maintenance capability is serialized.
#[derive(schemars::JsonSchema, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Provisioning {
    pub operation_id: Uuid,
    pub tenant_id: Uuid,
    pub administrator_id: Option<Uuid>,
    pub host_id: Uuid,
    pub revision: u64,
    pub phase: Phase,
    pub blocked: Option<BlockedReason>,
    pub origin: Option<String>,
    pub application: Option<Application>,
}
impl Provisioning {
    /// Neither a tenant row nor a saved configuration constitutes completed provisioning.
    pub fn enabled(&self, generation: Uuid, account_verified: bool, authorized: bool) -> bool {
        self.phase == Phase::Enabled
            && self.blocked.is_none()
            && account_verified
            && authorized
            && !self.tenant_id.is_nil()
            && self.administrator_id.is_some_and(|id| !id.is_nil())
            && !self.operation_id.is_nil()
            && self
                .application
                .as_ref()
                .is_some_and(|a| a.applied(self.host_id, generation, true))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn prior_process_wrong_material_and_expiry_never_prove_application() {
        let host = Uuid::from_u128(1);
        let generation = Uuid::from_u128(2);
        let mut application = Application {
            requested_revision: 3,
            material_digest: "a".repeat(64),
            operation_id: Uuid::from_u128(3),
            observation: Some(Observation {
                host_id: host,
                process_generation: generation,
                applied_revision: 3,
                material_digest: "a".repeat(64),
                observed_at: 1,
                failure: None,
            }),
        };
        assert!(application.applied(host, generation, true));
        assert!(!application.applied(host, Uuid::from_u128(4), true));
        assert!(!application.applied(host, generation, false));
        application.requested_revision = 4;
        assert!(!application.applied(host, generation, true));
        application.requested_revision = 3;
        application.observation.as_mut().unwrap().material_digest = "different".into();
        assert!(!application.applied(host, generation, true));
        application.observation = None;
        assert!(!application.applied(host, generation, true));
    }
}
