//! Value-free asset facts shared by independent incremental consumers.
use crate::{Invalid, Source};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Current authored asset fact contract; transport metadata carries its digest.
pub const ASSET_CHANGED_SCHEMA: &str = include_str!("../schema/asset-changed-v1.json");

/// The owner whose immutable fact changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetChangeKind {
    /// A projected collection field, including explicit absence.
    Inventory,
    /// An administrator-owned field assignment.
    Manual,
    /// A device registration or its execution eligibility.
    Device,
    /// An enabled source or its generation.
    Source,
    /// Credential eligibility, without any secret or locator.
    Credential,
    /// Collection evidence/progress, distinct from projected field values.
    Collection,
    /// A field's semantic catalog definition.
    Catalog,
}
impl AssetChangeKind {
    /// Whether current registration/source eligibility must be checked again.
    pub const fn changes_authority(self) -> bool {
        matches!(self, Self::Device | Self::Source | Self::Credential)
    }
}

/// Nature of a fact transition, never a grant to execute.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetChangeOperation {
    /// A new fact became available.
    Created,
    /// Existing fact or evidence changed.
    Updated,
    /// Evidence was explicitly removed.
    Deleted,
    /// A source, credential or registration lost eligibility.
    Revoked,
    /// An attempt failed; prior complete evidence is not implicitly deleted.
    Failed,
}

/// Coordinates captured by the fact owner in its original transaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssetFactIdentity {
    /// Stable identity within the fact kind.
    pub fact: String,
    /// Device/registration identity; catalog facts have no device.
    pub device: Option<rss_mdm_agent_wire::DeviceId>,
    /// Registration incarnation, separate from source and history epochs.
    pub registration_epoch: Option<Uuid>,
    /// Previous registration incarnation when replaced.
    pub previous_registration_epoch: Option<Uuid>,
    /// Evidence source; manual facts use Manual and have no source epoch.
    pub source: Option<Source>,
    /// Frozen source incarnation.
    pub source_epoch: Option<String>,
    /// Previous source incarnation when replaced.
    pub previous_source_epoch: Option<String>,
    /// Frozen dataset/collection scope, when applicable.
    pub scope: Option<String>,
    /// Exact field scope, when applicable.
    pub field_scope: Option<String>,
    /// Transition which produced this fact.
    pub operation: AssetChangeOperation,
}

/// One durable fact, independent of consumer progress and execution effects.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssetChanged {
    /// Current product wire version.
    pub v: u8,
    /// Fact tenant; it does not grant authority.
    pub tenant: Uuid,
    /// Unique event identity, not a commit-order watermark.
    pub revision: i64,
    /// History incarnation used by AssetCut visibility.
    pub history_epoch: Uuid,
    /// Fact owner/kind.
    pub kind: AssetChangeKind,
    /// Original immutable coordinates.
    pub identity: AssetFactIdentity,
    /// Fields whose value, completeness or eligibility needs reevaluation.
    pub fields: Vec<String>,
}
impl AssetChanged {
    /// Stable authored message identity, retained across delivery retries.
    pub fn message_id(&self) -> String {
        format!("asset.changed.v1:{}:{}", self.history_epoch, self.revision)
    }
    /// Validate bounded coordinates without accessing current device state.
    pub fn validate(&self) -> Result<(), Invalid> {
        let text =
            |s: &str, max| !s.is_empty() && s.len() <= max && !s.chars().any(char::is_control);
        if self.v != 1
            || self.tenant.is_nil()
            || self.history_epoch.is_nil()
            || self.revision <= 0
            || !text(&self.identity.fact, 4096)
            || self.identity.registration_epoch.is_some_and(|v| v.is_nil())
            || self
                .identity
                .previous_registration_epoch
                .is_some_and(|v| v.is_nil())
            || [
                &self.identity.source_epoch,
                &self.identity.previous_source_epoch,
            ]
            .into_iter()
            .flatten()
            .any(|v| !text(v, 256))
            || self.identity.scope.as_ref().is_some_and(|v| !text(v, 4096))
            || self
                .identity
                .field_scope
                .as_ref()
                .is_some_and(|v| !text(v, 32768))
            || self.fields.len() > 128
            || self
                .fields
                .iter()
                .any(|f| crate::FieldKey::parse(f).is_err())
            || (self.kind != AssetChangeKind::Catalog && self.identity.device.is_none())
            || (self.kind == AssetChangeKind::Catalog && self.identity.device.is_some())
        {
            return Err(Invalid::Evidence);
        }
        match self.kind {
            AssetChangeKind::Manual
                if self.identity.source != Some(Source::Manual)
                    || self.identity.source_epoch.is_some() =>
            {
                return Err(Invalid::Evidence);
            }
            AssetChangeKind::Inventory | AssetChangeKind::Collection | AssetChangeKind::Source
                if self
                    .identity
                    .source
                    .is_none_or(|source| source == Source::Manual)
                    || self.identity.source_epoch.is_none() =>
            {
                return Err(Invalid::Evidence);
            }
            AssetChangeKind::Device if self.identity.registration_epoch.is_none() => {
                return Err(Invalid::Evidence);
            }
            _ => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fact_identity_separates_epochs_and_rejects_untrusted_or_legacy_shapes() {
        let value = serde_json::json!({"v":1,"tenant":Uuid::from_u128(1),"revision":7,"historyEpoch":Uuid::from_u128(2),"kind":"source","identity":{
            "fact":"device:source","device":"00000000-0000-0000-0000-000000000001","registrationEpoch":Uuid::from_u128(3),"previousRegistrationEpoch":null,"source":"mdm.windows","sourceEpoch":"source-epoch","previousSourceEpoch":"old-source-epoch","scope":null,"fieldScope":null,"operation":"revoked"},"fields":[]});
        let event: AssetChanged = serde_json::from_value(value.clone()).unwrap();
        event.validate().unwrap();
        assert_ne!(
            event.history_epoch,
            event.identity.registration_epoch.unwrap()
        );
        assert_eq!(
            event.identity.previous_source_epoch.as_deref(),
            Some("old-source-epoch")
        );
        let mut secret = value.clone();
        secret["identity"]["locator"] = "credential-secret".into();
        assert!(serde_json::from_value::<AssetChanged>(secret).is_err());
        let mut missing = event.clone();
        missing.identity.source_epoch = None;
        assert!(missing.validate().is_err());
        let mut invalid = value.clone();
        invalid["identity"]["device"] = "device".into();
        assert!(serde_json::from_value::<AssetChanged>(invalid).is_err());
        let mut legacy = value;
        legacy["kind"] = "registration".into();
        assert!(serde_json::from_value::<AssetChanged>(legacy).is_err());
    }
}
