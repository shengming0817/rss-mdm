//! A tenant-bound, immutable coordinate for committed asset history.
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A provider-issued committed input. It is not a numeric commit frontier.
///
/// The PostgreSQL owner validates the snapshot and epoch lineage when using it.
/// Keeping this value in the original task/cursor preserves recovery without a
/// second snapshot registry or a transaction spanning pages.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(try_from = "CutWire", deny_unknown_fields)]
pub struct AssetCut {
    tenant: Uuid,
    epoch: Uuid,
    #[schemars(extend("minLength" = 1, "maxLength" = 65_536, "pattern" = "^[0-9:,]+$"))]
    snapshot: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct CutWire {
    tenant: Uuid,
    epoch: Uuid,
    #[schemars(extend("minLength" = 1, "maxLength" = 65_536, "pattern" = "^[0-9:,]+$"))]
    snapshot: String,
}

/// Invalid asset history coordinate; no source value is included in diagnostics.
#[derive(Debug)]
pub struct InvalidAssetCut;
impl std::fmt::Display for InvalidAssetCut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid asset cut")
    }
}
impl std::error::Error for InvalidAssetCut {}

impl TryFrom<CutWire> for AssetCut {
    type Error = InvalidAssetCut;
    fn try_from(value: CutWire) -> Result<Self, Self::Error> {
        let cut = Self {
            tenant: value.tenant,
            epoch: value.epoch,
            snapshot: value.snapshot,
        };
        if cut.tenant.is_nil()
            || cut.epoch.is_nil()
            || cut.snapshot.is_empty()
            || cut.snapshot.len() > 65_536
            || !cut
                .snapshot
                .bytes()
                .all(|b| b.is_ascii_digit() || b == b':' || b == b',')
        {
            return Err(InvalidAssetCut);
        }
        Ok(cut)
    }
}

impl AssetCut {
    /// Decode the bounded representation returned by the history owner.
    pub fn from_json(value: serde_json::Value) -> Result<Self, InvalidAssetCut> {
        serde_json::from_value(value).map_err(|_| InvalidAssetCut)
    }

    /// Tenant whose facts this coordinate selects. A cut never grants authority.
    pub fn tenant(&self) -> Uuid {
        self.tenant
    }

    /// JSON passed to the owner SQL visibility contract or stored with a task.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).expect("asset cut fields are serializable")
    }

    /// Opaque fixed-input identity stored by the product's calculation owner.
    pub fn input_version(&self) -> String {
        format!("assets:{}", self.to_json())
    }

    /// Read the current input format; numeric frontiers are not accepted.
    pub fn from_input_version(value: &str) -> Result<Self, InvalidAssetCut> {
        let value = value.strip_prefix("assets:").ok_or(InvalidAssetCut)?;
        if value.len() > 66_000 {
            return Err(InvalidAssetCut);
        }
        serde_json::from_str(value).map_err(|_| InvalidAssetCut)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn current_cut_round_trips_and_rejects_numeric_or_ambiguous_inputs() {
        let wire = serde_json::json!({"tenant":"11111111-1111-4111-8111-111111111111","epoch":"22222222-2222-4222-8222-222222222222","snapshot":"10:20:12,17"});
        let cut = AssetCut::from_json(wire.clone()).unwrap();
        assert_eq!(
            AssetCut::from_input_version(&cut.input_version()).unwrap(),
            cut
        );
        assert!(AssetCut::from_input_version("assets:17").is_err());
        let mut unknown = wire.clone();
        unknown["frontier"] = 17.into();
        assert!(AssetCut::from_json(unknown).is_err());
        let mut missing_tenant = wire.clone();
        missing_tenant["tenant"] = Uuid::nil().to_string().into();
        assert!(AssetCut::from_json(missing_tenant).is_err());
        let mut oversized = wire;
        oversized["snapshot"] = "1".repeat(65537).into();
        assert!(AssetCut::from_json(oversized).is_err());
    }
}
