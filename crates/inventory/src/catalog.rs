//! Fixed product field dictionary. Collection coverage is a subset of this dictionary.
use crate::{Result, Scalar};
use serde::{Deserialize, Serialize};
/// Current dictionary identity shared by every product consumer.
pub const DICTIONARY: &str = "assets-v1";
/// Product field identity; unknown keys cannot be constructed through serde.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FieldKey {
    /// Device model reported by a trusted collector.
    #[serde(rename = "device.model")]
    Model,
    /// OS version reported by a trusted collector.
    #[serde(rename = "device.os.version")]
    OsVersion,
    /// Organization asset tag.
    #[serde(rename = "custom.asset_tag")]
    AssetTag,
    /// Office floor, including basement floors.
    #[serde(rename = "custom.office_floor")]
    OfficeFloor,
    /// Whether the device is a loaner.
    #[serde(rename = "custom.is_loaner")]
    IsLoaner,
    /// Purchase time as UTC Unix seconds.
    #[serde(rename = "custom.purchase_date")]
    PurchaseDate,
}
/// Scalar type; there are no implicit conversions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// UTF-8 text.
    String,
    /// Signed 64-bit integer.
    Integer,
    /// Boolean.
    Boolean,
    /// UTC Unix seconds.
    Time,
}
/// Closed product operator vocabulary mapped to the Group evaluator by the app.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operator {
    /// Equal.
    Eq,
    /// Not equal.
    Ne,
    /// Member of a homogeneous operand set.
    In,
    /// Not a member of a homogeneous operand set.
    NotIn,
    /// Less than.
    Lt,
    /// Less than or equal.
    Le,
    /// Greater than.
    Gt,
    /// Greater than or equal.
    Ge,
    /// Literal substring.
    Contains,
    /// Absence of literal substring.
    NotContains,
    /// Explicit null.
    IsNull,
    /// Known non-null value.
    IsNotNull,
}
/// One immutable dictionary entry. No deadlines or configurable sources.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldDefinition {
    /// Stable key.
    pub key: FieldKey,
    /// Scalar type.
    pub kind: Kind,
    /// Accepts explicit null, distinct from deletion.
    pub nullable: bool,
    /// Only these fields accept management assignments.
    pub manual: bool,
    /// Allowed producer identities; Manual is never a device channel.
    pub sources: &'static [crate::Source],
    /// Allowed operations, checked again by Group.
    pub operations: Vec<Operator>,
}
impl FieldKey {
    /// Complete fixed catalog.
    pub const ALL: [Self; 6] = [
        Self::Model,
        Self::OsVersion,
        Self::AssetTag,
        Self::OfficeFloor,
        Self::IsLoaner,
        Self::PurchaseDate,
    ];
    /// Exact external key.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Model => "device.model",
            Self::OsVersion => "device.os.version",
            Self::AssetTag => "custom.asset_tag",
            Self::OfficeFloor => "custom.office_floor",
            Self::IsLoaner => "custom.is_loaner",
            Self::PurchaseDate => "custom.purchase_date",
        }
    }
    /// Parse only the registered catalog.
    pub fn parse(key: &str) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|f| f.as_str() == key)
            .ok_or(crate::Invalid)
    }
    /// Whether this key is assigned by a management principal.
    pub const fn is_manual(self) -> bool {
        !matches!(self, Self::Model | Self::OsVersion)
    }
    /// Number of fields in the existing collector coverage, derived from the catalog.
    pub const OBSERVED_COUNT: usize = {
        let mut n = 0;
        let mut i = 0;
        while i < Self::ALL.len() {
            if !Self::ALL[i].is_manual() {
                n += 1;
            }
            i += 1;
        }
        n
    };
    /// Fields produced by the existing device-basics coverage.
    pub fn observed() -> impl Iterator<Item = Self> {
        Self::ALL.into_iter().filter(|f| !f.is_manual())
    }
    /// Fixed type and operation policy.
    pub fn definition(self) -> FieldDefinition {
        use Operator::*;
        let kind = match self {
            Self::Model | Self::OsVersion | Self::AssetTag => Kind::String,
            Self::OfficeFloor => Kind::Integer,
            Self::IsLoaner => Kind::Boolean,
            Self::PurchaseDate => Kind::Time,
        };
        let manual = self.is_manual();
        let mut operations = vec![Eq, Ne, In, NotIn];
        match kind {
            Kind::String => operations.extend([Contains, NotContains]),
            Kind::Integer | Kind::Time => operations.extend([Lt, Le, Gt, Ge]),
            Kind::Boolean => {}
        }
        if manual {
            operations.extend([IsNull, IsNotNull]);
        }
        FieldDefinition {
            key: self,
            kind,
            nullable: manual,
            manual,
            sources: if manual {
                &[crate::Source::Manual]
            } else {
                &[crate::Source::MdmWindows, crate::Source::AgentBuiltin]
            },
            operations,
        }
    }
    /// Validate the declared type and bounded scalar without coercion.
    pub fn validate_scalar(self, value: &Scalar) -> Result<()> {
        if self.definition().kind != value.kind() {
            return Err(crate::Invalid);
        }
        value.validate()?;
        Ok(())
    }
    /// Validation used by the existing UTF-8 Observation coverage.
    pub fn validate(self, value: &str) -> bool {
        !self.definition().manual && self.validate_scalar(&Scalar::String(value.into())).is_ok()
    }
}
