//! Group source identity and frozen semantic coordinates; no provider dependency.
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Invalid non-nil UUID identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("invalid group identity")]
pub struct IdentityError;

macro_rules! id {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(
            schemars::JsonSchema,
            Clone,
            Copy,
            Debug,
            Eq,
            PartialEq,
            Ord,
            PartialOrd,
            Serialize,
            Deserialize,
        )]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(Uuid);
        impl $name {
            /// Parse a UUID, rejecting the nil identity. Display emits its canonical form.
            pub fn parse(s: &str) -> Result<Self, IdentityError> {
                let value = Uuid::parse_str(s).map_err(|_| IdentityError)?;
                if value.is_nil() {
                    return Err(IdentityError);
                }
                Ok(Self(value))
            }
        }
        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(f)
            }
        }
        impl TryFrom<String> for $name {
            type Error = IdentityError;
            fn try_from(s: String) -> Result<Self, Self::Error> {
                Self::parse(&s)
            }
        }
        impl From<$name> for String {
            fn from(id: $name) -> Self {
                id.to_string()
            }
        }
    };
}
id!(
    GroupId,
    "Tenant-scoped group UUID; logical deletion never releases this identity."
);
id!(
    OperationId,
    "Tenant-scoped idempotency UUID shared by commands and recalculations."
);

/// Asset universe fixed when a group is created.
#[derive(schemars::JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetContext {
    /// Original endpoint facts; association discovery never changes this universe.
    Endpoint,
    /// Unified device objects, including explicitly unassociated endpoints.
    AssociatedDevice,
}
impl AssetContext {
    /// Canonical persisted discriminator.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Endpoint => "endpoint",
            Self::AssociatedDevice => "associated_device",
        }
    }
}
/// Frozen group input, shared by Group and its product consumers.
#[derive(schemars::JsonSchema, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupSource {
    /// Source identity in this transaction's tenant.
    pub group: GroupId,
    /// Shared source coordinates, also consumed by Scope.
    pub coordinates: SourceCoordinates,
}
/// Semantic and immutable coordinates of one product group source.
#[derive(schemars::JsonSchema, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceCoordinates {
    /// Immutable result used for every page.
    pub member_set: Option<OperationId>,
    /// Definition coordinate, independent of calculation progress.
    pub definition_version: u64,
    /// Three-valued membership coordinate, including Unknown transitions.
    pub member_version: u64,
    /// Source authorization coordinate.
    pub authority_version: u64,
    /// Object universe; cross-context conversion is not implicit.
    pub asset_context: AssetContext,
}
