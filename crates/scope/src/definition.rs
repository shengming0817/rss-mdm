//! Authored selection; absent limitations and an empty limitation set differ.
//! Empty schema descriptions retain the existing HTTP artifact while rustdoc explains the domain.
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use uuid::Uuid;

#[derive(
    schemars::JsonSchema, Clone, Debug, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd,
)]
#[serde(
    tag = "kind",
    content = "id",
    rename_all = "snake_case",
    deny_unknown_fields
)]
/// An authored source reference; authorization and existence are checked by the application.
#[schemars(description = "")]
pub enum Reference {
    /// Direct device identity.
    #[schemars(description = "")]
    Device(String),
    /// Group definition identity.
    #[schemars(description = "")]
    Group(Uuid),
}
#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// Union targets, optional limitation intersection, then exclusion difference.
#[schemars(description = "")]
pub struct ScopeDefinition {
    /// Sources included in the target union.
    #[schemars(description = "")]
    pub targets: BTreeSet<Reference>,
    /// None is unrestricted; Some(empty) admits no targets.
    #[schemars(description = "")]
    pub limitations: Option<BTreeSet<Reference>>,
    /// Exclusion sources; unknown absence must not expand membership.
    #[schemars(description = "")]
    pub exclusions: BTreeSet<Reference>,
}
impl ScopeDefinition {
    /// Unique authored sources, without resolving their current members.
    pub fn references(&self) -> BTreeSet<Reference> {
        self.targets
            .iter()
            .chain(self.limitations.iter().flatten())
            .chain(self.exclusions.iter())
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn absent_and_empty_limitations_remain_distinct() {
        let reference = Reference::Group(Uuid::from_u128(1));
        let mut definition = ScopeDefinition {
            targets: [reference.clone()].into(),
            limitations: None,
            exclusions: [reference.clone()].into(),
        };
        assert_eq!(definition.references(), [reference].into());
        let absent = serde_json::to_value(&definition).unwrap();
        definition.limitations = Some(Default::default());
        let empty = serde_json::to_value(&definition).unwrap();
        assert_ne!(absent, empty);
        assert_eq!(
            serde_json::from_value::<ScopeDefinition>(empty).unwrap(),
            definition
        );
    }
}
