//! Server-owned fields use the ordinary asset dictionary and scalar/set operators.
//! ref: PostgreSQL REL_17_STABLE doc/src/sgml/datatype-uuid.sgml
use crate::{FieldDefinition, FieldKey, Platform, Sensitivity, ValueType};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// User-valued fields of an enrolled device.
pub enum DeviceUser {
    /// Principal recorded at registration.
    Registration,
    /// Principal of the currently qualified session.
    Current,
}

impl DeviceUser {
    /// Both attribution fields in stable order.
    pub const ALL: [Self; 2] = [Self::Registration, Self::Current];

    fn prefix(self) -> &'static str {
        match self {
            Self::Registration => "device.registration_user",
            Self::Current => "device.current_user",
        }
    }

    /// Reserve these roots even when a definition or a particular source is absent.
    pub fn for_key(key: FieldKey) -> Option<Self> {
        Self::ALL.into_iter().find(|user| {
            key.as_str()
                .strip_prefix(user.prefix())
                .is_some_and(|suffix| suffix.is_empty() || suffix.starts_with('.'))
        })
    }

    /// Canonical inventory key for this device attribute.
    pub fn key(self, attribute: Attribute) -> FieldKey {
        let suffix = match attribute {
            Attribute::Principal => "principal_id".to_owned(),
            Attribute::LocalGroups => "local_group_ids".to_owned(),
            Attribute::Provider(provider, field) => {
                format!("idp.p_{}.{}", provider.simple(), field.key())
            }
            Attribute::Profile(id) => format!("profile.f_{}", id.simple()),
        };
        FieldKey::parse(&format!("{}.{suffix}", self.prefix()))
            .expect("bounded personnel field key")
    }

    /// Construct an ordinary server-owned catalog field.
    pub fn definition(
        self,
        attribute: Attribute,
        version: u64,
        value_type: ValueType,
    ) -> FieldDefinition {
        FieldDefinition {
            key: self.key(attribute),
            value_type,
            version,
            time_series: None,
            nullable: false,
            manual: false,
            sources: Default::default(),
            platforms: [Platform::Windows, Platform::Macos].into(),
            sensitivity: if self == Self::Current {
                Sensitivity::Sensitive
            } else {
                Sensitivity::Standard
            },
            unit: None,
            searchable: true,
            item_key: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Address of an attribute relative to a device user.
pub enum Attribute {
    /// Stable principal identifier.
    Principal,
    /// Product-managed user group identifiers.
    LocalGroups,
    /// Trusted identifiers from the specified IdP.
    Provider(Uuid, ProviderAttribute),
    /// Product-approved scalar mapping.
    Profile(Uuid),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Independent source-qualified IdP attributes.
pub enum ProviderAttribute {
    /// Group identifiers.
    Groups,
    /// Direct department memberships.
    Departments,
    /// Direct departments and their ancestors.
    DepartmentAncestors,
}
impl ProviderAttribute {
    /// Supported membership paths.
    pub const ALL: [Self; 3] = [Self::Groups, Self::Departments, Self::DepartmentAncestors];
    fn key(self) -> &'static str {
        match self {
            Self::Groups => "group_ids",
            Self::Departments => "department_ids",
            Self::DepartmentAncestors => "department_ancestor_ids",
        }
    }
}
/// Catalog type for a set of opaque membership identifiers.
pub fn identifiers() -> ValueType {
    ValueType::Array {
        items: Box::new(ValueType::String {
            max_length: 256,
            allow_empty: false,
        }),
        max_items: 10000,
    }
}
/// Fields available without provider or profile configuration.
pub fn fixed_fields() -> impl Iterator<Item = FieldDefinition> {
    fixed_attributes().flat_map(|(attribute, kind)| {
        DeviceUser::ALL.map(|user| user.definition(attribute, 1, kind.clone()))
    })
}

/// Attribute types shared by the installed and refreshed device field catalogs.
pub fn fixed_attributes() -> impl Iterator<Item = (Attribute, ValueType)> {
    [
        (
            Attribute::Principal,
            ValueType::String {
                max_length: 36,
                allow_empty: false,
            },
        ),
        (Attribute::LocalGroups, identifiers()),
    ]
    .into_iter()
}

/// Decode canonical, server-owned dictionary paths.
pub fn attribute(key: FieldKey) -> Option<(DeviceUser, Attribute)> {
    let user = DeviceUser::for_key(key)?;
    let path = key
        .as_str()
        .strip_prefix(user.prefix())?
        .strip_prefix('.')?;
    let id = |s: &str, prefix| {
        let raw = s.strip_prefix(prefix)?;
        let id = Uuid::parse_str(raw).ok()?;
        (!id.is_nil() && id.simple().to_string() == raw).then_some(id)
    };
    let value = match path {
        "principal_id" => Attribute::Principal,
        "local_group_ids" => Attribute::LocalGroups,
        _ => {
            if let Some(field) = path.strip_prefix("profile.") {
                Attribute::Profile(id(field, "f_")?)
            } else {
                let (provider, name) = path.strip_prefix("idp.")?.split_once('.')?;
                Attribute::Provider(
                    id(provider, "p_")?,
                    ProviderAttribute::ALL
                        .into_iter()
                        .find(|field| field.key() == name)?,
                )
            }
        }
    };
    Some((user, value))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn both_device_fields_expose_the_same_ordinary_scalar_and_set_types() {
        let provider = Uuid::from_u128(123);
        let mapping = Uuid::from_u128(456);
        for role in DeviceUser::ALL {
            for (attr, kind, many) in [
                (
                    Attribute::Principal,
                    ValueType::String {
                        max_length: 36,
                        allow_empty: false,
                    },
                    false,
                ),
                (Attribute::LocalGroups, identifiers(), true),
                (Attribute::Profile(mapping), ValueType::Boolean, false),
                (
                    Attribute::Provider(provider, ProviderAttribute::Groups),
                    identifiers(),
                    true,
                ),
                (
                    Attribute::Provider(provider, ProviderAttribute::Departments),
                    identifiers(),
                    true,
                ),
                (
                    Attribute::Provider(provider, ProviderAttribute::DepartmentAncestors),
                    identifiers(),
                    true,
                ),
            ] {
                let def = role.definition(attr, 1, kind);
                let key = def.key;
                assert_eq!(attribute(key), Some((role, attr)));
                assert!(!def.manual && def.sources.is_empty());
                let catalog = crate::Catalog::new(vec![def]).unwrap();
                assert_eq!(catalog.path(key).unwrap().many, many);
            }
        }
    }
}
