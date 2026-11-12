//! Product identity values; construction does not authenticate a device or resolve an association.
use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use std::{cmp::Ordering, fmt, str::FromStr};
use uuid::Uuid;

/// Invalid product identity, without echoing untrusted input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdentityError;
impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid product identity")
    }
}
impl std::error::Error for IdentityError {}

/// A nonzero registration identity. Tenant and registration authority are separate coordinates.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DeviceId(Uuid);
impl DeviceId {
    /// Allocate an independent v4 registration identity.
    pub fn new_v4() -> Self {
        Self(Uuid::new_v4())
    }
    /// Parse the canonical lowercase, hyphenated, nonzero UUID representation.
    pub fn parse(value: &str) -> Result<Self, IdentityError> {
        canonical_uuid(value).map(Self)
    }
    /// Borrow the UUID for a persistence adapter.
    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }
    /// Return the UUID for a persistence adapter.
    pub fn into_uuid(self) -> Uuid {
        self.0
    }
}
impl TryFrom<Uuid> for DeviceId {
    type Error = IdentityError;
    fn try_from(value: Uuid) -> Result<Self, Self::Error> {
        if value.is_nil() { Err(IdentityError) } else { Ok(Self(value)) }
    }
}
impl FromStr for DeviceId {
    type Err = IdentityError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}
impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.hyphenated().fmt(f)
    }
}
impl Serialize for DeviceId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}
impl<'de> Deserialize<'de> for DeviceId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(D::Error::custom)
    }
}
impl JsonSchema for DeviceId {
    fn schema_name() -> std::borrow::Cow<'static, str> { "DeviceId".into() }
    fn json_schema(generator: &mut SchemaGenerator) -> Schema { uuid_schema(generator) }
}

/// A directory/calculation object; associations must be resolved before device execution.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObjectRef {
    /// One independently registered endpoint.
    Endpoint(DeviceId),
    /// One association, with its own identity and member authority.
    Association(
        #[serde(with = "association_uuid")]
        #[schemars(schema_with = "uuid_schema")]
        Uuid,
    ),
}
impl ObjectRef {
    /// Stable relational discriminator: endpoint = 0, association = 1.
    pub const fn kind(self) -> i16 {
        match self { Self::Endpoint(_) => 0, Self::Association(_) => 1 }
    }
    /// UUID component of the relational identity; always pair it with its kind.
    pub fn uuid(self) -> Uuid {
        match self { Self::Endpoint(id) => id.into_uuid(), Self::Association(id) => id }
    }
    /// Reconstruct a typed relational identity, rejecting unknown kinds and zero UUIDs.
    pub fn from_parts(kind: i16, id: Uuid) -> Result<Self, IdentityError> {
        if id.is_nil() { return Err(IdentityError); }
        match kind {
            0 => Ok(Self::Endpoint(DeviceId::try_from(id)?)),
            1 => Ok(Self::Association(id)),
            _ => Err(IdentityError),
        }
    }
}
impl Ord for ObjectRef {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.kind(), self.uuid()).cmp(&(other.kind(), other.uuid()))
    }
}
impl PartialOrd for ObjectRef {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

fn canonical_uuid(value: &str) -> Result<Uuid, IdentityError> {
    let id = Uuid::parse_str(value).map_err(|_| IdentityError)?;
    if id.is_nil() || id.hyphenated().to_string() != value { return Err(IdentityError); }
    Ok(id)
}
fn uuid_schema(_: &mut SchemaGenerator) -> Schema {
    schemars::json_schema!({"type":"string","format":"uuid","minLength":36,"maxLength":36,
        "pattern":"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
        "not":{"const":"00000000-0000-0000-0000-000000000000"}})
}
mod association_uuid {
    use super::*;
    pub fn serialize<S: Serializer>(id: &Uuid, s: S) -> Result<S::Ok, S::Error> {
        if id.is_nil() { return Err(serde::ser::Error::custom(IdentityError)); }
        s.collect_str(&id.hyphenated())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Uuid, D::Error> {
        canonical_uuid(&String::deserialize(d)?).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const ID: &str = "7f8c2d91-4a63-4f20-9b8e-c1526d0a7349";
    #[test]
    fn public_identity_contract_rejects_alternate_spellings() {
        let schema = schemars::schema_for!(DeviceId);
        let validator = jsonschema::validator_for(&serde_json::to_value(schema).unwrap()).unwrap();
        for text in [ID.to_owned(), ID.to_uppercase(), ID.replace('-', ""), format!("urn:uuid:{ID}"),
            format!("{{{ID}}}"), "00000000-0000-0000-0000-000000000000".into(), "device".into()] {
            let value = serde_json::Value::String(text.clone());
            assert_eq!(validator.is_valid(&value), text == ID);
            assert_eq!(serde_json::from_value::<DeviceId>(value).is_ok(), text == ID);
        }
        let id = DeviceId::parse(ID).unwrap();
        let map = std::collections::BTreeMap::from([(id, 1)]);
        let bytes = serde_json::to_vec(&map).unwrap();
        assert_eq!(serde_json::from_slice::<std::collections::BTreeMap<DeviceId, i32>>(&bytes).unwrap(), map);
    }
    #[test]
    fn object_kind_survives_wire_and_relational_round_trips() {
        let id = DeviceId::parse(ID).unwrap();
        let endpoint = ObjectRef::Endpoint(id);
        let association = ObjectRef::Association(id.into_uuid());
        assert_ne!(endpoint, association);
        assert!(endpoint < association);
        for object in [endpoint, association] {
            assert_eq!(ObjectRef::from_parts(object.kind(), object.uuid()).unwrap(), object);
            let bytes = serde_json::to_vec(&object).unwrap();
            assert_eq!(serde_json::from_slice::<ObjectRef>(&bytes).unwrap(), object);
        }
        assert!(ObjectRef::from_parts(2, id.into_uuid()).is_err());
        assert!(ObjectRef::from_parts(1, Uuid::nil()).is_err());
        assert!(serde_json::from_str::<ObjectRef>(r#"{"kind":"association","id":"00000000-0000-0000-0000-000000000000"}"#).is_err());
    }
}
