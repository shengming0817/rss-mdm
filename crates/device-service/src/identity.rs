//! Hardware matching uses current authenticated source facts, never resolved/manual hints.
use crate::*;
use rss_mdm_inventory::{Channel, Evidence, Scalar, Source, State as FieldState};
use rss_mdm_registration_service::device::endpoints;
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Hardware {
    pub serial: BTreeSet<String>,
    pub uuid: BTreeSet<String>,
    pub manufacturer: BTreeSet<String>,
    pub sources: Vec<Evidence>,
}
impl Hardware {
    fn same_values(&self, other: &Self) -> bool {
        self.serial == other.serial
            && self.uuid == other.uuid
            && self.manufacturer == other.manufacturer
    }
    fn shares_key(&self, other: &Self) -> bool {
        !self.serial.is_disjoint(&other.serial) || !self.uuid.is_disjoint(&other.uuid)
    }
    fn consistent(&self) -> bool {
        self.serial.len() <= 1 && self.uuid.len() <= 1 && self.manufacturer.len() <= 1
    }
    pub(crate) fn matches(&self, other: &Self) -> bool {
        self.consistent()
            && other.consistent()
            && !self.contradicts(other)
            && ((!self.serial.is_empty() && self.serial == other.serial)
                || (!self.uuid.is_empty() && self.uuid == other.uuid))
    }
    pub(crate) fn contradicts(&self, other: &Self) -> bool {
        !self.consistent()
            || !other.consistent()
            || [
                (&self.serial, &other.serial),
                (&self.uuid, &other.uuid),
                (&self.manufacturer, &other.manufacturer),
            ]
            .iter()
            .any(|(a, b)| !a.is_empty() && !b.is_empty() && a != b)
    }
}
fn normalized(value: &str, uuid: bool) -> Option<String> {
    let value = value.trim().to_uppercase();
    if value.is_empty()
        || value.len() > 256
        || value.chars().any(char::is_control)
        || [
            "UNKNOWN",
            "NONE",
            "NULL",
            "N/A",
            "NA",
            "NOT SPECIFIED",
            "NOT APPLICABLE",
            "DEFAULT STRING",
            "SYSTEM SERIAL NUMBER",
            "TO BE FILLED BY O.E.M.",
            "TO BE FILLED BY OEM",
        ]
        .contains(&value.as_str())
        || value.chars().all(|c| c == '0' || c == '-' || c == ' ')
    {
        return None;
    }
    if uuid {
        let id = uuid::Uuid::parse_str(&value).ok()?;
        if id.is_nil() || id.as_u128() == u128::MAX {
            None
        } else {
            Some(id.to_string())
        }
    } else {
        Some(value)
    }
}
#[derive(Clone, Debug)]
pub(crate) struct EndpointIdentity {
    pub member: Member,
    pub hardware: Hardware,
}
pub(crate) struct World {
    pub watermark: i64,
    pub endpoints: Vec<EndpointIdentity>,
    pub associations: Vec<Association>,
}
impl World {
    pub fn current(&self, member: &Member) -> Option<&EndpointIdentity> {
        self.endpoints
            .iter()
            .find(|e| e.member.device == member.device && e.member.channel == member.channel)
    }
    /// Already associated endpoints represent one instance for uniqueness, not two competitors.
    pub fn unique(&self, members: &[Member], hardware: &Hardware) -> bool {
        let own: BTreeSet<_> = members.iter().map(|m| m.device.as_str()).collect();
        !self
            .endpoints
            .iter()
            .any(|e| !own.contains(e.member.device.as_str()) && hardware.shares_key(&e.hardware))
    }
    pub fn effective(&self, mut a: Association) -> Association {
        if a.state == State::Revoked {
            return a;
        }
        let current: Option<Vec<_>> = a.members.iter().map(|m| self.current(m)).collect();
        if a.confirmed_by != "device-associations"
            && current.as_ref().is_some_and(|items| {
                items.iter().all(|e| {
                    a.members.contains(&e.member)
                        && a.hardware
                            .get(e.member.channel.as_str())
                            .is_some_and(|old| e.hardware.same_values(old))
                })
            })
        {
            a.state = State::Confirmed;
            return a;
        }
        a.state = match current {
            Some(ref current)
                if current.iter().all(|e| {
                    a.hardware
                        .get(e.member.channel.as_str())
                        .is_some_and(|old| {
                            !e.hardware.contradicts(old)
                                && (a.members.contains(&e.member)
                                    || e.hardware.matches(old)
                                    || current.iter().any(|peer| {
                                        peer.member.device != e.member.device
                                            && e.hardware.matches(&peer.hardware)
                                    }))
                        })
                        && self.unique(&a.members, &e.hardware)
                }) && !current[0].hardware.contradicts(&current[1].hardware) =>
            {
                State::Confirmed
            }
            _ => State::NeedsVerification,
        };
        a
    }
}
/// The caller holds Audit (for mutations) and the asset watermark before taking channel locks.
pub(crate) async fn world(c: &mut PgConnection, tenant: TenantId) -> Result<World> {
    let watermark = rss_mdm_inventory_postgres::lock_watermark_in(c, tenant).await?;
    let catalog = rss_mdm_inventory_postgres::catalog_at_in(c, tenant, watermark)
        .await
        .map_err(|_| Error::Storage)?;
    let catalog = rss_mdm_inventory::Catalog::new(
        catalog
            .fields()
            .filter(|f| {
                [
                    "device.serial_number",
                    "device.hardware_uuid",
                    "device.manufacturer",
                ]
                .contains(&f.key.as_str())
            })
            .cloned()
            .collect(),
    )
    .map_err(|_| Error::Storage)?;
    let reader = rss_mdm_inventory_service::assets::planning::SnapshotReader { tenant };
    let mut after = String::new();
    let mut identities = Vec::new();
    loop {
        let ids = endpoints::page_in(c, &tenant.to_string(), &after, 250).await?;
        if ids.is_empty() {
            break;
        }
        let devices = reader
            .devices_on(c, watermark, &ids, &catalog, true)
            .await
            .map_err(|_| Error::Storage)?;
        for device in devices {
            for channel in [Channel::Mdm, Channel::Agent] {
                let Some(member) =
                    endpoints::current_in(c, &tenant.to_string(), &device.device, channel).await?
                else {
                    continue;
                };
                let mut hardware = Hardware::default();
                for (field, resolved) in &device.fields {
                    let name = field.as_str();
                    if ![
                        "device.serial_number",
                        "device.hardware_uuid",
                        "device.manufacturer",
                    ]
                    .contains(&name)
                    {
                        continue;
                    }
                    for fact in &resolved.sources {
                        let e = &fact.evidence;
                        if e.source == Source::Manual
                            || e.source.channel() != Some(channel)
                            || e.registration.as_deref()
                                != Some(member.registration_id.to_string().as_str())
                            || e.registration_generation != Some(member.generation as u64)
                        {
                            continue;
                        }
                        if let FieldState::Known(Scalar::String(value)) = &fact.state
                            && let Some(value) = normalized(value, name == "device.hardware_uuid")
                        {
                            match name {
                                "device.serial_number" => {
                                    hardware.serial.insert(value);
                                }
                                "device.hardware_uuid" => {
                                    hardware.uuid.insert(value);
                                }
                                _ => {
                                    hardware.manufacturer.insert(value);
                                }
                            }
                            hardware.sources.push(e.clone());
                        }
                    }
                }
                identities.push(EndpointIdentity { member, hardware });
            }
        }
        after = ids.last().ok_or(Error::Storage)?.clone();
    }
    let ids: Vec<uuid::Uuid> = sqlx::query_scalar(
        "SELECT id FROM mdm_devices.associations WHERE tenant_id=$1::uuid ORDER BY id",
    )
    .bind(tenant.to_string())
    .fetch_all(&mut *c)
    .await?;
    let mut associations = Vec::new();
    for id in ids {
        associations.push(read::load(c, &tenant.to_string(), id).await?);
    }
    Ok(World {
        watermark,
        endpoints: identities,
        associations,
    })
}
pub(crate) fn evidence(world: &World, members: &[Member]) -> BTreeMap<String, Hardware> {
    members
        .iter()
        .filter_map(|m| {
            world
                .current(m)
                .map(|e| (m.channel.as_str().to_string(), e.hardware.clone()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hardware(serial: &str, uuid: &str) -> Hardware {
        Hardware {
            serial: normalized(serial, false).into_iter().collect(),
            uuid: normalized(uuid, true).into_iter().collect(),
            ..Hardware::default()
        }
    }
    #[test]
    fn serial_or_uuid_matches_without_requiring_both() {
        assert!(hardware(" 00-ab.c ", "").matches(&hardware("00-AB.C", "")));
        assert!(!hardware("00-AB.C", "").matches(&hardware("AB.C", "")));
        assert!(
            hardware("", "6ba7b810-9dad-11d1-80b4-00c04fd430c8")
                .matches(&hardware("", "6BA7B8109DAD11D180B400C04FD430C8"))
        );
        for placeholder in ["", "0000", "unknown", "To Be Filled By O.E.M."] {
            assert!(!hardware(placeholder, "").matches(&hardware(placeholder, "")));
        }
        assert!(normalized("ffffffff-ffff-ffff-ffff-ffffffffffff", true).is_none());
    }
    #[test]
    fn contradictions_block_but_duplicate_keys_still_compete() {
        let a = hardware("serial", "6ba7b810-9dad-11d1-80b4-00c04fd430c8");
        let b = hardware("serial", "6ba7b811-9dad-11d1-80b4-00c04fd430c8");
        assert!(!a.matches(&b));
        assert!(a.shares_key(&b));
        let mut bad = a.clone();
        bad.serial.insert("other".into());
        assert!(!bad.matches(&a));
        let mut vendor_a = a.clone();
        vendor_a.manufacturer.insert("ACME".into());
        let mut vendor_b = a.clone();
        vendor_b.manufacturer.insert("OTHER".into());
        assert!(!vendor_a.matches(&vendor_b));
    }
}
