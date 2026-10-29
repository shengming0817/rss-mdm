//! Hardware matching uses current authenticated source facts, never resolved/manual hints.
use crate::*;
use rss_mdm_inventory::{Channel, Evidence, Scalar, Source, State as FieldState};
use rss_mdm_registration_service::device::endpoints;
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;
use std::collections::{BTreeMap, BTreeSet};

#[derive(schemars::JsonSchema, Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Hardware {
    pub serial: BTreeSet<String>,
    pub uuid: BTreeSet<String>,
    pub manufacturer: BTreeSet<String>,
    pub sources: Vec<Evidence>,
}
impl Hardware {
    fn keys(&self) -> impl Iterator<Item = (&'static str, &String)> {
        self.serial
            .iter()
            .map(|v| ("serial", v))
            .chain(self.uuid.iter().map(|v| ("uuid", v)))
    }
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
            && self.shares_key(other)
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
fn normalized_manufacturer(value: &str) -> Option<String> {
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
    Some(value)
}
fn normalized(value: &str, uuid: bool) -> Option<String> {
    if uuid {
        rss_mdm_inventory::normalize_hardware_uuid(value).ok()
    } else {
        rss_mdm_inventory::normalize_serial_number(value).ok()
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct EndpointIdentity {
    pub member: Member,
    pub hardware: Hardware,
}
#[derive(Default)]
pub(crate) struct World {
    pub watermark: i64,
    pub endpoints: Vec<EndpointIdentity>,
    pub associations: Vec<Association>,
    by_device: BTreeMap<String, BTreeMap<&'static str, usize>>,
    by_hardware: BTreeMap<&'static str, BTreeMap<String, BTreeSet<String>>>,
    revoked_pairs: BTreeSet<(String, String)>,
}
impl World {
    fn insert(&mut self, endpoint: EndpointIdentity) {
        let index = self.endpoints.len();
        self.by_device
            .entry(endpoint.member.device.clone())
            .or_default()
            .insert(endpoint.member.channel.as_str(), index);
        for (kind, value) in endpoint.hardware.keys() {
            self.by_hardware
                .entry(kind)
                .or_default()
                .entry(value.clone())
                .or_default()
                .insert(endpoint.member.device.clone());
        }
        self.endpoints.push(endpoint);
    }
    pub fn current(&self, member: &Member) -> Option<&EndpointIdentity> {
        self.by_device
            .get(&member.device)?
            .get(member.channel.as_str())
            .and_then(|i| self.endpoints.get(*i))
    }
    /// Already associated endpoints represent one instance, not two competitors.
    pub fn unique(&self, members: &[Member], hardware: &Hardware) -> bool {
        hardware.keys().all(|(kind, value)| {
            self.by_hardware
                .get(kind)
                .and_then(|m| m.get(value))
                .is_none_or(|devices| {
                    devices.len() <= members.len()
                        && devices
                            .iter()
                            .all(|device| members.iter().any(|m| &m.device == device))
                })
        })
    }
    /// Read only key buckets of at most two endpoints; a larger bucket is ambiguous.
    pub fn peer(&self, endpoint: &EndpointIdentity) -> Option<&EndpointIdentity> {
        let mut candidates = BTreeSet::new();
        for (kind, value) in endpoint.hardware.keys() {
            let devices = self.by_hardware.get(kind)?.get(value)?;
            if devices.len() > 2 {
                return None;
            }
            candidates.extend(devices.iter().filter(|d| **d != endpoint.member.device));
        }
        if candidates.len() != 1 {
            return None;
        }
        let device = *candidates.first()?;
        let index = self.by_device.get(device)?.get(Channel::Agent.as_str())?;
        let peer = self.endpoints.get(*index)?;
        endpoint.hardware.matches(&peer.hardware).then_some(peer)
    }
    pub fn revoked(&self, members: &[Member]) -> bool {
        self.revoked_pairs
            .contains(&pair(&members[0].device, &members[1].device))
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
/// The asset watermark precedes authorization and channel locks; source facts flush last.
pub(crate) async fn world(c: &mut PgConnection, tenant: TenantId) -> Result<World> {
    let watermark = rss_mdm_inventory_postgres::lock_watermark_in(c, tenant).await?;
    let mut after = String::new();
    let mut world = World {
        watermark,
        ..World::default()
    };
    loop {
        let ids = endpoints::page_in(c, &tenant.to_string(), &after, 250).await?;
        if ids.is_empty() {
            break;
        }
        for endpoint in endpoint_page(c, tenant, watermark, &ids).await? {
            world.insert(endpoint);
        }
        after = ids.last().ok_or(Error::Storage)?.clone();
        tokio::task::yield_now().await;
    }
    let mut after = uuid::Uuid::nil();
    loop {
        let ids:Vec<uuid::Uuid>=sqlx::query_scalar("SELECT id FROM mdm_devices.associations WHERE tenant_id=$1::uuid AND id>$2 ORDER BY id LIMIT 250").bind(tenant.to_string()).bind(after).fetch_all(&mut *c).await?;
        if ids.is_empty() {
            break;
        }
        after = *ids.last().ok_or(Error::Storage)?;
        for id in ids {
            let a = read::load(c, &tenant.to_string(), id).await?;
            if a.state == State::Revoked {
                world
                    .revoked_pairs
                    .insert(pair(&a.members[0].device, &a.members[1].device));
            }
            world.associations.push(a);
        }
        tokio::task::yield_now().await;
    }
    Ok(world)
}
/// Writer validation: selected members and at most three distinct competitors
/// per exact canonical hardware key. No tenant-wide endpoint/history materialization.
pub(crate) async fn local_world(
    c: &mut PgConnection,
    tenant: TenantId,
    ids: &[String],
    associations: &[uuid::Uuid],
) -> Result<World> {
    if ids.len() > 200 || associations.len() > 100 {
        return Err(Error::Malformed);
    }
    let watermark = rss_mdm_inventory_postgres::lock_watermark_in(c, tenant).await?;
    let mut world = endpoint_world(endpoint_page(c, tenant, watermark, ids).await?);
    world.watermark = watermark;
    world.associations = read::load_page(c, &tenant.to_string(), associations).await?;
    let keys = world
        .endpoints
        .iter()
        .flat_map(|e| {
            e.hardware
                .keys()
                .map(|(kind, value)| (kind.to_owned(), value.clone()))
        })
        .collect::<BTreeSet<_>>();
    let (kinds, values): (Vec<_>, Vec<_>) = keys.into_iter().unzip();
    let peers:Vec<(String,String,String)>=sqlx::query_as("SELECT q.kind,q.value,p.device FROM unnest($2::text[],$3::text[]) q(kind,value) CROSS JOIN LATERAL (SELECT DISTINCT device FROM mdm_assets.hardware_keys h WHERE h.tenant_id=$1::uuid AND h.kind=q.kind AND h.value=q.value ORDER BY device LIMIT 3) p")
        .bind(tenant.to_string()).bind(kinds).bind(values).fetch_all(c).await?;
    for (kind, value, device) in peers {
        let kind = match kind.as_str() {
            "serial" => "serial",
            "uuid" => "uuid",
            _ => return Err(Error::Storage),
        };
        world
            .by_hardware
            .entry(kind)
            .or_default()
            .entry(value)
            .or_default()
            .insert(device);
    }
    Ok(world)
}
pub(crate) fn from_snapshot(
    watermark: i64,
    endpoints: Vec<EndpointIdentity>,
    associations: Vec<Association>,
    peers: Vec<(String, String, String)>,
) -> Result<World> {
    let mut world = endpoint_world(endpoints);
    world.watermark = watermark;
    world.associations = associations;
    for (kind, value, device) in peers {
        let kind = match kind.as_str() {
            "serial" => "serial",
            "uuid" => "uuid",
            _ => return Err(Error::Storage),
        };
        world
            .by_hardware
            .entry(kind)
            .or_default()
            .entry(value)
            .or_default()
            .insert(device);
    }
    Ok(world)
}
fn pair(a: &str, b: &str) -> (String, String) {
    if a < b {
        (a.into(), b.into())
    } else {
        (b.into(), a.into())
    }
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

pub(crate) async fn endpoint_page(
    c: &mut PgConnection,
    tenant: TenantId,
    watermark: i64,
    ids: &[String],
) -> Result<Vec<EndpointIdentity>> {
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
    let devices = reader
        .scalar_devices_on(c, watermark, ids, &catalog)
        .await
        .map_err(|_| Error::Storage)?;
    let primary = endpoints::current_page_in(c, &tenant.to_string(), ids).await?;
    endpoint_facts(&devices.iter().collect::<Vec<_>>(), primary)
}
pub(crate) fn endpoint_facts(
    devices: &[&rss_mdm_inventory_service::assets::DeviceView],
    primary: Vec<endpoints::PrimaryRegistration>,
) -> Result<Vec<EndpointIdentity>> {
    let primary = primary
        .into_iter()
        .map(|member| ((member.device.clone(), member.channel.as_str()), member))
        .collect::<BTreeMap<_, _>>();
    let mut result = Vec::new();
    for device in devices {
        for channel in [Channel::Mdm, Channel::Agent] {
            let Some(member) = primary
                .get(&(device.device.clone(), channel.as_str()))
                .cloned()
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
                        && let Some(value) = if name == "device.manufacturer" {
                            normalized_manufacturer(value)
                        } else {
                            normalized(value, name == "device.hardware_uuid")
                        }
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
            result.push(EndpointIdentity { member, hardware });
        }
    }
    Ok(result)
}
pub(crate) fn endpoint_world(endpoints: Vec<EndpointIdentity>) -> World {
    let mut world = World::default();
    for endpoint in endpoints {
        world.insert(endpoint);
    }
    world
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
    fn indexed_matching_counts_a_pair_once_and_keeps_conflicting_competitors() {
        let endpoint = |device: &str, channel: Channel, hardware: Hardware| EndpointIdentity {
            member: Member {
                device: device.into(),
                channel,
                registration_id: uuid::Uuid::new_v4(),
                generation: 1,
            },
            hardware,
        };
        let mut world = World::default();
        world.insert(endpoint(
            "mdm",
            Channel::Mdm,
            hardware("SERIAL", "6ba7b810-9dad-11d1-80b4-00c04fd430c8"),
        ));
        world.insert(endpoint(
            "agent",
            Channel::Agent,
            hardware("SERIAL", "6ba7b810-9dad-11d1-80b4-00c04fd430c8"),
        ));
        let mdm = world.endpoints[0].clone();
        let agent = world.peer(&mdm).unwrap().clone();
        assert!(world.unique(&[mdm.member.clone(), agent.member.clone()], &mdm.hardware));
        world.insert(endpoint(
            "third",
            Channel::Mdm,
            hardware("SERIAL", "6ba7b811-9dad-11d1-80b4-00c04fd430c8"),
        ));
        assert!(world.peer(&mdm).is_none());
        assert!(!world.unique(&[mdm.member, agent.member], &mdm.hardware));
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
