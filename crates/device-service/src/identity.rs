//! Hardware matching uses current authenticated source facts, never resolved/manual hints.
use crate::*;
use rss_mdm_inventory::{Channel, Evidence, Scalar, Source, State as FieldState};
use rss_mdm_registration_service::device::endpoints;
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

#[derive(schemars::JsonSchema, Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Hardware {
    pub serial: BTreeSet<String>,
    pub uuid: BTreeSet<String>,
    pub manufacturer: BTreeSet<String>,
    pub sources: Vec<Evidence>,
}
impl Hardware {
    pub(crate) fn keys(&self) -> impl Iterator<Item = (&'static str, &String)> {
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct EndpointIdentity {
    pub member: Member,
    pub hardware: Hardware,
}
#[derive(Default)]
pub(crate) struct World {
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
/// Writer validation: selected members and at most three distinct competitors
/// per exact canonical hardware key. No tenant-wide endpoint/history materialization.
pub(crate) async fn local_world(
    c: &mut PgConnection,
    tenant: TenantId,
    ids: &[String],
    associations: &[Uuid],
) -> Result<World> {
    if ids.len() > 200 || associations.len() > 100 {
        return Err(Error::Malformed);
    }
    let value:serde_json::Value=sqlx::query_scalar("SELECT mdm_devices.read_world($1,$2,ARRAY['device.serial_number','device.hardware_uuid','device.manufacturer']::text[])")
        .bind(associations).bind(ids).fetch_one(c).await?;
    Ok(crate::snapshot::decode_world(&value, tenant, ids)?.0)
}
async fn add_peers(c: &mut PgConnection, tenant: TenantId, world: &mut World) -> Result<()> {
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
    Ok(())
}
pub(crate) fn from_snapshot(
    endpoints: Vec<EndpointIdentity>,
    associations: Vec<Association>,
    peers: Vec<(String, String, String)>,
) -> Result<World> {
    let mut world = endpoint_world(endpoints);
    world.revoked_pairs = associations
        .iter()
        .filter(|a| a.state == State::Revoked)
        .map(|a| pair(&a.members[0].device, &a.members[1].device))
        .collect();
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
/// The exact relevant index inputs, checked against canonical source interpretation.
/// Saturated three-candidate buckets prove ambiguity; they never prove uniqueness.
#[derive(PartialEq, Eq)]
struct Stamp {
    endpoints: Vec<EndpointIdentity>,
    associations: BTreeMap<Uuid, i64>,
    peers: BTreeMap<&'static str, BTreeMap<String, BTreeSet<String>>>,
    revoked: BTreeSet<(String, String)>,
}
pub(crate) struct PreparedWorld {
    pub world: World,
    ids: Vec<String>,
    stamp: Stamp,
}
impl PreparedWorld {
    /// Called only after all computation, before any association/evidence publication.
    pub(crate) async fn fence(&self, c: &mut PgConnection, tenant: TenantId) -> Result<()> {
        // Only the Device publication owner touches this row; ingress never does.
        // NOWAIT avoids the claim/publication inversion with the input worker.
        sqlx::query("SELECT tenant_id FROM mdm_devices.checkpoints WHERE tenant_id=$1::uuid FOR UPDATE NOWAIT")
            .bind(tenant.to_string()).fetch_optional(&mut *c).await?;
        if stamp(c, tenant, &self.ids).await? != self.stamp {
            return Err(Error::Conflict);
        }
        Ok(())
    }
}
async fn stamp(c: &mut PgConnection, tenant: TenantId, ids: &[String]) -> Result<Stamp> {
    let t = tenant.to_string();
    let endpoints = local_world(c, tenant, ids, &[]).await?.endpoints;
    let mut indexed = endpoint_world(endpoints.clone());
    add_peers(c, tenant, &mut indexed).await?;
    let associations: Vec<(Uuid, i64)> = sqlx::query_as("SELECT DISTINCT a.id,a.version FROM mdm_devices.associations a JOIN mdm_devices.members m ON(m.tenant_id,m.association_id)=(a.tenant_id,a.id) WHERE a.tenant_id=$1::uuid AND m.device=ANY($2) AND NOT m.released ORDER BY a.id")
        .bind(&t).bind(ids).fetch_all(&mut *c).await?;
    let revoked: Vec<(String,String)> = sqlx::query_as("SELECT a.device,b.device FROM mdm_devices.members a JOIN mdm_devices.members b USING(tenant_id,association_id) JOIN mdm_devices.associations r ON(r.tenant_id,r.id)=(a.tenant_id,a.association_id) WHERE a.tenant_id=$1::uuid AND a.device=ANY($2) AND b.device=ANY($2) AND a.device<b.device AND r.state='revoked'")
        .bind(&t).bind(ids).fetch_all(c).await?;
    Ok(Stamp {
        endpoints,
        associations: associations.into_iter().collect(),
        peers: indexed.by_hardware,
        revoked: revoked.into_iter().map(|(a, b)| pair(&a, &b)).collect(),
    })
}
/// Read and compute under the affected device fences, without the tenant publication lock.
pub(crate) async fn affected_world(
    c: &mut PgConnection,
    tenant: TenantId,
    device: &str,
) -> Result<PreparedWorld> {
    let t = tenant.to_string();
    let mut ids: BTreeSet<String> = sqlx::query_scalar("SELECT DISTINCT p.device FROM mdm_assets.hardware_keys k CROSS JOIN LATERAL (SELECT DISTINCT device FROM mdm_assets.hardware_keys WHERE tenant_id=k.tenant_id AND kind=k.kind AND value=k.value ORDER BY device LIMIT 3) p WHERE k.tenant_id=$1::uuid AND k.device=$2")
        .bind(&t).bind(device).fetch_all(&mut *c).await?.into_iter().collect();
    ids.insert(device.into());
    let associated: Vec<String> = sqlx::query_scalar("SELECT peer.device FROM mdm_devices.members anchor JOIN mdm_devices.members peer USING(tenant_id,association_id) WHERE anchor.tenant_id=$1::uuid AND anchor.device=$2 AND NOT anchor.released")
        .bind(&t).bind(device).fetch_all(&mut *c).await?;
    ids.extend(associated);
    let ids = ids.into_iter().collect::<Vec<_>>();
    if !rss_mdm_registration_service::lifecycle::try_lock_devices_in(c, &t, &ids).await? {
        return Err(Error::Conflict);
    }
    let association_ids: Vec<Uuid> = sqlx::query_scalar("SELECT DISTINCT association_id FROM mdm_devices.members WHERE tenant_id=$1::uuid AND device=ANY($2) AND NOT released ORDER BY association_id")
        .bind(&t).bind(&ids).fetch_all(&mut *c).await?;
    let mut world = local_world(c, tenant, &ids, &association_ids).await?;
    let stamp = stamp(c, tenant, &ids).await?;
    let mut canonical = world.endpoints.clone();
    canonical.sort_by(|a, b| {
        (&a.member.device, a.member.channel.as_str())
            .cmp(&(&b.member.device, b.member.channel.as_str()))
    });
    if canonical != stamp.endpoints
        || world.by_hardware != stamp.peers
        || world
            .associations
            .iter()
            .map(|a| (a.id, a.version))
            .collect::<BTreeMap<_, _>>()
            != stamp.associations
    {
        return Err(Error::Conflict);
    }
    world.revoked_pairs = stamp.revoked.clone();
    Ok(PreparedWorld { world, ids, stamp })
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
    cut: &rss_mdm_inventory::AssetCut,
    ids: &[String],
) -> Result<Vec<EndpointIdentity>> {
    let catalog = rss_mdm_inventory_postgres::catalog_at_in(c, tenant, cut)
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
        .scalar_devices_on(c, cut, ids, &catalog)
        .await
        .map_err(|_| Error::Storage)?;
    let primary = endpoints::page_at(c, &tenant.to_string(), cut, ids).await?;
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
