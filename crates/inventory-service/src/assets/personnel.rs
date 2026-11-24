//! Fixed-cut, server-side field inputs. Only referenced keys are loaded.
//! ref: PostgreSQL REL_17_STABLE doc/src/sgml/queries.sgml
use super::*;
use rss_mdm_agent_wire::DeviceId;
use rss_mdm_authorization_service::{Permission, Snapshot, context::AuthorizedPrincipal};
use rss_mdm_inventory::personnel::{self, Attribute, DeviceUser};
use sqlx::Row;

#[derive(Clone, Debug, serde::Serialize)]
pub struct Fact {
    pub subject: Option<Uuid>,
    pub value: Option<Scalar>,
    pub revision: i64,
    pub observed_at: i64,
}

pub fn permissions(key: FieldKey) -> impl Iterator<Item = Permission> {
    let fields = personnel::attribute(key)
        .map(|(user, field)| {
            [
                Some(match user {
                    DeviceUser::Registration => Permission::Enrollment,
                    DeviceUser::Current => Permission::InventorySensitiveRead,
                }),
                match field {
                    Attribute::Provider(_, personnel::ProviderAttribute::Groups)
                    | Attribute::LocalGroups => Some(Permission::UserGroupRead),
                    Attribute::Provider(..) => Some(Permission::DepartmentRead),
                    Attribute::Profile(_) => Some(Permission::UserProfilesRead),
                    _ => None,
                },
            ]
        })
        .unwrap_or([None, None]);
    fields.into_iter().flatten()
}

pub fn readable(key: FieldKey, proof: &AuthorizedPrincipal, authority: &Snapshot) -> bool {
    permissions(key).all(|permission| {
        if permission.device() {
            authority.devices_for(proof, permission).is_ok()
        } else {
            authority.require(proof, permission, None).is_ok()
        }
    })
}
pub(super) async fn load_in(
    tx: &mut PgTransaction<'_>,
    cut: &AssetCut,
    ids: &[DeviceId],
    fields: &[FieldKey],
) -> Result<BTreeMap<DeviceId, BTreeMap<FieldKey, Fact>>> {
    if fields.is_empty() || ids.is_empty() {
        return Ok(BTreeMap::new());
    }
    let tenant = tx.tenant_id().to_string();
    let ids = ids.iter().map(|id| id.into_uuid()).collect::<Vec<_>>();
    let keys = fields
        .iter()
        .map(|f| f.as_str().to_owned())
        .collect::<Vec<_>>();
    let cut = cut.to_json();
    let rows = tx
        .with_connection(move |c| {
            Box::pin(async move {
                if !sqlx::query_scalar::<_, bool>("SELECT mdm_user_profiles.fields_current()")
                    .fetch_one(&mut *c)
                    .await?
                {
                    return Ok(None);
                }
                let rows = sqlx::query(include_str!("personnel.sql"))
                    .bind(tenant)
                    .bind(ids)
                    .bind(keys)
                    .bind(cut)
                    .fetch_all(c)
                    .await?;
                Ok(Some(rows))
            })
        })
        .await?
        .ok_or(Error::Unavailable(Failure::AssetSources))?;
    let mut page = BTreeMap::<_, BTreeMap<_, _>>::new();
    for row in rows {
        let id = crate::database::device_id(row.try_get("device")?)?;
        let key = stored(FieldKey::parse(row.try_get("field")?))?;
        let raw: Option<Value> = row.try_get("value")?;
        page.entry(id).or_default().insert(
            key,
            Fact {
                subject: row.try_get("subject")?,
                value: raw
                    .map(serde_json::from_value)
                    .transpose()
                    .map_err(|_| Error::Conflict)?,
                revision: row.try_get("revision")?,
                observed_at: row.try_get("observed_at")?,
            },
        );
    }
    Ok(page)
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Access {
    registration: Option<BTreeSet<DeviceId>>,
    current: bool,
    groups: bool,
    profiles: bool,
    departments: bool,
}
impl Access {
    pub fn all() -> Self {
        Self {
            registration: None,
            current: true,
            groups: true,
            profiles: true,
            departments: true,
        }
    }
    pub(super) fn from_snapshot(p: &AuthorizedPrincipal, snapshot: &Snapshot) -> Self {
        Self {
            departments: snapshot
                .require(p, Permission::DepartmentRead, None)
                .is_ok(),
            registration: snapshot
                .devices_for(p, Permission::Enrollment)
                .unwrap_or(Some(BTreeSet::new())),
            current: snapshot
                .require(p, Permission::InventorySensitiveRead, None)
                .is_ok(),
            groups: snapshot.require(p, Permission::UserGroupRead, None).is_ok(),
            profiles: snapshot
                .require(p, Permission::UserProfilesRead, None)
                .is_ok(),
        }
    }
    pub fn allows(&self, key: FieldKey, devices: Option<&BTreeSet<DeviceId>>) -> bool {
        permissions(key).all(|p| match p {
            Permission::Enrollment => self
                .registration
                .as_ref()
                .is_none_or(|allowed| devices.is_some_and(|ids| ids.is_subset(allowed))),
            Permission::InventorySensitiveRead => self.current,
            Permission::UserGroupRead => self.groups,
            Permission::UserProfilesRead => self.profiles,
            Permission::DepartmentRead => self.departments,
            _ => false,
        })
    }
}
