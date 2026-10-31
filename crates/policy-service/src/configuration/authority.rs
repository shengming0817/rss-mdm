//! Configuration grants retain the exact authored version and native unit identity.
use super::{definition::Owner, frozen::Frozen, *};
use crate::authorization::Permission;
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, Row};
mod read;
pub(crate) use read::many;
#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Authority {
    Policy {
        origin: rss_mdm_audit_integration::activity::ActivityOrigin,
        source_objects: Vec<rss_mdm_scope_service::channels::DeviceObject>,
        unit: String,
        required: Vec<Permission>,
        tenant: String,
        policy: Uuid,
        version: Uuid,
        device: String,
        remove: bool,
    },
    Retirement {
        origin: rss_mdm_audit_integration::activity::ActivityOrigin,
        tenant: String,
        retirement: Uuid,
        version: Uuid,
        device: String,
        registration: Uuid,
        execution: Uuid,
        required: Vec<Permission>,
    },
}
impl Authority {
    pub fn version(&self) -> Uuid {
        match self {
            Self::Policy { version, .. } | Self::Retirement { version, .. } => *version,
        }
    }
    pub fn required(&self) -> &[Permission] {
        match self {
            Self::Policy { required, .. } | Self::Retirement { required, .. } => required,
        }
    }
    pub fn bind_required(&mut self, value: Vec<Permission>) {
        match self {
            Self::Policy { required, .. } | Self::Retirement { required, .. } => *required = value,
        }
    }
    pub fn apple_owner(&self) -> String {
        match self {
            Self::Policy { unit, .. } => format!("configuration:{unit}"),
            Self::Retirement { retirement, .. } => format!("retirement:{retirement}"),
        }
    }
    pub async fn dispatch_ready(
        &self,
        source: &rss_mdm_scope_service::channels::ChannelTargets,
        c: &mut PgConnection,
    ) -> std::result::Result<bool, Error> {
        match self {
            Self::Policy { remove: true, .. } => Ok(true),
            Self::Policy {
                tenant,
                device,
                source_objects,
                ..
            } => Ok(source
                .evidence_valid_on(
                    c,
                    TenantId::parse(tenant).map_err(|_| Error::Malformed)?,
                    rss_mdm_inventory::Channel::Mdm,
                    device,
                    source_objects,
                )
                .await?),
            Self::Retirement {
                tenant,
                device,
                execution,
                ..
            } => rss_mdm_device_service::lifecycle::execution_allowed_in(
                c, tenant, device, *execution,
            )
            .await
            .map_err(Error::from),
        }
    }
    pub async fn receipt_valid(
        &self,
        c: &mut PgConnection,
        key: &rss_mdm_native_protection::Protector,
        permissions: &[Permission],
    ) -> std::result::Result<bool, Error> {
        if permissions.is_empty() {
            return Ok(false);
        }
        let Self::Policy {
            tenant,
            policy,
            version,
            ..
        } = self
        else {
            return Ok(permissions.iter().all(|p| self.required().contains(p)));
        };
        let frozen:Option<serde_json::Value>=sqlx::query_scalar("SELECT frozen FROM mdm_policy.versions WHERE tenant_id=$1::uuid AND id=$2 AND policy=$3").bind(tenant).bind(version).bind(policy).fetch_optional(c).await.map_err(db)?;
        let Some(frozen) = frozen else {
            return Ok(false);
        };
        let Frozen::Configuration { native, .. } = serde_json::from_value(frozen)
            .map_err(|_| Error::Unavailable(Failure::NativeInputIntegrity))?;
        let native = native.open(
            key,
            TenantId::parse(tenant).map_err(|_| Error::Malformed)?,
            Owner::Policy {
                policy: *policy,
                version: *version,
            },
        )?;
        let mut accepted = native.apply.permissions()?;
        if let Some(remove) = native.remove {
            accepted.extend(remove.permissions()?);
        }
        Ok(permissions
            .iter()
            .chain(self.required())
            .all(|p| accepted.contains(p)))
    }
    pub async fn valid(
        &self,
        source: &rss_mdm_scope_service::channels::ChannelTargets,
        c: &mut PgConnection,
        key: &rss_mdm_native_protection::Protector,
        permissions: &[Permission],
        _now: i64,
    ) -> std::result::Result<bool, Error> {
        if !self.receipt_valid(c, key, permissions).await? {
            return Ok(false);
        }
        match self {
            Self::Retirement {
                tenant,
                device,
                execution,
                retirement,
                registration,
                ..
            } => {
                let allowed = rss_mdm_device_service::lifecycle::execution_allowed_in(
                    c, tenant, device, *execution,
                )
                .await
                .map_err(Error::from)?;
                let current:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_devices.retirement_work w JOIN mdm_access.registrations r ON(r.tenant_id,r.id)=(w.tenant_id,w.registration) WHERE w.tenant_id=$1::uuid AND w.operation=$2 AND w.registration=$3 AND w.execution=$4 AND r.device=$5 AND r.state='active')").bind(tenant).bind(retirement).bind(registration).bind(execution).bind(device).fetch_one(c).await.map_err(db)?;
                Ok(allowed && current)
            }
            Self::Policy {
                tenant,
                policy,
                version,
                device,
                remove,
                unit,
                ..
            } => {
                sqlx::query("SELECT mdm_policy.lock_policy($1)")
                    .bind(policy)
                    .execute(&mut *c)
                    .await
                    .map_err(db)?;
                let row=sqlx::query("SELECT v.frozen,p.state='enabled' AS live FROM mdm_policy.versions v LEFT JOIN mdm_policy.policies p ON(p.tenant_id,p.id)=(v.tenant_id,v.policy) WHERE v.tenant_id=$1::uuid AND v.id=$2 AND v.policy=$3 AND octet_length(v.frozen::text)<=16777216").bind(tenant).bind(version).bind(policy).fetch_optional(&mut *c).await.map_err(db)?;
                let Some(row) = row else { return Ok(false) };
                let tenant_id = TenantId::parse(tenant).map_err(|_| Error::Malformed)?;
                let Frozen::Configuration { native, exit, .. } =
                    serde_json::from_value(row.try_get("frozen").map_err(db)?)
                        .map_err(|_| Error::Unavailable(Failure::NativeInputIntegrity))?;
                let native = native.open(
                    key,
                    tenant_id,
                    Owner::Policy {
                        policy: *policy,
                        version: *version,
                    },
                )?;
                if native.unit_key(key, tenant_id, device)? != *unit {
                    return Ok(false);
                }
                if !*remove {
                    let retained = matches!(exit, rss_mdm_policy::Exit::Retain)
                        && matches!(
                            native.apply,
                            Task::Macos {
                                request:
                                    rss_mdm_apple_mdm::native::request::Request::Declarations { .. }
                            }
                        );
                    let claimed:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_planning.configuration_claims cc JOIN mdm_planning.configuration_operations o ON(o.tenant_id,o.id)=(cc.tenant_id,cc.operation) JOIN mdm_policy.policies p ON(p.tenant_id,p.id)=(cc.tenant_id,cc.policy) WHERE cc.tenant_id=$1::uuid AND cc.device=$2 AND o.authority->>'unit'=$3 AND p.state='enabled')").bind(tenant).bind(device).bind(unit).fetch_one(c).await.map_err(db)?;
                    return Ok(retained
                        || row
                            .try_get::<Option<bool>, _>("live")
                            .map_err(db)?
                            .unwrap_or(false)
                        || claimed);
                }
                if !matches!(exit, rss_mdm_policy::Exit::Remove) || native.remove.is_none() {
                    return Ok(false);
                }
                let expected = native.objects()?;
                let mut after = Uuid::nil();
                let candidates = candidates::PolicyCandidates {
                    objects: source.objects.clone(),
                };
                loop {
                    let page = candidates
                        .candidates_on(
                            c,
                            tenant_id,
                            device,
                            candidates::CandidateKind::Configuration,
                            after,
                        )
                        .await?;
                    for candidate in page.items {
                        let value:Option<serde_json::Value>=sqlx::query_scalar("SELECT frozen FROM mdm_policy.versions WHERE tenant_id=$1::uuid AND id=$2 AND policy=$3 AND octet_length(frozen::text)<=16777216").bind(tenant).bind(candidate.version).bind(candidate.policy).fetch_optional(&mut *c).await.map_err(db)?;
                        let value =
                            value.ok_or(Error::Unavailable(Failure::NativeInputIntegrity))?;
                        let Frozen::Configuration { native, .. } = serde_json::from_value(value)
                            .map_err(|_| Error::Unavailable(Failure::NativeInputIntegrity))?;
                        let current = native.open(
                            key,
                            tenant_id,
                            Owner::Policy {
                                policy: candidate.policy,
                                version: candidate.version,
                            },
                        )?;
                        if current
                            .objects()?
                            .iter()
                            .any(|o| expected.iter().any(|e| o.overlaps(e)))
                        {
                            return Ok(false);
                        }
                    }
                    if !page.has_more {
                        break;
                    }
                    if page.scanned_after <= after {
                        return Err(Error::Unavailable(Failure::CommandInvariant));
                    }
                    after = page.scanned_after;
                }
                Ok(true)
            }
        }
    }
}
