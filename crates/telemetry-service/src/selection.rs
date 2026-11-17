//! Tenant selections share the same transaction fence with first use and storage delivery.
use crate::{Error, backend::SystemClock};
use rss_mdm_native_protection::{DerivedAad, ProtectionContext, Protector};
use rss_request_context::{Deadline, TenantId};
use rss_timeseries_clickhouse::{ChOwner, ChStore, Credentials, CursorKey};
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, Row};
use std::{
    collections::HashMap,
    num::NonZeroU64,
    sync::{Arc, Mutex},
    time::Duration,
};
use uuid::Uuid;
use zeroize::Zeroizing;

/// Current selection in the tenant-scoped transaction.
#[derive(Serialize, Deserialize)]
pub struct Selection {
    pub binding: Vec<u8>,
    pub resource_id: Option<Uuid>,
    pub revision: i64,
    pub operation_id: Option<Uuid>,
    pub material: Option<Vec<u8>>,
}

pub async fn load(c: &mut PgConnection, tenant: TenantId) -> Result<Option<Selection>, Error> {
    load_row(c, tenant, false).await
}
pub(crate) async fn load_row(
    c: &mut PgConnection,
    tenant: TenantId,
    active_only: bool,
) -> Result<Option<Selection>, Error> {
    let row=sqlx::query("SELECT binding,resource_id,revision,operation_id,material FROM mdm_telemetry.storage_binding WHERE tenant_id=$1::uuid AND (NOT $2 OR pending IS NULL)")
        .bind(tenant.to_string()).bind(active_only).fetch_optional(c).await?;
    row.map(|r| {
        Ok(Selection {
            binding: r.try_get("binding")?,
            resource_id: r.try_get("resource_id")?,
            revision: r.try_get("revision")?,
            operation_id: r.try_get("operation_id")?,
            material: r.try_get("material")?,
        })
    })
    .transpose()
}
pub(crate) async fn lock_read(c: &mut PgConnection, tenant: TenantId) -> Result<(), Error> {
    sqlx::query("SELECT pg_advisory_xact_lock_shared(hashtextextended($1,3190))")
        .bind(tenant.to_string())
        .execute(c)
        .await?;
    Ok(())
}
/// Serialize selection with earlier admissions, definitions and maintenance intents.
pub async fn lock_change(c: &mut PgConnection, tenant: TenantId) -> Result<(), Error> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,3190))")
        .bind(tenant.to_string())
        .execute(c)
        .await?;
    Ok(())
}
/// The cursor survives reader rotation and retirement on the same installation.
#[derive(Serialize, Deserialize)]
pub struct Reader {
    pub user: String,
    pub password: Option<Zeroizing<String>>,
    pub cursor: Zeroizing<[u8; 32]>,
}
fn aad(tenant: TenantId, resource: Uuid, rev: i64) -> Result<DerivedAad, Error> {
    ProtectionContext::new(tenant, &format!("{resource}.{rev}"), "telemetry.reader", 1)
        .map(|v| v.derive())
        .map_err(|_| Error::Invalid)
}
impl Reader {
    pub fn seal(
        &self,
        key: &Protector,
        tenant: TenantId,
        resource: Uuid,
        rev: i64,
    ) -> Result<Vec<u8>, Error> {
        let bytes = Zeroizing::new(serde_json::to_vec(self)?);
        key.seal_bytes(&bytes, &aad(tenant, resource, rev)?)
            .map_err(|_| Error::Storage)
    }
    pub async fn bind(
        &self,
        owner: &ChOwner<SystemClock>,
        tenant: TenantId,
        rev: i64,
        deadline: Deadline,
    ) -> Result<ChStore<SystemClock>, Error> {
        let version = u64::try_from(rev)
            .ok()
            .and_then(NonZeroU64::new)
            .ok_or(Error::Storage)?;
        let password = self.password.as_ref().ok_or(Error::Denied)?;
        Ok(owner
            .bind_tenant(
                tenant,
                Credentials::new(self.user.clone(), password.to_string())?,
                CursorKey::new(*self.cursor),
                version,
                deadline,
            )
            .await?)
    }
}
impl Selection {
    pub fn reader(&self, key: &Protector, tenant: TenantId) -> Result<Option<Reader>, Error> {
        let Some(bytes) = &self.material else {
            return Ok(None);
        };
        let aad = aad(
            tenant,
            self.resource_id.ok_or(Error::Storage)?,
            self.revision,
        )?;
        let plain = key.open_bytes(bytes, &aad).map_err(|_| Error::Storage)?;
        serde_json::from_slice(plain.expose())
            .map(Some)
            .map_err(|_| Error::Storage)
    }
}
/// Participate in the existing product key rotation transaction.
pub async fn rewrap(c: &mut PgConnection, tenant: TenantId, key: &Protector) -> Result<u64, Error> {
    lock_change(c, tenant).await?;
    let mut changed = 0;
    if let Some(mut current) = load(c, tenant).await?
        && rewrap_selection(&mut current, tenant, key)?
    {
        sqlx::query(
            "UPDATE mdm_telemetry.storage_binding SET material=$2 WHERE tenant_id=$1::uuid",
        )
        .bind(tenant.to_string())
        .bind(current.material)
        .execute(&mut *c)
        .await?;
        changed += 1;
    }
    if let Some(mut pending) = pending(c, tenant).await?
        && rewrap_selection(&mut pending, tenant, key)?
    {
        sqlx::query("UPDATE mdm_telemetry.storage_binding SET pending=$2 WHERE tenant_id=$1::uuid")
            .bind(tenant.to_string())
            .bind(serde_json::to_value(pending)?)
            .execute(c)
            .await?;
        changed += 1;
    }
    Ok(changed)
}
fn rewrap_selection(row: &mut Selection, tenant: TenantId, key: &Protector) -> Result<bool, Error> {
    let Some(bytes) = row.material.as_ref() else {
        return Ok(false);
    };
    if bytes.starts_with(&key.ciphertext_prefix()) {
        return Ok(false);
    }
    let aad = aad(tenant, row.resource_id.ok_or(Error::Storage)?, row.revision)?;
    row.material = Some(key.rewrap_bytes(bytes, &aad).map_err(|_| Error::Storage)?);
    Ok(true)
}
pub async fn pending(c: &mut PgConnection, tenant: TenantId) -> Result<Option<Selection>, Error> {
    let row=sqlx::query_scalar::<_,serde_json::Value>("SELECT pending FROM mdm_telemetry.storage_binding WHERE tenant_id=$1::uuid AND pending IS NOT NULL")
        .bind(tenant.to_string()).fetch_optional(c).await?;
    row.map(serde_json::from_value)
        .transpose()
        .map_err(|_| Error::Storage)
}
/// Freeze the next revision while admissions and maintenance share the tenant fence.
pub async fn reserve(
    c: &mut PgConnection,
    tenant: TenantId,
    current: &Selection,
    next: &Selection,
) -> Result<(), Error> {
    if next.revision != current.revision.checked_add(1).ok_or(Error::Invalid)? {
        return Err(Error::Conflict);
    }
    if current.binding != next.binding {
        let used:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_telemetry.batches WHERE tenant_id=$1::uuid) OR EXISTS(SELECT FROM mdm_telemetry.definition_progress WHERE tenant_id=$1::uuid) OR EXISTS(SELECT FROM mdm_telemetry.maintenance WHERE tenant_id=$1::uuid)").bind(tenant.to_string()).fetch_one(&mut *c).await?;
        if used {
            return Err(Error::Conflict);
        }
    }
    let rows=sqlx::query("UPDATE mdm_telemetry.storage_binding SET pending=$3 WHERE tenant_id=$1::uuid AND revision=$2 AND pending IS NULL")
        .bind(tenant.to_string()).bind(current.revision).bind(serde_json::to_value(next)?).execute(c).await?.rows_affected();
    if rows != 1 {
        return Err(Error::Conflict);
    }
    Ok(())
}
pub async fn ready(c: &mut PgConnection, tenant: TenantId, op: Uuid) -> Result<(), Error> {
    if sqlx::query("UPDATE mdm_telemetry.storage_binding SET probe_ready=true WHERE tenant_id=$1::uuid AND pending->>'operation_id'=$2")
        .bind(tenant.to_string()).bind(op.to_string()).execute(c).await?.rows_affected()!=1 {return Err(Error::Conflict);}
    Ok(())
}
/// The installer publishes only the original probed operation. Retirement has verified account absence.
pub async fn publish(
    c: &mut PgConnection,
    tenant: TenantId,
    op: Uuid,
    retire: bool,
) -> Result<bool, Error> {
    let Some(next) = pending(c, tenant).await? else {
        return Err(Error::Conflict);
    };
    if next.operation_id != Some(op) {
        return Err(Error::Conflict);
    }
    Ok(sqlx::query("UPDATE mdm_telemetry.storage_binding SET binding=$3,resource_id=$4,revision=$5,operation_id=$2,material=$6,pending=NULL,probe_ready=false,qualified=NULL WHERE tenant_id=$1::uuid AND pending->>'operation_id'=($2::uuid)::text AND (qualified=$2 OR $7)")
        .bind(tenant.to_string()).bind(op).bind(next.binding).bind(next.resource_id).bind(next.revision).bind(next.material).bind(retire).execute(c).await?.rows_affected()==1)
}
impl crate::Service {
    /// The existing scoped relay performs admission on the host-owned physical resource.
    pub(crate) async fn qualify_reader(
        self: &Arc<Self>,
        execution: rss_transactional_messaging::fence::ExecutionBinding,
    ) -> Result<(), Error> {
        let service = self.clone();
        let cutoff = Deadline::from_timeout(&SystemClock, Duration::from_secs(6))
            .map_err(|_| Error::Storage)?;
        self.runtime
            .local_tx(
                execution,
                rss_transactional_messaging::policy::OperationDeadline::from_cutoff(
                    cutoff,
                    &SystemClock,
                ),
                move |tx| {
                    Box::pin(async move {
                        tx.with_connection(move |c| {
                            Box::pin(async move {
                                Ok(service.qualify_on(c, execution.tenant(), cutoff).await)
                            })
                        })
                        .await
                    })
                },
            )
            .await
            .fold(
                |v| v,
                |_| Err(Error::Storage),
                |_| Err(Error::Storage),
                |_| Err(Error::Unknown),
                |_| Err(Error::Unknown),
                |_| Err(Error::Storage),
            )
    }
    async fn qualify_on(
        &self,
        c: &mut PgConnection,
        tenant: TenantId,
        cutoff: Deadline,
    ) -> Result<(), Error> {
        lock_read(c, tenant).await?;
        let value=sqlx::query_scalar::<_,serde_json::Value>("SELECT pending FROM mdm_telemetry.storage_binding WHERE tenant_id=$1::uuid AND probe_ready AND qualified IS NULL")
            .bind(tenant.to_string()).fetch_optional(&mut *c).await?;
        let Some(value) = value else { return Ok(()) };
        let candidate: Selection = serde_json::from_value(value)?;
        let resource = self
            .resources
            .get(candidate.binding.as_slice())
            .ok_or(Error::Storage)?;
        if Some(resource.installation) != candidate.resource_id
            || resource.tenant.is_some_and(|t| t != tenant)
        {
            return Err(Error::Denied);
        }
        let access = match resource.backend.as_deref().ok_or(Error::Storage)? {
            crate::backend::Backend::Postgres(pg) => crate::backend::Access::Postgres(pg.clone()),
            crate::backend::Backend::ClickHouse(owner) => {
                crate::backend::Access::ClickHouse(Arc::new(
                    candidate
                        .reader(&self.protection, tenant)?
                        .ok_or(Error::Storage)?
                        .bind(owner, tenant, candidate.revision, cutoff)
                        .await?,
                ))
            }
        };
        crate::diagnostics::probe(&access, tenant, cutoff).await?;
        let op = candidate.operation_id.ok_or(Error::Storage)?;
        sqlx::query("UPDATE mdm_telemetry.storage_binding SET qualified=$2 WHERE tenant_id=$1::uuid AND pending->>'operation_id'=($2::uuid)::text AND probe_ready")
            .bind(tenant.to_string()).bind(op).execute(c).await?;
        Ok(())
    }
}
type Slot = tokio::sync::Mutex<Option<Arc<ChStore<SystemClock>>>>;
#[derive(Default)]
pub(crate) struct Readers(Mutex<HashMap<TenantId, Arc<Slot>>>);
impl Readers {
    pub(crate) async fn access(
        &self,
        owner: &ChOwner<SystemClock>,
        key: &Protector,
        tenant: TenantId,
        selection: &Selection,
        cutoff: Deadline,
    ) -> Result<Arc<ChStore<SystemClock>>, Error> {
        let slot = self
            .0
            .lock()
            .map_err(|_| Error::Storage)?
            .entry(tenant)
            .or_default()
            .clone();
        let mut active = slot.lock().await;
        if let Some(access) = active.as_ref()
            && i64::try_from(access.material_version().get()).ok() == Some(selection.revision)
        {
            return Ok(access.clone());
        }
        let deadline = cutoff.capped(&SystemClock, Duration::from_secs(6));
        if let Some(old) = active.as_ref() {
            old.retire(deadline).await?;
        }
        *active = None;
        let reader = selection.reader(key, tenant)?.ok_or(Error::Storage)?;
        let access = Arc::new(
            reader
                .bind(owner, tenant, selection.revision, deadline)
                .await?,
        );
        *active = Some(access.clone());
        Ok(access)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reader_credentials_are_bound_to_installation_tenant_and_revision() {
        let key = Protector::new(&[4; 32]).unwrap();
        let tenant = TenantId::parse(&Uuid::new_v4().to_string()).unwrap();
        let resource = Uuid::new_v4();
        let reader = Reader {
            user: "reader".into(),
            password: Some(Zeroizing::new("first".into())),
            cursor: Zeroizing::new([2; 32]),
        };
        let mut selection = Selection {
            binding: vec![1; 32],
            resource_id: Some(resource),
            revision: 3,
            operation_id: Some(Uuid::new_v4()),
            material: Some(reader.seal(&key, tenant, resource, 3).unwrap()),
        };
        assert_eq!(
            *selection.reader(&key, tenant).unwrap().unwrap().cursor,
            [2; 32]
        );
        assert!(
            selection
                .reader(&key, TenantId::parse(&Uuid::new_v4().to_string()).unwrap())
                .is_err()
        );
        selection.revision = 4;
        assert!(selection.reader(&key, tenant).is_err());
        selection.revision = 3;
        selection.resource_id = Some(Uuid::new_v4());
        assert!(selection.reader(&key, tenant).is_err());
    }
}
