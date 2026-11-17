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
pub struct Selection {
    pub binding: Vec<u8>,
    pub resource_id: Option<Uuid>,
    pub revision: i64,
    pub operation_id: Option<Uuid>,
    pub material: Option<Vec<u8>>,
}

pub async fn load(c: &mut PgConnection, tenant: TenantId) -> Result<Option<Selection>, Error> {
    let row=sqlx::query("SELECT binding,resource_id,revision,operation_id,material FROM mdm_telemetry.storage_binding WHERE tenant_id=$1::uuid")
        .bind(tenant.to_string()).fetch_optional(c).await?;
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
    let Some(selection) = load(c, tenant).await? else {
        return Ok(0);
    };
    let Some(bytes) = selection.material else {
        return Ok(0);
    };
    if bytes.starts_with(&key.ciphertext_prefix()) {
        return Ok(0);
    }
    let aad = aad(
        tenant,
        selection.resource_id.ok_or(Error::Storage)?,
        selection.revision,
    )?;
    let wrapped = key.rewrap_bytes(&bytes, &aad).map_err(|_| Error::Storage)?;
    Ok(
        sqlx::query(
            "UPDATE mdm_telemetry.storage_binding SET material=$2 WHERE tenant_id=$1::uuid",
        )
        .bind(tenant.to_string())
        .bind(wrapped)
        .execute(c)
        .await?
        .rows_affected(),
    )
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
        let deadline = Deadline::from_timeout(&SystemClock, Duration::from_secs(6))
            .map_err(|_| Error::Storage)?;
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
