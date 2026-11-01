//! One mutable asset owner per endpoint, independent of enrollment origin and quotas.
//! ref: sqlx v0.8.6 sqlx-core/src/transaction.rs (borrowed transaction).
use super::DeviceService;
use crate::operations::{Actor, Operation};
use crate::{Error, database::db};
use rss_mdm_audit_integration::{Fact, RequestAudit, budget::AuditBudget};
use rss_mdm_authorization_service::{User, context::AuthorizedPrincipal};
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, Row};
use uuid::Uuid;
#[derive(schemars::JsonSchema, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationUser {
    pub revision: u64,
    pub user: Option<User>,
}
#[derive(schemars::JsonSchema, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationUserChange {
    pub expected_revision: u64,
    #[serde(deserialize_with = "Option::deserialize")]
    pub user: Option<User>,
}
impl DeviceService {
    pub async fn registration_user(
        &self,
        p: &AuthorizedPrincipal,
        device: &str,
    ) -> Result<RegistrationUser, Error> {
        let profile = self.profile();

        if p.tenant_id() != self.tenant {
            return Err(Error::Forbidden);
        }
        p.enrollment(device)?;
        let mut tx = self.access.begin(p.tenant_id()).await?;
        target_on(profile, &mut tx, p, device).await?;
        read_on(profile, &mut tx, p.tenant_id(), device).await
    }
    pub async fn assign_registration_user(
        &self,
        p: &AuthorizedPrincipal,
        device: &str,
        change: &RegistrationUserChange,
        key: Uuid,
        audit: &RequestAudit,
    ) -> Result<RegistrationUser, Error> {
        let profile = self.profile();

        if p.tenant_id() != self.tenant {
            return Err(Error::Forbidden);
        }
        p.enrollment(device)?;
        rss_observation::Id::new(device).map_err(|_| Error::Malformed)?;
        if key.is_nil() || change.expected_revision >= i64::MAX as u64 {
            return Err(Error::Malformed);
        }
        if let Some(user) = &change.user {
            user.validate(p.tenant_id(), p.instance_id())
                .map_err(|_| Error::Malformed)?;
        }
        p.bind_audit(audit)?;
        audit.operation(
            key,
            "registration_user_change",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.target_device(device);
        let digest = crate::enrollment::digest(&(
            "registration_user.v1",
            device,
            change.expected_revision,
            &change.user,
        ));
        let op = Operation {
            actor: Actor::from_authorized(p),
            key,
            digest: &digest,
        };
        let budget = AuditBudget::new(std::time::Duration::from_secs(6));
        let result = self.audit_store.write(rss_request_context::TenantId::parse(p.tenant_id()).map_err(|_| Error::Malformed)?,
            &budget.source_control(),(&self.audit_store,p,device,change,&op,audit), |ctx,tx| Box::pin(async move {
            let (store,p,device,change,op,audit) = *ctx;
            let (value,replayed) = tx.with_connection_context(&mut (p,device,change,op,audit), |ctx,c| Box::pin(async move {
                let (p,device,change,op,audit) = *ctx;
                rss_mdm_authorization_service::lock_on(profile, c,p.tenant_id(),p.instance_id()).await?;
                rss_mdm_authorization_service::snapshot_on(profile, c,p.tenant_id(),p.instance_id()).await?.require(p,rss_mdm_authorization_service::Permission::Enrollment,Some(device)).map_err(rss_mdm_authorization_service::Error::from)?;
                lock_on(profile, c,p.tenant_id(),device).await?;
                target_on(profile, c,p,device).await?;
                if let Some(old) = crate::operations::replay(profile, c,op).await? {
                    return Ok::<_,Error>((serde_json::from_str(&old).map_err(|_| Error::Corrupt)?,true));
                }
                let current = read_on(profile, c,p.tenant_id(),device).await?;
                if current.revision != change.expected_revision { return Err(Error::Conflict); }
                let revision = current.revision+1;
                sqlx::query(crate::storage_profile::sql(profile).device_registration_user_assign_registration_user_1)
                    .bind(p.tenant_id()).bind(device).bind(revision as i64).bind(change.user.as_ref().map(|u| &u.instance_id)).bind(change.user.as_ref().map(|u| &u.principal_id)).execute(&mut *c).await.map_err(db)?;
                p.enrollment(device)?;
                let value = RegistrationUser { revision, user: change.user.clone() };
                crate::operations::save(profile, c,op,&serde_json::to_string(&value).map_err(|_| Error::Corrupt)?,audit).await?;
                Ok((value,false))
            })).await?;
            let fact = Fact::business(audit, &format!("registration-user:{}:{}",p.principal_id(),op.key), 200, "success", None)?;
            (if replayed { Ok(()) } else { store.append(tx, &fact).await }).map_err(Error::from)?;
            if replayed { audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed); }
            audit.mark_commit_started();
            Ok(value)
        })).await;
        crate::operations::settle(result, audit)
    }
}
async fn target_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    p: &AuthorizedPrincipal,
    device: &str,
) -> Result<(), Error> {
    if profile != p.profile() {
        return Err(crate::Error::Forbidden);
    }

    p.enrollment(device)?;
    let exists: bool = sqlx::query_scalar(
        crate::storage_profile::sql(profile).device_registration_user_target_on_1,
    )
    .bind(p.tenant_id())
    .bind(device)
    .fetch_one(c)
    .await
    .map_err(db)?;
    if exists { Ok(()) } else { Err(Error::NotFound) }
}
pub async fn read_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: &str,
    device: &str,
) -> Result<RegistrationUser, Error> {
    let row = sqlx::query(crate::storage_profile::sql(profile).device_registration_user_read_on_1)
        .bind(tenant)
        .bind(device)
        .fetch_optional(c)
        .await
        .map_err(db)?;
    if let Some(row) = row {
        let instance: Option<String> = row.try_get("instance").map_err(db)?;
        let principal: Option<String> = row.try_get("principal").map_err(db)?;
        let user = instance
            .zip(principal)
            .map(|(instance_id, principal_id)| User {
                tenant_id: tenant.into(),
                instance_id,
                principal_id,
            });
        Ok(RegistrationUser {
            revision: u64::try_from(row.try_get::<i64, _>("revision").map_err(db)?)
                .map_err(|_| Error::Corrupt)?,
            user,
        })
    } else {
        Ok(RegistrationUser {
            revision: 0,
            user: None,
        })
    }
}

/// Serialize all manual assignments and authenticated first-login initialization.
pub(crate) async fn lock_on(
    _profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: &str,
    device: &str,
) -> Result<(), Error> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2671))")
        .bind(format!("{tenant}:{device}"))
        .execute(c)
        .await
        .map_err(db)?;
    Ok(())
}
/// Caller owns the authenticated enrollment/login transaction and its success audit.
/// A cleared relation is eligible on the next new login, never on operation replay.
pub async fn initialize_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    device: &str,
    user: &User,
) -> Result<(), Error> {
    user.validate(&user.tenant_id, &user.instance_id)
        .map_err(|_| Error::Malformed)?;
    lock_on(profile, c, &user.tenant_id, device).await?;
    sqlx::query(crate::storage_profile::sql(profile).device_registration_user_initialize_on_1)
        .bind(&user.tenant_id)
        .bind(device)
        .bind(&user.instance_id)
        .bind(&user.principal_id)
        .execute(c)
        .await
        .map_err(db)?;
    Ok(())
}

/// Borrow the consumer's tenant transaction and already-authorized device batch.
pub async fn page_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: &str,
    devices: &[String],
) -> Result<std::collections::BTreeMap<String, RegistrationUser>, Error> {
    if devices.len() > 1000 {
        return Err(Error::Malformed);
    }
    let rows = sqlx::query(crate::storage_profile::sql(profile).device_registration_user_page_on_1)
        .bind(tenant)
        .bind(devices)
        .fetch_all(c)
        .await
        .map_err(db)?;
    let mut result = devices
        .iter()
        .map(|id| {
            (
                id.clone(),
                RegistrationUser {
                    revision: 0,
                    user: None,
                },
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    for row in rows {
        let instance: Option<String> = row.try_get("instance").map_err(db)?;
        let principal: Option<String> = row.try_get("principal").map_err(db)?;
        result.insert(
            row.try_get("device").map_err(db)?,
            RegistrationUser {
                revision: row
                    .try_get::<i64, _>("revision")
                    .map_err(db)?
                    .try_into()
                    .map_err(|_| Error::Corrupt)?,
                user: instance
                    .zip(principal)
                    .map(|(instance_id, principal_id)| User {
                        tenant_id: tenant.into(),
                        instance_id,
                        principal_id,
                    }),
            },
        );
    }
    Ok(result)
}
