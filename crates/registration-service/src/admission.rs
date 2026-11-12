//! Tenant registration admission. It never changes active device authority.
//! ref: PostgreSQL src/backend/utils/adt/lockfuncs.c@REL_17_6.
use crate::{Error, Store, database::db, quotas::Channel};
use rss_mdm_audit_integration::{Fact, RequestAudit, budget::AuditBudget};
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, Row};
use std::sync::Arc;
use uuid::Uuid;

#[derive(schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Allowed,
    Paused,
}
#[derive(schemars::JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Setting {
    pub channel: Channel,
    pub revision: u64,
    pub admission: State,
}
#[derive(schemars::JsonSchema, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Change {
    pub expected_revision: u64,
    pub admission: State,
}

/// Capacity reservation remains serialized by the quota owner. Admission settings
/// have a separate reader/writer fence so first authentication reserves no quota.
pub async fn lock_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: &str,
) -> Result<(), Error> {
    crate::quotas::lock_on(profile, c, tenant).await
}
async fn fence(
    _profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: &str,
    channel: Channel,
    writer: bool,
) -> Result<(), Error> {
    let query = if writer {
        "SELECT pg_advisory_xact_lock(hashtextextended($1,3032))"
    } else {
        "SELECT pg_advisory_xact_lock_shared(hashtextextended($1,3032))"
    };
    sqlx::query(query)
        .bind(format!("{tenant}:{}", channel.as_str()))
        .execute(c)
        .await
        .map_err(db)?;
    Ok(())
}
pub async fn read_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: &str,
    channel: Channel,
) -> Result<Setting, Error> {
    let row = sqlx::query(crate::storage_profile::sql(profile).admission_read_in_1)
        .bind(tenant)
        .bind(channel.as_str())
        .fetch_optional(c)
        .await
        .map_err(db)?;
    let (revision, paused) = match row {
        None => (0, false),
        Some(r) => (
            u64::try_from(r.try_get::<i64, _>("revision").map_err(db)?)
                .map_err(|_| Error::Corrupt)?,
            r.try_get("paused").map_err(db)?,
        ),
    };
    Ok(Setting {
        channel,
        revision,
        admission: if paused {
            State::Paused
        } else {
            State::Allowed
        },
    })
}
pub async fn require_new_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: &str,
    channel: Channel,
) -> Result<(), Error> {
    lock_in(profile, c, tenant).await?;
    fence(profile, c, tenant, channel, false).await?;
    if read_in(profile, c, tenant, channel).await?.admission == State::Paused {
        return Err(Error::EnrollmentPaused);
    }
    Ok(())
}
/// A bound Apple request is created at Authenticate; Windows binds at signing,
/// so Windows additionally needs the first authenticated management transaction.
pub async fn require_request_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: &str,
    request: Uuid,
    channel: Channel,
) -> Result<(), Error> {
    lock_in(profile, c, tenant).await?;
    let established: bool =
        sqlx::query_scalar(crate::storage_profile::sql(profile).admission_require_request_in_1)
            .bind(tenant)
            .bind(request)
            .fetch_one(&mut *c)
            .await
            .map_err(db)?;
    if !established {
        require_new_in(profile, c, tenant, channel).await?;
    }
    Ok(())
}

pub struct Admission {
    store: Arc<Store>,
    audit: Arc<rss_mdm_audit_integration::AuditStore>,
}
impl Admission {
    pub fn profile(&self) -> rss_mdm_install_support::StorageProfile {
        self.store.profile()
    }
    pub fn new(store: Arc<Store>, audit: Arc<rss_mdm_audit_integration::AuditStore>) -> Self {
        Self { store, audit }
    }
    pub async fn read(&self, p: &AuthorizedPrincipal) -> Result<Vec<Setting>, Error> {
        let profile = self.profile();

        p.check_live()?;
        let mut tx = self.store.snapshot(p.tenant_id()).await?;
        let mut values = Vec::new();
        for channel in Channel::ALL {
            values.push(read_in(profile, &mut tx, p.tenant_id(), channel).await?);
        }
        tx.commit().await.map_err(db)?;
        Ok(values)
    }
    pub async fn change(
        &self,
        p: &AuthorizedPrincipal,
        channel: Channel,
        change: &Change,
        key: Uuid,
        audit: &RequestAudit,
    ) -> Result<Setting, Error> {
        let profile = self.profile();

        use crate::operations::{Actor, Operation};
        p.manage(Permission::RegistrationConfigurationWrite)?;
        if key.is_nil() || change.expected_revision >= i64::MAX as u64 {
            return Err(Error::Malformed);
        }
        p.bind_audit(audit)?;
        audit.owned_operation(
            rss_mdm_audit_integration::operation::OperationOwner::Registration,
            key,
            "registration_admission_change",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        let digest = crate::enrollment::digest(&(
            "registration.admission.v1",
            channel,
            change.expected_revision,
            change.admission,
        ));
        let op = Operation {
            actor: Actor::from_authorized(p),
            key,
            digest: &digest,
        };
        let budget = AuditBudget::new(std::time::Duration::from_secs(6));
        let result = self
            .audit
            .write(
                rss_request_context::TenantId::parse(p.tenant_id())
                    .map_err(|_| Error::Malformed)?,
                &budget.source_control(),
                (&self.audit, p, channel, change, &op, audit),
                |ctx, tx| {
                    Box::pin(async move {
                        let (store, p, channel, change, op, audit) = *ctx;
                        let (revision, replayed) = tx
                            .with_connection_context(
                                &mut (p, channel, change, op, audit),
                                |ctx, c| {
                                    Box::pin(async move {
                                        let (p, channel, change, op, audit) = *ctx;
                                        lock_in(profile, c, p.tenant_id()).await?;
                                        fence(profile, c, p.tenant_id(), channel, true).await?;
                                        if let Some(old) =
                                            crate::operations::replay(profile, c, op).await?
                                        {
                                            return Ok::<_, Error>((
                                                serde_json::from_str::<u64>(&old)
                                                    .map_err(|_| Error::Corrupt)?,
                                                true,
                                            ));
                                        }
                                        let current =
                                            read_in(profile, c, p.tenant_id(), channel).await?;
                                        if current.revision != change.expected_revision {
                                            return Err(Error::Conflict);
                                        }
                                        let revision = current.revision + 1;
                                        sqlx::query(
                                            crate::storage_profile::sql(profile).admission_change_1,
                                        )
                                        .bind(p.tenant_id())
                                        .bind(channel.as_str())
                                        .bind(revision as i64)
                                        .bind(change.admission == State::Paused)
                                        .execute(&mut *c)
                                        .await
                                        .map_err(db)?;
                                        p.manage(Permission::RegistrationConfigurationWrite)?;
                                        crate::operations::save(
                                            profile,
                                            c,
                                            op,
                                            &revision.to_string(),
                                            audit,
                                            false,
                                        )
                                        .await?;
                                        Ok((revision, false))
                                    })
                                },
                            )
                            .await?;
                        let fact = Fact::business(
                            audit,
                            rss_mdm_audit_integration::operation::OperationOwner::Registration,
                            &format!("registration-admission:{}:{}", p.principal_id(), op.key),
                            200,
                            "success",
                            None,
                        )?;
                        (if replayed {
                            Ok(())
                        } else {
                            store.append(tx, &fact).await
                        })
                        .map_err(Error::from)?;
                        if replayed {
                            audit.management_result(
                                rss_mdm_audit_integration::ManagementResult::Replayed,
                            );
                        }
                        audit.mark_commit_started();
                        Ok(Setting {
                            channel,
                            revision,
                            admission: change.admission,
                        })
                    })
                },
            )
            .await;
        crate::operations::settle(result, audit)
    }
}

/// First Windows management admission uses durable authentication, not certificate issuance.
pub async fn require_windows_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    p: &crate::DevicePrincipal,
) -> Result<(), Error> {
    if profile != p.profile() {
        return Err(crate::Error::Forbidden);
    }

    let tenant = p.tenant().to_string();
    // The active principal is checked under the actual endpoint/channel fence.
    crate::device::store::revalidate_management(profile, c, p).await?;
    let authenticated: bool =
        sqlx::query_scalar(crate::storage_profile::sql(profile).admission_require_windows_in_1)
            .bind(&tenant)
            .bind(p.device().into_uuid())
            .fetch_optional(&mut *c)
            .await
            .map_err(db)?
            .ok_or(Error::Unauthorized)?;
    if !authenticated {
        fence(profile, c, &tenant, Channel::WindowsMdm, false).await?;
        if read_in(profile, c, &tenant, Channel::WindowsMdm)
            .await?
            .admission
            == State::Paused
        {
            return Err(Error::EnrollmentPaused);
        }
    }
    Ok(())
}
