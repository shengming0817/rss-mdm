//! Self-service quotas. Organization enrollment and mutable responsibility are separate.
//! ref: PostgreSQL src/backend/utils/adt/lockfuncs.c@REL_17_6.
use crate::{Error, Store, database::db};
use rss_mdm_authorization_service::{Permission, User, context::AuthorizedPrincipal};
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, Row};
use std::sync::Arc;
pub mod management;
pub mod responsibility;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Channel {
    Agent,
    WindowsMdm,
    MacosMdm,
}
impl Channel {
    pub const ALL: [Self; 3] = [Self::Agent, Self::WindowsMdm, Self::MacosMdm];
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::WindowsMdm => "windows_mdm",
            Self::MacosMdm => "macos_mdm",
        }
    }
    pub fn source(source: rss_mdm_inventory::ReportSource) -> Self {
        use rss_mdm_inventory::ReportSource as S;
        match source {
            S::AgentBuiltin => Self::Agent,
            S::MdmWindows => Self::WindowsMdm,
            S::MdmApple => Self::MacosMdm,
        }
    }
}
/// Null means inheritance in a user override. Tenant defaults require all three values.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub agent: Option<u32>,
    pub windows_mdm: Option<u32>,
    pub macos_mdm: Option<u32>,
}
impl Limits {
    pub fn defaults() -> Self {
        Self {
            agent: Some(20),
            windows_mdm: Some(20),
            macos_mdm: Some(20),
        }
    }
    fn get(&self, channel: Channel) -> Option<u32> {
        match channel {
            Channel::Agent => self.agent,
            Channel::WindowsMdm => self.windows_mdm,
            Channel::MacosMdm => self.macos_mdm,
        }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Configuration {
    pub revision: u64,
    pub limits: Limits,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Change {
    pub expected_revision: u64,
    pub limits: Limits,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Usage {
    pub tenant_id: String,
    pub instance_id: String,
    pub principal_id: String,
    pub channels: Vec<ChannelUsage>,
    pub as_of: i64,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelUsage {
    pub channel: Channel,
    pub limit: u32,
    pub active: u64,
    pub reserved: u64,
    pub used: u64,
    pub over_limit: u64,
}
pub struct Quotas {
    store: Arc<Store>,
    audit: Arc<rss_mdm_audit_integration::AuditStore>,
}
impl Quotas {
    pub fn new(store: Arc<Store>, audit: Arc<rss_mdm_audit_integration::AuditStore>) -> Self {
        Self { store, audit }
    }
    pub async fn configuration(
        &self,
        p: &AuthorizedPrincipal,
        user: Option<&User>,
    ) -> Result<Configuration, Error> {
        p.manage(Permission::AuthorizationRead)?;
        let subject = subject(p, user)?;
        let mut tx = self.store.begin(p.tenant_id()).await?;
        configuration_on(&mut tx, p.tenant_id(), &subject).await
    }
    pub async fn usage(
        &self,
        p: &AuthorizedPrincipal,
        user: Option<&User>,
    ) -> Result<Usage, Error> {
        p.check_live()?;
        if user.is_some() {
            p.manage(Permission::AuthorizationRead)?;
        }
        let owned = p.user()?;
        let user = user.unwrap_or(&owned);
        user.validate(p.tenant_id(), p.instance_id())
            .map_err(|_| Error::Malformed)?;
        let mut tx = self.store.begin(p.tenant_id()).await?;
        lock_on(&mut tx, p.tenant_id()).await?;
        let defaults = configuration_on(&mut tx, p.tenant_id(), "tenant").await?;
        let overrides = configuration_on(&mut tx, p.tenant_id(), &user_subject(user)).await?;
        let counts = counts_on(
            &mut tx,
            p.tenant_id(),
            &user.instance_id,
            &user.principal_id,
        )
        .await?;
        let channels = Channel::ALL
            .into_iter()
            .enumerate()
            .map(|(i, channel)| {
                let limit = overrides
                    .limits
                    .get(channel)
                    .or(defaults.limits.get(channel))
                    .unwrap_or(20);
                let (active, reserved) = counts[i];
                let used = active + reserved;
                ChannelUsage {
                    channel,
                    limit,
                    active,
                    reserved,
                    used,
                    over_limit: used.saturating_sub(u64::from(limit)),
                }
            })
            .collect();
        let as_of =
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                .fetch_one(&mut *tx)
                .await
                .map_err(db)?;
        tx.commit().await.map_err(db)?;
        Ok(Usage {
            tenant_id: user.tenant_id.clone(),
            instance_id: user.instance_id.clone(),
            principal_id: user.principal_id.clone(),
            channels,
            as_of,
        })
    }
}
fn subject(p: &AuthorizedPrincipal, user: Option<&User>) -> Result<String, Error> {
    if let Some(user) = user {
        user.validate(p.tenant_id(), p.instance_id())
            .map_err(|_| Error::Malformed)?;
        Ok(user_subject(user))
    } else {
        Ok("tenant".into())
    }
}
fn user_subject(user: &User) -> String {
    format!("user:{}:{}", user.instance_id, user.principal_id)
}
/// Acquired after Audit/authorization admission, before registration business locks.
/// Reads never acquire Audit while holding this lock.
pub(crate) async fn lock_on(c: &mut PgConnection, tenant: &str) -> Result<(), Error> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2670))")
        .bind(tenant)
        .execute(c)
        .await
        .map_err(db)?;
    Ok(())
}
async fn configuration_on(
    c: &mut PgConnection,
    tenant: &str,
    subject: &str,
) -> Result<Configuration, Error> {
    let row = sqlx::query("SELECT revision,agent,windows_mdm,macos_mdm FROM mdm_access.registration_quota_settings WHERE tenant_id=$1::uuid AND subject=$2")
        .bind(tenant).bind(subject).fetch_optional(c).await.map_err(db)?;
    if let Some(row) = row {
        let field = |name| -> Result<Option<u32>, Error> {
            row.try_get::<Option<i64>, _>(name)
                .map_err(db)?
                .map(|v| u32::try_from(v).map_err(|_| Error::Corrupt))
                .transpose()
        };
        Ok(Configuration {
            revision: u64::try_from(row.try_get::<i64, _>("revision").map_err(db)?)
                .map_err(|_| Error::Corrupt)?,
            limits: Limits {
                agent: field("agent")?,
                windows_mdm: field("windows_mdm")?,
                macos_mdm: field("macos_mdm")?,
            },
        })
    } else {
        Ok(Configuration {
            revision: 0,
            limits: if subject == "tenant" {
                Limits::defaults()
            } else {
                Limits::default()
            },
        })
    }
}
async fn counts_on(
    c: &mut PgConnection,
    tenant: &str,
    instance: &str,
    actor: &str,
) -> Result<[(u64, u64); 3], Error> {
    let rows = sqlx::query(include_str!("../schema/quota-usage.sql"))
        .bind(tenant)
        .bind(instance)
        .bind(actor)
        .fetch_all(c)
        .await
        .map_err(db)?;
    let mut counts = [(0, 0); 3];
    for row in rows {
        let channel: String = row.try_get("channel").map_err(db)?;
        let i = Channel::ALL
            .iter()
            .position(|c| c.as_str() == channel)
            .ok_or(Error::Corrupt)?;
        counts[i] = (
            u64::try_from(row.try_get::<i64, _>("active").map_err(db)?)
                .map_err(|_| Error::Corrupt)?,
            u64::try_from(row.try_get::<i64, _>("reserved").map_err(db)?)
                .map_err(|_| Error::Corrupt)?,
        );
    }
    Ok(counts)
}
/// Freeze admission in the existing grant/request transaction. Activation does not re-admit.
pub(crate) async fn admit_on(
    c: &mut PgConnection,
    tenant: &str,
    instance: &str,
    actor: &str,
    channel: Channel,
) -> Result<(), Error> {
    lock_on(c, tenant).await?;
    let subject = format!("user:{instance}:{actor}");
    let default = configuration_on(c, tenant, "tenant").await?.limits;
    let override_ = configuration_on(c, tenant, &subject).await?.limits;
    let limit = override_
        .get(channel)
        .or(default.get(channel))
        .unwrap_or(20);
    let counts = counts_on(c, tenant, instance, actor).await?;
    let i = Channel::ALL
        .iter()
        .position(|v| *v == channel)
        .ok_or(Error::Corrupt)?;
    if counts[i].0 + counts[i].1 >= u64::from(limit) {
        Err(Error::RegistrationLimit)
    } else {
        Ok(())
    }
}
