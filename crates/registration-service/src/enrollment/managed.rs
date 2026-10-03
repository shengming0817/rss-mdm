//! A native install authorizes one independent Agent enrollment in the caller's transaction.
use crate::{Error, database::db, device::DevicePrincipal};
use rss_mdm_authorization_service::{Permission, UserGrant};
use rss_mdm_inventory::ReportSource;
use sqlx::PgConnection;
use uuid::Uuid;
/// Sealed enrollment admission. Only live native source and actual Enrollment grants construct it.
pub struct Authority {
    principal: DevicePrincipal,
    installation: Uuid,
    deadline: i64,
    user: rss_mdm_authorization_service::User,
}
impl Authority {
    pub fn deadline(&self) -> i64 {
        self.deadline
    }
    pub fn user(&self) -> &rss_mdm_authorization_service::User {
        &self.user
    }
    pub fn principal(&self) -> &DevicePrincipal {
        &self.principal
    }
    pub fn installation(&self) -> Uuid {
        self.installation
    }
}
pub async fn authorize_on(
    c: &mut PgConnection,
    p: &DevicePrincipal,
    source: ReportSource,
    installation: Uuid,
    deadline: i64,
    grant: &UserGrant,
) -> Result<Authority, Error> {
    if source == ReportSource::AgentBuiltin || installation.is_nil() {
        return Err(Error::Forbidden);
    }
    crate::device::store::revalidate_source(c, p, source).await?;
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&mut *c)
            .await
            .map_err(db)?;
    if now >= deadline || !grant.valid(c, Permission::Enrollment, now).await? {
        return Err(Error::Forbidden);
    }
    Ok(Authority {
        principal: p.clone(),
        installation,
        deadline,
        user: grant.user().clone(),
    })
}
