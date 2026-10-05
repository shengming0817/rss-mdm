//! Mandatory organization authority, consumed by the existing native registration transaction.
use super::*;
use rss_mdm_registration_service::Error as RegistrationError;
use rss_mdm_registration_service::enrollment::native::{Coordinates, OrganizationAuthority};
type Pending<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), RegistrationError>> + Send + 'a>>;
struct Authority;
pub(crate) fn authority() -> Arc<dyn OrganizationAuthority> {
    Arc::new(Authority)
}
impl OrganizationAuthority for Authority {
    fn authorize_issue<'a>(
        &'a self,
        c: &'a mut sqlx::PgConnection,
        tenant: &'a str,
        organization: Uuid,
        profile: Uuid,
        machine: &'a rss_mdm_certificate::apple::ade::MachineInfo,
    ) -> Pending<'a> {
        Box::pin(async move {
            issue_row(c, tenant, organization, profile, machine.serial())
                .await
                .map(|_| ())
                .map_err(|_| RegistrationError::Unauthorized)
        })
    }
    fn current<'a>(&'a self, c: &'a mut sqlx::PgConnection, data: &'a Coordinates) -> Pending<'a> {
        Box::pin(async move {
            require_in(c, &data.tenant, data.id)
                .await
                .map_err(|_| RegistrationError::Unauthorized)
        })
    }
}
pub(super) async fn issue_row(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    organization: Uuid,
    profile: Uuid,
    serial: &str,
) -> Result<sqlx::postgres::PgRow, Error> {
    sqlx::query("SELECT s.revision AS server_revision,d.assignment_revision,p.revision AS profile_revision,p.configuration FROM mdm_apple.ade_servers s JOIN mdm_apple.ade_devices d ON(d.tenant_id,d.organization)=(s.tenant_id,s.organization) JOIN mdm_apple.ade_profiles p ON(p.tenant_id,p.organization,p.remote_uuid)=(d.tenant_id,d.organization,d.remote_profile) WHERE s.tenant_id=$1::uuid AND s.organization=$2 AND d.serial=$3 AND p.id=$4 AND s.enabled AND s.verified AND NOT s.token_invalid AND s.token_expires>floor(extract(epoch FROM clock_timestamp()))::bigint AND s.synced_at IS NOT NULL AND s.synced_at>floor(extract(epoch FROM clock_timestamp()))::bigint-604800 AND NOT d.deleted AND NOT EXISTS(SELECT 1 FROM mdm_apple.ade_operations o WHERE o.tenant_id=s.tenant_id AND o.organization=s.organization AND o.kind IN('assign','clear') AND o.state IN('pending','running','unknown') AND o.request->'devices' ? d.serial) FOR SHARE OF s,d,p")
        .bind(tenant).bind(organization).bind(serial).bind(profile).fetch_optional(c).await.map_err(db)?.ok_or(Error::Unauthorized)
}
pub(crate) async fn require_in(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    enrollment: Uuid,
) -> Result<(), Error> {
    let row=sqlx::query("SELECT organization,serial,profile_id,server_revision,assignment_revision,profile_revision FROM mdm_apple.ade_enrollments WHERE tenant_id=$1::uuid AND enrollment=$2 AND NOT revoked FOR SHARE").bind(tenant).bind(enrollment).fetch_optional(&mut *c).await.map_err(db)?.ok_or(Error::Unauthorized)?;
    let current = issue_row(
        c,
        tenant,
        row.try_get("organization").map_err(db)?,
        row.try_get("profile_id").map_err(db)?,
        &row.try_get::<String, _>("serial").map_err(db)?,
    )
    .await?;
    for name in ["server_revision", "assignment_revision", "profile_revision"] {
        if row.try_get::<i64, _>(name).map_err(db)?
            != current.try_get::<i64, _>(name).map_err(db)?
        {
            return Err(Error::Unauthorized);
        }
    }
    Ok(())
}
pub(crate) async fn udid_in(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    enrollment: Uuid,
    udid: &str,
) -> Result<(), Error> {
    let same:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_apple.ade_enrollments WHERE tenant_id=$1::uuid AND enrollment=$2 AND udid=$3 AND NOT revoked)").bind(tenant).bind(enrollment).bind(udid).fetch_one(c).await.map_err(db)?;
    if !same {
        return Err(Error::Unauthorized);
    }
    Ok(())
}
