//! One owner for authenticated native response replay and durable transitions.
use super::protocol::Status;
use crate::{Error, database::db, device::DevicePrincipal};
use sqlx::{PgConnection, Row};
use uuid::Uuid;

pub enum Owner {
    Collection,
    Command,
    Certificate,
}
pub enum Reception {
    Replay,
    Ready(Attempt),
}
pub struct Attempt {
    pub latest: bool,
    tenant: String,
    id: Uuid,
    bytes: Vec<u8>,
    digest: Vec<u8>,
    pub operation: Option<Uuid>,
    pub phase: String,
}
pub async fn lock(
    c: &mut PgConnection,
    protection: &rss_mdm_native_protection::Protector,
    p: &DevicePrincipal,
    id: Uuid,
    owner: Owner,
    bytes: &[u8],
) -> Result<Option<Reception>, Error> {
    let tenant = p.tenant().to_string();
    let row = sqlx::query("SELECT operation::text,phase,state,response_digest,(operation IS NULL OR ordinal=(SELECT max(b.ordinal) FROM mdm_apple.attempts b WHERE b.tenant_id=a.tenant_id AND b.operation=a.operation AND b.phase=a.phase)) AS latest FROM mdm_apple.attempts a WHERE tenant_id=$1::uuid AND id=$2::uuid AND registration=$3::uuid AND generation=$4 AND CASE $5 WHEN 0 THEN collection IS NOT NULL WHEN 1 THEN operation IS NOT NULL ELSE certificate IS NOT NULL END FOR UPDATE")
        .bind(&tenant).bind(id.to_string()).bind(p.registration().to_string()).bind(p.generation()).bind(match owner { Owner::Collection=>0i32, Owner::Command=>1, Owner::Certificate=>2 }).fetch_optional(c).await.map_err(db)?;
    let Some(row) = row else { return Ok(None) };
    let state: String = row.try_get("state").map_err(db)?;
    let digest = protection
        .mac(
            bytes,
            &crate::protection::aad(
                &tenant,
                p.registration(),
                p.generation(),
                id,
                crate::protection::Part::Replay,
            )?,
        )
        .map_err(|_| Error::Unavailable(crate::Failure::AppleStorage))?
        .to_vec();
    if matches!(state.as_str(), "acknowledged" | "error") {
        return if row
            .try_get::<Option<Vec<u8>>, _>("response_digest")
            .map_err(db)?
            == Some(digest)
        {
            Ok(Some(Reception::Replay))
        } else {
            Err(Error::Conflict)
        };
    }
    if !matches!(state.as_str(), "sent" | "not_now") {
        return Err(Error::Conflict);
    }
    let operation = row
        .try_get::<Option<String>, _>("operation")
        .map_err(db)?
        .map(|id| {
            Uuid::parse_str(&id).map_err(|_| Error::Unavailable(crate::Failure::AppleStorage))
        })
        .transpose()?;
    Ok(Some(Reception::Ready(Attempt {
        latest: row.try_get("latest").map_err(db)?,
        tenant: tenant.clone(),
        id,
        bytes: crate::protection::seal(
            protection,
            &tenant,
            p.registration(),
            p.generation(),
            id,
            crate::protection::Part::Response,
            bytes,
        )?,
        digest,
        operation,
        phase: row.try_get("phase").map_err(db)?,
    })))
}
impl Attempt {
    /// Persist authenticated evidence and its eligibility under the same transaction.
    pub async fn settle(
        self,
        c: &mut PgConnection,
        status: Status,
        accepted: bool,
    ) -> Result<(), Error> {
        let state = match status {
            Status::Acknowledged => "acknowledged",
            Status::Error => "error",
            Status::NotNow => "not_now",
            Status::Idle => return Err(Error::Malformed),
        };
        sqlx::query("UPDATE mdm_apple.attempts SET state=$3,response=$4,response_digest=$5,accepted=$6,received_at=floor(extract(epoch FROM clock_timestamp()))::bigint,next_attempt=clock_timestamp()+interval '30 seconds' WHERE tenant_id=$1::uuid AND id=$2::uuid")
            .bind(self.tenant).bind(self.id.to_string()).bind(state).bind(self.bytes).bind(self.digest).bind(accepted).execute(&mut *c).await.map_err(db)?;
        if status == Status::NotNow {
            crate::notify(c, "apple").await.map_err(db)?;
        }
        Ok(())
    }
}
