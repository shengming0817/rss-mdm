//! Current, secret-free control-plane projections; write receipts remain immutable.
use super::*;
use crate::identity::Principal;
use crate::{AccessStore, access::EnrollmentPermission, access_store::db};
use sqlx::Row;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Status {
    enrollment_id: Uuid,
    status: String,
    expires_at: i64,
    registration_id: Option<String>,
    channel: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Page {
    pub after: Option<Uuid>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Registration {
    registration_id: Uuid,
    enrollment_id: Uuid,
    channel: String,
    generation: i64,
    status: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Registrations {
    items: Vec<Registration>,
    next_cursor: Option<Uuid>,
}
impl AccessStore {
    pub(crate) async fn enrollment_status(
        &self,
        permission: EnrollmentPermission<'_>,
        id: Uuid,
    ) -> Result<Status, Error> {
        let mut tx = self.begin(permission.proof().tenant_id()).await?;
        let row = sqlx::query("SELECT q.state,q.channel,floor(extract(epoch FROM q.expires_at))::bigint AS expires_at,r.id::text AS registration FROM mdm_access.requests q JOIN mdm_access.grants g ON (g.tenant_id,g.id)=(q.tenant_id,q.grant_id) LEFT JOIN mdm_access.registrations r ON (r.tenant_id,r.request_id)=(q.tenant_id,q.id) WHERE q.tenant_id=$1::uuid AND q.id=$2::uuid AND g.device=$3 AND q.issuance_operation IS NOT NULL")
            .bind(permission.proof().tenant_id()).bind(id.to_string()).bind(permission.device()).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(Error::Forbidden)?;
        Ok(Status {
            enrollment_id: id,
            status: row.try_get("state").map_err(db)?,
            expires_at: row.try_get("expires_at").map_err(db)?,
            registration_id: row.try_get("registration").map_err(db)?,
            channel: row.try_get("channel").map_err(db)?,
        })
    }
    pub(crate) async fn registration_list(
        &self,
        proof: &Principal,
        device: &str,
        page: Page,
    ) -> Result<Registrations, Error> {
        rss_observation::Id::new(device).map_err(|_| Error::Malformed)?;
        proof.credentials(device)?;
        let mut tx = self.begin(proof.tenant_id()).await?;
        let rows = sqlx::query("SELECT id::text,request_id::text,channel,generation,state FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND device=$2 AND ($3::uuid IS NULL OR id>$3::uuid) ORDER BY id LIMIT 101")
            .bind(proof.tenant_id()).bind(device).bind(page.after.map(|v|v.to_string())).fetch_all(&mut *tx).await.map_err(db)?;
        let more = rows.len() > 100;
        let items = rows
            .into_iter()
            .take(100)
            .map(|row| {
                Ok(Registration {
                    registration_id: store::uuid(&row, "id")?,
                    enrollment_id: store::uuid(&row, "request_id")?,
                    channel: row.try_get("channel").map_err(db)?,
                    generation: row.try_get("generation").map_err(db)?,
                    status: row.try_get("state").map_err(db)?,
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let next_cursor = more.then(|| items.last().expect("full page").registration_id);
        Ok(Registrations { items, next_cursor })
    }
}
