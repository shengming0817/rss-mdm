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
    pub valid: bool,
    pub outcome: Option<rss_mdm_apple_mdm::native::outcome::Outcome>,
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
    let scope = crate::protocol::user(&crate::protocol::decode(bytes)?)?
        .map(|id| id.to_string())
        .unwrap_or_default();
    let row = sqlx::query("SELECT operation::text,phase,state,response_digest,request,context,(operation IS NULL OR ordinal=(SELECT max(b.ordinal) FROM mdm_apple.attempts b WHERE b.tenant_id=a.tenant_id AND b.operation=a.operation AND b.phase=a.phase)) AS latest FROM mdm_apple.attempts a WHERE tenant_id=$1::uuid AND id=$2::uuid AND registration=$3::uuid AND generation=$4 AND user_key=$6 AND CASE $5 WHEN 0 THEN collection IS NOT NULL WHEN 1 THEN operation IS NOT NULL ELSE certificate IS NOT NULL END FOR UPDATE")
        .bind(&tenant).bind(id.to_string()).bind(p.registration().to_string()).bind(p.generation()).bind(match owner { Owner::Collection=>0i32, Owner::Command=>1, Owner::Certificate=>2 }).bind(scope).fetch_optional(&mut *c).await.map_err(db)?;
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
    let response = crate::protocol::decode(bytes)?;
    let status = crate::protocol::management(&response)?.status;
    let phase: String = row.try_get("phase").map_err(db)?;
    let frozen: Option<serde_json::Value> = row.try_get("context").map_err(db)?;
    let context = if let Some(frozen) = frozen {
        Some(
            serde_json::from_value::<rss_mdm_apple_mdm::applicability::Context>(frozen)
                .map_err(|_| Error::Unavailable(crate::Failure::AppleStorage))?,
        )
    } else if phase == "resolve_device" && status == Status::Acknowledged {
        rss_mdm_apple_mdm::applicability::Context::from_reports(
            &response,
            None,
            rss_mdm_apple_mdm::applicability::Channel::Device,
        )
        .ok()
    } else if phase == "resolve_security" && status == Status::Acknowledged {
        let device=sqlx::query("SELECT id,response FROM mdm_apple.attempts WHERE tenant_id=$1::uuid AND operation=$2 AND phase='resolve_device' AND accepted AND state='acknowledged'").bind(&tenant).bind(operation).fetch_optional(&mut *c).await.map_err(db)?;
        if let Some(device) = device {
            let sealed: Vec<u8> = device.try_get("response").map_err(db)?;
            let plain = crate::protection::open(
                protection,
                &tenant,
                p.registration(),
                p.generation(),
                device.try_get("id").map_err(db)?,
                crate::protection::Part::Response,
                &sealed,
            )?;
            let device = crate::protocol::decode(plain.expose())?;
            rss_mdm_apple_mdm::applicability::Context::from_reports(
                &device,
                Some(&response),
                rss_mdm_apple_mdm::applicability::Channel::Device,
            )
            .ok()
        } else {
            None
        }
    } else {
        None
    };
    let (valid, outcome) = if let Some(context) = context {
        let sealed: Vec<u8> = row.try_get("request").map_err(db)?;
        let request = crate::protection::open(
            protection,
            &tenant,
            p.registration(),
            p.generation(),
            id,
            crate::protection::Part::Request,
            &sealed,
        )?;
        let request = crate::protocol::decode(request.expose())?;
        let body = request
            .get("Command")
            .and_then(plist::Value::as_dictionary)
            .ok_or(Error::Malformed)?;
        let name = crate::protocol::text(body, "RequestType")?;
        let mut fields = body.clone();
        fields.remove("RequestType");
        let command = rss_mdm_apple_mdm::native::input::CommandInput {
            request_type: name.into(),
            fields: rss_mdm_apple_mdm::native::input::Fields::from_plist(&fields)
                .map_err(|_| Error::Malformed)?,
        };
        let rights:i32=sqlx::query_scalar("SELECT access_rights FROM mdm_apple.devices WHERE tenant_id=$1::uuid AND registration=$2 AND state='active'").bind(&tenant).bind(p.registration()).fetch_one(&mut *c).await.map_err(db)?;
        let rights = crate::native::rights(rights);
        let target = rss_mdm_apple_mdm::native::Target {
            context: &context,
            access_rights: &rights,
        };
        match rss_mdm_apple_mdm::native::outcome::interpret(&command, &response, status, &target) {
            Ok(outcome) => (true, Some(outcome)),
            Err(_) => (false, None),
        }
    } else {
        (
            !phase.starts_with("resolve_") || status != Status::Acknowledged,
            None,
        )
    };
    Ok(Some(Reception::Ready(Attempt {
        latest: row.try_get("latest").map_err(db)?,
        valid,
        outcome,
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
        sqlx::query("UPDATE mdm_apple.attempts SET state=$3,response=$4,response_digest=$5,accepted=$6,native_outcome=$7,received_at=floor(extract(epoch FROM clock_timestamp()))::bigint,next_attempt=clock_timestamp()+interval '30 seconds' WHERE tenant_id=$1::uuid AND id=$2::uuid")
            .bind(self.tenant).bind(self.id.to_string()).bind(state).bind(self.bytes).bind(self.digest).bind(accepted).bind(if accepted { self.outcome.map(|value| serde_json::to_value(value).expect("closed outcome").as_str().expect("outcome string").to_owned()) } else { None }).execute(&mut *c).await.map_err(db)?;
        if status == Status::NotNow {
            crate::notify(c, "apple").await.map_err(db)?;
        }
        Ok(())
    }
}
