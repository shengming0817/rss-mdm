//! Collection-owned prerequisite attempts; no synthetic OS version or enrollment authority.
use crate::{Error, database::db};
use rss_mdm_apple_mdm::{
    applicability::{Channel, Context},
    protocol,
};
use sqlx::{PgConnection, Row};
use uuid::Uuid;

pub(crate) fn retained(phase: &str, response: &plist::Dictionary) -> Result<Vec<u8>, Error> {
    let mut safe = plist::Dictionary::new();
    for key in ["Status", "UDID", "CommandUUID", "UserID"] {
        if let Some(value) = response.get(key) {
            safe.insert(key.into(), value.clone());
        }
    }
    let (root, keys): (_, &[_]) = if phase == "collect_device" {
        (
            "QueryResponses",
            &["OSVersion", "IsSupervised", "IsAppleSilicon"],
        )
    } else {
        ("SecurityInfo", &["ManagementStatus"])
    };
    if let Some(body) = response.get(root).and_then(plist::Value::as_dictionary) {
        let mut facts = plist::Dictionary::new();
        for key in keys {
            if let Some(value) = body.get(*key) {
                if *key == "ManagementStatus" {
                    if let Some(management) = value.as_dictionary() {
                        let mut filtered = plist::Dictionary::new();
                        for name in [
                            "IsUserEnrollment",
                            "EnrolledViaDEP",
                            "UserApprovedEnrollment",
                        ] {
                            if let Some(value) =
                                management.get(name).and_then(plist::Value::as_boolean)
                            {
                                filtered.insert(name.into(), value.into());
                            }
                        }
                        facts.insert((*key).into(), filtered.into());
                    }
                } else if matches!(value, plist::Value::String(_) | plist::Value::Boolean(_)) {
                    facts.insert((*key).into(), value.clone());
                }
            }
        }
        safe.insert(root.into(), facts.into());
    }
    Ok(protocol::xml(safe)?)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn prepare(
    c: &mut PgConnection,
    protection: &rss_mdm_native_protection::Protector,
    tenant: &str,
    collection: Uuid,
    registration: Uuid,
    generation: i64,
    sequence: i64,
    deadline: &str,
    user: &str,
) -> Result<Option<Context>, Error> {
    let mut device = None;
    let mut security = None;
    for (phase, command) in [
        (
            "collect_device",
            protocol::dictionary([
                ("RequestType", "DeviceInformation".into()),
                (
                    "Queries",
                    plist::Value::Array(vec![
                        "OSVersion".into(),
                        "IsSupervised".into(),
                        "IsAppleSilicon".into(),
                    ]),
                ),
            ]),
        ),
        (
            "collect_security",
            protocol::dictionary([("RequestType", "SecurityInfo".into())]),
        ),
    ] {
        let row = sqlx::query("SELECT id,state,accepted,response FROM mdm_apple.attempts WHERE tenant_id=$1::uuid AND collection=$2 AND phase=$3")
            .bind(tenant).bind(collection).bind(phase).fetch_optional(&mut *c).await.map_err(db)?;
        if let Some(row) = row {
            if row.try_get::<String, _>("state").map_err(db)? != "acknowledged"
                || !row.try_get::<bool, _>("accepted").map_err(db)?
            {
                return Ok(None);
            }
            let sealed: Vec<u8> = row.try_get("response").map_err(db)?;
            let plain = crate::protection::open(
                protection,
                tenant,
                registration,
                generation,
                row.try_get("id").map_err(db)?,
                crate::protection::Part::Response,
                &sealed,
            )?;
            let body = protocol::decode(plain.expose())?;
            if phase == "collect_device" {
                device = Some(body);
            } else {
                security = Some(body);
            }
        } else {
            let id = Uuid::new_v4();
            let bytes = protocol::command(id, command)?;
            let request = crate::protection::seal(
                protection,
                tenant,
                registration,
                generation,
                id,
                crate::protection::Part::Request,
                &bytes,
            )?;
            sqlx::query("INSERT INTO mdm_apple.attempts(tenant_id,id,registration,generation,collection,phase,request,state,collection_sequence,deadline) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,'pending',$8,$9::text::timestamptz)")
                .bind(tenant).bind(id).bind(registration).bind(generation).bind(collection).bind(phase).bind(request).bind(sequence).bind(deadline).execute(&mut *c).await.map_err(db)?;
            crate::notify(c, "apple").await.map_err(db)?;
            return Ok(None);
        }
    }
    Ok(Some(Context::from_reports(
        &device.ok_or(Error::Malformed)?,
        security.as_ref(),
        if user.is_empty() {
            Channel::Device
        } else {
            Channel::User
        },
    )?))
}

pub(crate) async fn security_valid(
    c: &mut PgConnection,
    protection: &rss_mdm_native_protection::Protector,
    p: &crate::device::DevicePrincipal,
    collection: Uuid,
    response: &plist::Dictionary,
) -> Result<bool, Error> {
    let Some(management) = response
        .get("SecurityInfo")
        .and_then(plist::Value::as_dictionary)
        .and_then(|d| d.get("ManagementStatus"))
        .and_then(plist::Value::as_dictionary)
    else {
        return Ok(false);
    };
    if management
        .get("IsUserEnrollment")
        .and_then(plist::Value::as_boolean)
        .is_none()
    {
        return Ok(false);
    }
    let tenant = p.tenant().to_string();
    let row=sqlx::query("SELECT id,response FROM mdm_apple.attempts WHERE tenant_id=$1::uuid AND collection=$2 AND phase='collect_device' AND accepted AND state='acknowledged'")
        .bind(&tenant).bind(collection).fetch_one(&mut *c).await.map_err(db)?;
    let sealed: Vec<u8> = row.try_get("response").map_err(db)?;
    let plain = crate::protection::open(
        protection,
        &tenant,
        p.registration(),
        p.generation(),
        row.try_get("id").map_err(db)?,
        crate::protection::Part::Response,
        &sealed,
    )?;
    let device = protocol::decode(plain.expose())?;
    let Ok(context) = Context::from_reports(&device, Some(response), Channel::Device) else {
        return Ok(false);
    };
    let mask: i32 = sqlx::query_scalar(
        "SELECT access_rights FROM mdm_apple.devices WHERE tenant_id=$1::uuid AND registration=$2",
    )
    .bind(&tenant)
    .bind(p.registration())
    .fetch_one(c)
    .await
    .map_err(db)?;
    let rights = crate::native::rights(mask);
    let target = rss_mdm_apple_mdm::native::Target {
        context: &context,
        access_rights: &rights,
    };
    let input = rss_mdm_apple_mdm::native::input::CommandInput {
        request_type: "SecurityInfo".into(),
        fields: Default::default(),
    };
    Ok(rss_mdm_apple_mdm::native::outcome::interpret(
        &input,
        response,
        protocol::Status::Acknowledged,
        &target,
    )
    .is_ok())
}
