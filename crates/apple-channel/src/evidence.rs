//! Protected native results are decoded and interpreted at their sole channel owner.
use crate::{Error, Failure, database::db, execution::channels::Observation, protocol};
use rss_mdm_apple_mdm::native::{
    evidence::{Phase, ReceiptState},
    input::Fields,
    request::Request,
};
use rss_mdm_native_protection::Protector;
use sqlx::{PgConnection, Row};
use uuid::Uuid;
fn typed<T: serde::de::DeserializeOwned>(value: String) -> Result<T, Error> {
    serde_json::from_value(serde_json::Value::String(value))
        .map_err(|_| Error::Unavailable(Failure::AppleStorage))
}
pub(crate) async fn observations(
    c: &mut PgConnection,
    key: &Protector,
    tenant: &str,
    operation: Uuid,
    request: &Request,
    native_values: bool,
) -> Result<Vec<Observation>, Error> {
    let profile = matches!(
        request,
        Request::InstallProfile { .. } | Request::RemoveProfile { .. }
    );
    let assessment = if profile {
        Some(crate::profiles::assessment(c, key, tenant, operation).await?)
    } else {
        None
    };
    let rows = sqlx::query("SELECT id,registration,generation,phase,state,response,received_at,accepted,native_outcome FROM mdm_apple.attempts WHERE tenant_id=$1::uuid AND operation=$2 ORDER BY ordinal,phase")
        .bind(tenant).bind(operation).fetch_all(c).await.map_err(db)?;
    rows.into_iter()
        .map(|r| {
            let phase: Phase = typed(r.try_get("phase").map_err(db)?)?;
            let state: ReceiptState = typed(r.try_get("state").map_err(db)?)?;
            let accepted: bool = r.try_get("accepted").map_err(db)?;
            let body = r
                .try_get::<Option<Vec<u8>>, _>("response")
                .map_err(db)?
                .map(|sealed| {
                    let plain = crate::protection::open(
                        key,
                        tenant,
                        r.try_get("registration").map_err(db)?,
                        r.try_get("generation").map_err(db)?,
                        r.try_get("id").map_err(db)?,
                        crate::protection::Part::Response,
                        &sealed,
                    )?;
                    protocol::decode(plain.expose()).map_err(Error::from)
                })
                .transpose()?;
            let application =
                if accepted && state == ReceiptState::Acknowledged && phase == Phase::Observe {
                    match (request, body.as_ref()) {
                        (Request::Command { command }, Some(body)) => {
                            rss_mdm_apple_mdm::software::receipt_presence(command, body)
                                .map_err(Error::from)?
                        }
                        _ => None,
                    }
                } else {
                    None
                };
            let mut fields = None;
            let mut error = None;
            if native_values
                && accepted
                && !phase.prerequisite()
                && let Some(mut body) = body
            {
                if let Some(chain) = body.get("ErrorChain") {
                    error = Some(
                        Fields::from_plist(&protocol::dictionary([("ErrorChain", chain.clone())]))
                            .map_err(|_| Error::Malformed)?,
                    );
                }
                for name in [
                    "Status",
                    "CommandUUID",
                    "UDID",
                    "UserID",
                    "AuthToken",
                    "UserLongName",
                    "UserShortName",
                    "EnrollmentID",
                    "EnrollmentUserID",
                ] {
                    body.remove(name);
                }
                fields = Some(Fields::from_plist(&body).map_err(|_| Error::Malformed)?);
            }
            Ok(Observation {
                phase,
                state,
                fields,
                error,
                application,
                profile: if phase == Phase::Observe {
                    assessment
                } else {
                    None
                },
                accepted,
                native_outcome: r
                    .try_get::<Option<String>, _>("native_outcome")
                    .map_err(db)?
                    .map(typed)
                    .transpose()?,
                received_at: r.try_get("received_at").map_err(db)?,
            })
        })
        .collect()
}
