//! Protected native results are decoded and interpreted at their sole channel owner.
use crate::{Error, Failure, database::db, protocol};
use rss_mdm_apple_mdm::native::{
    evidence::{Observation, Phase, ReceiptState},
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
    observations_many(
        c,
        key,
        tenant,
        vec![(operation, request.clone())],
        native_values,
    )
    .await?
    .remove(&operation)
    .ok_or(Error::Unavailable(Failure::AppleStorage))
}
pub(crate) async fn observations_many(
    c: &mut PgConnection,
    key: &Protector,
    tenant: &str,
    requests: Vec<(Uuid, Request)>,
    native_values: bool,
) -> Result<std::collections::BTreeMap<Uuid, Vec<Observation>>, Error> {
    if requests.len() > 1000 {
        return Err(Error::Malformed);
    }
    let ids = requests.iter().map(|(id, _)| *id).collect::<Vec<_>>();
    if ids.is_empty() {
        return Ok(Default::default());
    }
    let profiles:Vec<(Uuid,String)>=sqlx::query_as("SELECT operation,verification FROM mdm_apple.profile_qualifications($2::uuid[]) WHERE tenant_id=$1::uuid AND operation=ANY($2)").bind(tenant).bind(&ids).fetch_all(&mut *c).await.map_err(db)?;
    let profiles = profiles
        .into_iter()
        .collect::<std::collections::BTreeMap<_, _>>();
    let rows=sqlx::query("WITH selected AS MATERIALIZED (SELECT operation,id,registration,generation,phase,state,response,received_at,accepted,native_outcome,ordinal FROM mdm_apple.attempts WHERE tenant_id=$1::uuid AND operation=ANY($2)),budget AS(SELECT count(*)<=8192 AND coalesce(sum(pg_column_size(selected)),0)<=16777216 AS ok FROM selected) SELECT selected.*,budget.ok AS within_budget FROM budget LEFT JOIN selected ON budget.ok ORDER BY operation,ordinal,phase")
        .bind(tenant).bind(ids).fetch_all(&mut *c).await.map_err(db)?;
    rss_mdm_query_postgres::observe_rows("execution.apple", &rows).map_err(db)?;
    let mut grouped = std::collections::BTreeMap::<Uuid, Vec<_>>::new();
    for row in rows {
        if !row.try_get::<bool, _>("within_budget").map_err(db)? {
            return Err(Error::Malformed);
        }
        if let Some(operation) = row.try_get::<Option<Uuid>, _>("operation").map_err(db)? {
            grouped.entry(operation).or_default().push(row);
        }
    }
    requests
        .into_iter()
        .map(|(operation, request)| {
            let profile = matches!(
                request,
                Request::InstallProfile { .. } | Request::RemoveProfile { .. }
            );
            let assessment = if profile {
                Some(crate::profiles::decode_assessment(
                    profiles.get(&operation).map(String::as_str),
                )?)
            } else {
                None
            };
            let rows = grouped.remove(&operation).unwrap_or_default();
            Ok((
                operation,
                decode_observations(rows, key, tenant, &request, native_values, assessment)?,
            ))
        })
        .collect()
}
fn decode_observations(
    rows: Vec<sqlx::postgres::PgRow>,
    key: &Protector,
    tenant: &str,
    request: &Request,
    native_values: bool,
    assessment: Option<rss_mdm_apple_mdm::native::profiles::Verification>,
) -> Result<Vec<Observation>, Error> {
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
                crate::recovery_credentials::redact(&mut body);
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
