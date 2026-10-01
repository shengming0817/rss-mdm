use crate::{Error, database::db, device::DevicePrincipal};
use rss_mdm_apple_mdm::protocol as wire;
use rss_mdm_inventory_service::collection::{Attempts, store};
use rss_mdm_registration_service::enrollment::store::uuid;
use sqlx::{PgConnection, Row};
use uuid::Uuid;
pub async fn receive(
    c: &mut PgConnection,
    facts: &mut Vec<rss_mdm_audit_integration::Fact>,
    p: &DevicePrincipal,
    id: Uuid,
    status: wire::Status,
    d: &plist::Dictionary,
    bytes: &[u8],
) -> Result<bool, Error> {
    use crate::attempt::{self, Owner, Reception};
    let tenant = p.tenant().to_string();
    let attempt = match attempt::lock(c, p, id, Owner::Collection, bytes).await? {
        None => return Ok(false),
        Some(Reception::Replay) => return Ok(true),
        Some(Reception::Ready(attempt)) => attempt,
    };
    if !rss_mdm_inventory_service::apple_collection::current(c, &tenant, id).await? {
        attempt.settle(c, status).await?;
        return Ok(true);
    }
    attempt.settle(c, status).await?;
    if status != wire::Status::NotNow {
        let mut run = store::load_on(c, &tenant, id).await?;
        let now = sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&mut *c)
            .await
            .map_err(db)?;
        if let Some(template) =
            rss_mdm_inventory_service::collection::native::template(c, &tenant, id).await?
        {
            let root = if template.spec().adapter
                == rss_mdm_resource::NativeAdapter::AppleDeviceInformation
            {
                d.get("QueryResponses")
                    .cloned()
                    .unwrap_or(plist::Value::Dictionary(Default::default()))
            } else {
                plist::Value::Dictionary(d.clone())
            };
            let value = serde_json::to_value(root).map_err(|_| Error::Malformed)?;
            let success = status == wire::Status::Acknowledged
                && bytes.len() <= template.spec().output_bytes as usize;
            run.attempts = rss_mdm_inventory_service::collection::native::result(
                &template,
                run.attempts.definition().clone(),
                &value,
                now,
                success,
            )?;
            facts.extend(store::seal(c, &mut run, "complete").await?);
            return Ok(true);
        }
        let values = if status == wire::Status::Acknowledged {
            Some(
                d.get("QueryResponses")
                    .and_then(plist::Value::as_dictionary)
                    .ok_or(Error::Malformed)?,
            )
        } else {
            None
        };
        use rss_mdm_inventory_service::collection::NativeValue;
        let values = [
            (rss_mdm_inventory::builtin::MODEL, "Model"),
            (rss_mdm_inventory::builtin::OS_VERSION, "OSVersion"),
        ]
        .into_iter()
        .map(|(field, key)| {
            (
                field,
                match values {
                    None => NativeValue::Failed,
                    Some(d) => match d.get(key) {
                        Some(plist::Value::String(s)) => {
                            NativeValue::Value(rss_mdm_inventory::CollectedValue::Value(
                                rss_mdm_inventory::Scalar::String(s.clone()),
                            ))
                        }
                        Some(_) => NativeValue::Invalid,
                        None => NativeValue::Missing,
                    },
                },
            )
        })
        .collect();
        run.attempts = Attempts::native(run.attempts.definition().clone(), values, now)
            .map_err(|_| Error::Malformed)?;
        facts.extend(store::seal(c, &mut run, "complete").await?);
    }
    Ok(true)
}
pub async fn send(c: &mut PgConnection, p: &DevicePrincipal) -> Result<Vec<u8>, Error> {
    let tenant = p.tenant().to_string();
    let rows=sqlx::query("SELECT id::text,request FROM mdm_apple.attempts WHERE tenant_id=$1::uuid AND registration=$2::uuid AND generation=$3 AND phase='collect' AND state IN ('pending','sent','not_now') AND next_attempt<=clock_timestamp() AND deadline>clock_timestamp() ORDER BY collection_sequence LIMIT 32 FOR UPDATE")
        .bind(&tenant).bind(p.registration().to_string()).bind(p.generation()).fetch_all(&mut *c).await.map_err(db)?;
    for row in rows {
        let id = uuid(&row, "id")?;
        if !rss_mdm_inventory_service::apple_collection::current(c, &tenant, id).await? {
            sqlx::query("UPDATE mdm_apple.attempts SET next_attempt=clock_timestamp()+interval '30 seconds' WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(&tenant).bind(id.to_string()).execute(&mut *c).await.map_err(db)?;
            crate::notify(c, "apple").await.map_err(db)?;
            continue;
        }
        sqlx::query("UPDATE mdm_apple.attempts SET state='sent',next_attempt=clock_timestamp()+interval '30 seconds' WHERE tenant_id=$1::uuid AND id=$2::uuid")
            .bind(&tenant).bind(id.to_string()).execute(&mut *c).await.map_err(db)?;
        crate::notify(c, "apple").await.map_err(db)?;
        crate::execution::actions::native_collection::sent(c, &tenant, id).await?;
        return row.try_get("request").map_err(db);
    }
    Ok(Vec::new())
}

pub struct Participant;
impl rss_mdm_inventory_service::apple_collection::Participant for Participant {
    fn start<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: &'a str,
        id: Uuid,
        registration: Uuid,
        generation: i64,
        sequence: i64,
        deadline: String,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<(), rss_mdm_inventory_service::Error>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let active:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_apple.devices WHERE tenant_id=$1::uuid AND registration=$2::uuid AND state='active' FOR SHARE)").bind(tenant).bind(registration).fetch_one(&mut *c).await.map_err(|_|rss_mdm_inventory_service::Error::Unavailable(rss_mdm_inventory_service::Failure::Database))?;
            if !active {
                return Err(rss_mdm_inventory_service::Error::Conflict);
            }
            let request = wire::command(
                id,
                wire::dictionary([
                    ("RequestType", "DeviceInformation".into()),
                    (
                        "Queries",
                        plist::Value::Array(vec!["Model".into(), "OSVersion".into()]),
                    ),
                ]),
            )
            .map_err(|_| {
                rss_mdm_inventory_service::Error::Unavailable(
                    rss_mdm_inventory_service::Failure::Protocol,
                )
            })?;
            sqlx::query("INSERT INTO mdm_apple.attempts(tenant_id,id,registration,generation,collection,phase,request,state,collection_sequence,deadline) VALUES($1::uuid,$2::uuid,$3::uuid,$4,$2::uuid,'collect',$5,'pending',$6,$7::text::timestamptz)").bind(tenant).bind(id).bind(registration).bind(generation).bind(request).bind(sequence).bind(deadline).execute(&mut *c).await.map_err(|_|rss_mdm_inventory_service::Error::Unavailable(rss_mdm_inventory_service::Failure::Database))?;
            crate::notify(c, "apple").await.map_err(|_| {
                rss_mdm_inventory_service::Error::Unavailable(
                    rss_mdm_inventory_service::Failure::Database,
                )
            })?;
            Ok(())
        })
    }
}

pub async fn prepare_native(
    c: &mut PgConnection,
    tenant: &str,
    id: Uuid,
) -> Result<Vec<rss_mdm_audit_integration::Fact>, Error> {
    use rss_mdm_resource::NativeAdapter;
    let template = rss_mdm_inventory_service::collection::native::template(c, tenant, id)
        .await?
        .ok_or(Error::Malformed)?;
    let row=sqlx::query("SELECT c.registration,r.generation,c.sequence,c.deadline::text AS deadline,d.access_rights FROM mdm_access.collection_runs c JOIN mdm_access.registrations r ON(r.tenant_id,r.id)=(c.tenant_id,c.registration) JOIN mdm_apple.devices d ON(d.tenant_id,d.registration)=(r.tenant_id,r.id) WHERE c.tenant_id=$1::uuid AND c.id=$2 AND c.sealed_at IS NULL AND d.state='active'").bind(tenant).bind(id).fetch_one(&mut *c).await.map_err(db)?;
    let required = match template.spec().adapter {
        NativeAdapter::AppleDeviceInformation => 16,
        NativeAdapter::AppleInstalledApplications => 256,
        _ => return Err(Error::Malformed),
    };
    if row.try_get::<i32, _>("access_rights").map_err(db)? & required != required {
        let mut run = store::load_on(c, tenant, id).await?;
        let now: i64 =
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                .fetch_one(&mut *c)
                .await
                .map_err(db)?;
        let values = run
            .attempts
            .definition()
            .fields()
            .iter()
            .map(|f| {
                (
                    f.key,
                    rss_mdm_inventory::NativeValue::Value(
                        rss_mdm_inventory::CollectedValue::Unsupported,
                    ),
                )
            })
            .collect();
        run.attempts = Attempts::native(run.attempts.definition().clone(), values, now)
            .map_err(|_| Error::Malformed)?;
        return Ok(store::seal(c, &mut run, "complete")
            .await?
            .into_iter()
            .collect());
    }
    let command = match template.spec().adapter {
        NativeAdapter::AppleDeviceInformation => wire::dictionary([
            ("RequestType", "DeviceInformation".into()),
            (
                "Queries",
                plist::Value::Array(
                    template
                        .spec()
                        .mappings
                        .values()
                        .map(|m| m.query.clone())
                        .collect::<std::collections::BTreeSet<_>>()
                        .into_iter()
                        .map(plist::Value::String)
                        .collect(),
                ),
            ),
        ]),
        NativeAdapter::AppleInstalledApplications => {
            wire::dictionary([("RequestType", "InstalledApplicationList".into())])
        }
        _ => return Err(Error::Malformed),
    };
    let request = wire::command(id, command)?;
    sqlx::query("INSERT INTO mdm_apple.attempts(tenant_id,id,registration,generation,collection,phase,request,state,collection_sequence,deadline) VALUES($1::uuid,$2,$3,$4,$2,'collect',$5,'pending',$6,$7::text::timestamptz)")
        .bind(tenant).bind(id).bind(row.try_get::<Uuid,_>("registration").map_err(db)?).bind(row.try_get::<i64,_>("generation").map_err(db)?).bind(request).bind(row.try_get::<i64,_>("sequence").map_err(db)?).bind(row.try_get::<String,_>("deadline").map_err(db)?).execute(&mut *c).await.map_err(db)?;
    crate::notify(c, "apple").await.map_err(db)?;
    Ok(Vec::new())
}
