//! One ADE operation journal, page checkpoints and fenced external effects.
use super::management::Command;
use super::*;
use rss_mdm_audit_integration::{Fact, RequestAudit};
use serde_json::{Value, json};

struct Work {
    id: Uuid,
    organization: Uuid,
    revision: i64,
    token_revision: i64,
    lease: Uuid,
    kind: String,
    request: Value,
    previous_result: Option<Value>,
    cursor: Option<String>,
    full: bool,
    attempt: i32,
}
pub fn registration(
    app: Arc<HttpState>,
    notify: Arc<tokio::sync::Notify>,
) -> rss_runtime::ManagedTaskRegistration {
    let (task, _) =
        rss_runtime::ManagedTask::prepare("apple-ade", std::time::Duration::from_secs(8));
    task.into_registration(move|stop|async move{
        loop{
            let progress=tokio::select!{biased;()=stop.cancelled()=>return Ok(()),r=cycle(&app)=>r};
            if matches!(progress,Ok(true)){continue;}
            if progress.is_err(){eprintln!("apple_ade_cycle_failed");}
            tokio::select!{biased;()=stop.cancelled()=>return Ok(()),()=notify.notified()=>{},()=tokio::time::sleep(std::time::Duration::from_secs(5))=>{}}
        }
    })
}
/// One bounded page/effect per invocation. Used by the real worker and protocol T2.
pub async fn cycle(app: &HttpState) -> Result<bool, Error> {
    let tenant = app.identity.tenant().to_string();
    let time = now(app)?;
    let audit = RequestAudit::new(tenant.clone(), "apple_ade_worker");
    audit.identify_service("service:apple-ade");
    let budget =
        rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(10));
    let claimed = app
        .audit_store
        .write(
            app.identity.tenant(),
            &budget.control(),
            (app, &audit, &tenant, time),
            |ctx, tx| {
                Box::pin(async move {
                    let (app, audit, tenant, time) = *ctx;
                    let (work, changes) = tx
                        .with_connection_context(&mut (app, tenant, time), |ctx, c| {
                            Box::pin(async move {
                                let (_app, tenant, time) = *ctx;
                                claim_in(c, tenant, time).await
                            })
                        })
                        .await?;
                    for (id, phase, attempt) in changes {
                        let fact = Fact::business(
                            audit,
                            &format!("ade:{id}:{phase}:{attempt}"),
                            format!("{id}:{phase}:{attempt}").as_bytes(),
                            200,
                            "success",
                            Some(id),
                        )?;
                        app.audit_store
                            .append(tx, &fact, false)
                            .await
                            .map_err(Error::from)?;
                    }
                    audit.mark_commit_started();
                    Ok(work)
                })
            },
        )
        .await;
    let Some(work) = crate::operations::settle(claimed, &audit)? else {
        return Ok(false);
    };
    let mut tx = app.access.begin(&tenant).await?;
    let row = server(&mut tx, &tenant, work.organization).await?;
    let token = super::token(&row, app, &tenant, work.organization);
    tx.rollback().await.map_err(db)?;
    let response = match token {
        Ok(token) => {
            let mut client = management::remote_client(app, token)?;
            perform(app, &tenant, &work, &mut client).await
        }
        Err(_) => Err(client::RemoteError::Unauthorized),
    };
    finish(app, &tenant, &work, response).await?;
    Ok(true)
}
async fn claim_in(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    time: i64,
) -> Result<(Option<Work>, Vec<(Uuid, &'static str, i32)>), Error> {
    let mut changes = Vec::new();
    let mut scheduled_id = None;
    let scheduled=sqlx::query("SELECT organization,revision,token_revision,cursor FROM mdm_apple.ade_servers s WHERE tenant_id=$1::uuid AND enabled AND verified AND NOT token_invalid AND token_expires>$2 AND next_sync<=$2 AND NOT EXISTS(SELECT 1 FROM mdm_apple.ade_operations o WHERE o.tenant_id=s.tenant_id AND o.organization=s.organization AND o.state IN('pending','running','unknown')) ORDER BY organization LIMIT 1 FOR UPDATE SKIP LOCKED").bind(tenant).bind(time).fetch_optional(&mut *c).await.map_err(db)?;
    if let Some(r) = scheduled {
        let organization: Uuid = r.try_get("organization").map_err(db)?;
        let id = Uuid::new_v4();
        scheduled_id = Some(id);
        management::save(
            c,
            tenant,
            organization,
            id,
            "sync",
            &rss_mdm_registration_service::enrollment::digest(&(id, organization)),
            "service:apple-ade",
            "service",
            r.try_get("revision").map_err(db)?,
            r.try_get("token_revision").map_err(db)?,
            &json!({"kind":"sync","full":false}),
            "pending",
            None,
            r.try_get::<Option<String>, _>("cursor")
                .map_err(db)?
                .is_none(),
            time,
        )
        .await?;
        sqlx::query(
            "UPDATE mdm_apple.ade_operations SET cursor=$3 WHERE tenant_id=$1::uuid AND id=$2",
        )
        .bind(tenant)
        .bind(id)
        .bind(r.try_get::<Option<String>, _>("cursor").map_err(db)?)
        .execute(&mut *c)
        .await
        .map_err(db)?;
        sqlx::query("UPDATE mdm_apple.ade_servers SET next_sync=$3 WHERE tenant_id=$1::uuid AND organization=$2").bind(tenant).bind(organization).bind(time+1800).execute(&mut *c).await.map_err(db)?;
        changes.push((id, "schedule", 0));
    }
    let candidate=sqlx::query("SELECT id,organization FROM mdm_apple.ade_operations WHERE tenant_id=$1::uuid AND ($3::uuid IS NULL OR id=$3) AND ((state='pending' AND next_attempt<=$2) OR (state='running' AND lease_until<=$2)) ORDER BY created_at,id LIMIT 1").bind(tenant).bind(time).bind(scheduled_id).fetch_optional(&mut *c).await.map_err(db)?;
    let Some(candidate) = candidate else {
        return Ok((None, changes));
    };
    let id: Uuid = candidate.try_get("id").map_err(db)?;
    let organization: Uuid = candidate.try_get("organization").map_err(db)?;
    let s = server(c, tenant, organization).await?;
    let row=sqlx::query("SELECT * FROM mdm_apple.ade_operations WHERE tenant_id=$1::uuid AND id=$2 AND ((state='pending' AND next_attempt<=$3) OR (state='running' AND lease_until<=$3)) FOR UPDATE SKIP LOCKED").bind(tenant).bind(id).bind(time).fetch_optional(&mut *c).await.map_err(db)?;
    let Some(r) = row else {
        return Ok((None, changes));
    };
    let kind: String = r.try_get("kind").map_err(db)?;
    let attempt: i32 = r
        .try_get::<i32, _>("attempts")
        .map_err(db)?
        .checked_add(1)
        .ok_or(Error::Conflict)?;
    if r.try_get::<String, _>("state").map_err(db)? == "running"
        && matches!(kind.as_str(), "profile" | "assign" | "clear")
    {
        sqlx::query("UPDATE mdm_apple.ade_operations SET state='unknown',result=$3,lease=NULL,lease_until=NULL WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(id).bind(json!({"reason":"interrupted_external_effect"})).execute(&mut *c).await.map_err(db)?;
        changes.push((id, "interrupted", attempt));
        return Ok((None, changes));
    }
    let revision: i64 = r.try_get("server_revision").map_err(db)?;
    let token_revision: i64 = r.try_get("token_revision").map_err(db)?;
    if !s.try_get::<bool, _>("enabled").map_err(db)?
        || s.try_get::<i64, _>("revision").map_err(db)? != revision
        || s.try_get::<i64, _>("token_revision").map_err(db)? != token_revision
    {
        sqlx::query("UPDATE mdm_apple.ade_operations SET state='superseded',result=$3 WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(id).bind(json!({"reason":"authority_changed"})).execute(&mut *c).await.map_err(db)?;
        sqlx::query(
            "DELETE FROM mdm_apple.ade_sync_devices WHERE tenant_id=$1::uuid AND operation=$2",
        )
        .bind(tenant)
        .bind(id)
        .execute(&mut *c)
        .await
        .map_err(db)?;
        changes.push((id, "superseded", attempt));
        return Ok((None, changes));
    }
    let lease = Uuid::new_v4();
    sqlx::query("UPDATE mdm_apple.ade_operations SET state='running',lease=$3,lease_until=$4,attempts=$5 WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(id).bind(lease).bind(time+180).bind(attempt).execute(&mut *c).await.map_err(db)?;
    changes.push((id, "claim", attempt));
    Ok((
        Some(Work {
            id,
            organization,
            revision,
            token_revision,
            lease,
            kind,
            request: r.try_get("request").map_err(db)?,
            previous_result: r.try_get("result").map_err(db)?,
            cursor: r.try_get("cursor").map_err(db)?,
            full: r.try_get("full_sync").map_err(db)?,
            attempt,
        }),
        changes,
    ))
}
async fn perform(
    app: &HttpState,
    tenant: &str,
    work: &Work,
    client: &mut client::Client,
) -> Result<Value, client::RemoteError> {
    if work.kind == "sync" {
        let mut request = json!({"limit":1000});
        if let Some(cursor) = &work.cursor {
            request["cursor"] = json!(cursor);
        }
        return client
            .request(
                reqwest::Method::POST,
                if work.full {
                    "/server/devices"
                } else {
                    "/devices/sync"
                },
                Some(&request),
            )
            .await;
    }
    let command: Command =
        serde_json::from_value(work.request.clone()).map_err(|_| client::RemoteError::Invalid)?;
    match command {
        Command::Profile {
            id, configuration, ..
        } => {
            client
                .request(
                    reqwest::Method::POST,
                    "/profile",
                    Some(&configuration.apple(format!(
                        "{}/api/v1/apple/ade/enroll/{}/{id}",
                        app.authentication.origin, work.organization
                    ))),
                )
                .await
        }
        Command::Assign {
            profile,
            revision,
            devices,
        } => {
            let mut tx = app
                .access
                .begin_read(tenant)
                .await
                .map_err(|_| client::RemoteError::Unknown)?;
            let remote:Option<Uuid>=sqlx::query_scalar("SELECT remote_uuid FROM mdm_apple.ade_profiles WHERE tenant_id=$1::uuid AND organization=$2 AND id=$3 AND revision=$4").bind(tenant).bind(work.organization).bind(profile).bind(revision).fetch_optional(&mut *tx).await.map_err(|_|client::RemoteError::Unknown)?.flatten();
            tx.rollback()
                .await
                .map_err(|_| client::RemoteError::Unknown)?;
            let remote = remote.ok_or(client::RemoteError::Invalid)?;
            client
                .request(
                    reqwest::Method::POST,
                    "/profile/devices",
                    Some(&json!({"profile_uuid":remote,"devices":retry_devices(work, &devices)})),
                )
                .await
        }
        Command::Clear { devices } => {
            client
                .request(
                    reqwest::Method::DELETE,
                    "/profile/devices",
                    Some(&json!({"devices":retry_devices(work, &devices)})),
                )
                .await
        }
        Command::Reconcile { operation } => {
            let mut tx = app
                .access
                .begin_read(tenant)
                .await
                .map_err(|_| client::RemoteError::Unknown)?;
            let frozen:Value=sqlx::query_scalar("SELECT request FROM mdm_apple.ade_operations WHERE tenant_id=$1::uuid AND organization=$2 AND id=$3 AND state='unknown'").bind(tenant).bind(work.organization).bind(operation).fetch_one(&mut *tx).await.map_err(|_|client::RemoteError::Invalid)?;
            tx.rollback()
                .await
                .map_err(|_| client::RemoteError::Unknown)?;
            let command: Command =
                serde_json::from_value(frozen).map_err(|_| client::RemoteError::Invalid)?;
            let devices = match command {
                Command::Assign { devices, .. } | Command::Clear { devices } => devices,
                _ => return Err(client::RemoteError::Invalid),
            };
            client
                .request(
                    reqwest::Method::POST,
                    "/devices",
                    Some(&json!({"devices":devices})),
                )
                .await
        }
        Command::Resolve { remote_profile, .. } => {
            client
                .request(
                    reqwest::Method::GET,
                    &format!("/profile?profile_uuid={remote_profile}"),
                    None,
                )
                .await
        }
        _ => Err(client::RemoteError::Invalid),
    }
}
fn is_write(kind: &str) -> bool {
    matches!(kind, "profile" | "assign" | "clear")
}
fn retry_devices<'a>(work: &Work, devices: &'a [String]) -> Vec<&'a String> {
    devices
        .iter()
        .filter(|serial| {
            !matches!(
                previous_outcome(work, serial),
                Some("SUCCESS" | "FAILED" | "NOT_ACCESSIBLE")
            )
        })
        .collect()
}
fn previous_outcome<'a>(work: &'a Work, serial: &str) -> Option<&'a str> {
    work.previous_result
        .as_ref()?
        .get("devices")?
        .get(serial)?
        .as_str()
}
async fn finish(
    app: &HttpState,
    tenant: &str,
    work: &Work,
    response: Result<Value, client::RemoteError>,
) -> Result<(), Error> {
    let audit = RequestAudit::new(tenant.into(), "apple_ade_worker");
    audit.identify_service("service:apple-ade");
    audit.operation(work.id, "apple_ade_worker");
    let budget =
        rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(10));
    let result=app.audit_store.write(app.identity.tenant(),&budget.control(),(app,tenant,work,&audit,&response),|ctx,tx|Box::pin(async move{
        let(app,tenant,work,audit,response)=*ctx;
        let committed=tx.with_connection_context(&mut(app,tenant,work,response),|ctx,c|Box::pin(async move{
            let(app,tenant,work,response)=*ctx;management::lock(c,tenant,work.organization).await?;let s=server(c,tenant,work.organization).await?;
            let active:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_apple.ade_operations WHERE tenant_id=$1::uuid AND id=$2 AND state='running' AND lease=$3 AND lease_until>$4)").bind(tenant).bind(work.id).bind(work.lease).bind(now(app)?).fetch_one(&mut *c).await.map_err(db)?;
            if !active{return Ok::<_,Error>(false);}
            let (state,value)=if s.try_get::<i64,_>("revision").map_err(db)?!=work.revision || s.try_get::<i64,_>("token_revision").map_err(db)?!=work.token_revision || !s.try_get::<bool,_>("enabled").map_err(db)?{
                // The external effect may have happened; a newer authority must not consume it.
                (if is_write(&work.kind){"unknown"}else{"superseded"},json!({"reason":"authority_changed"}))
            }else{match response{
                Ok(value)=>apply(c,app,tenant,work,value).await?,
                Err(client::RemoteError::Cursor) if work.kind=="sync"=>{
                    // Discard this incomplete snapshot without changing published devices.
                    sqlx::query("DELETE FROM mdm_apple.ade_sync_devices WHERE tenant_id=$1::uuid AND operation=$2").bind(tenant).bind(work.id).execute(&mut *c).await.map_err(db)?;
                    sqlx::query("UPDATE mdm_apple.ade_operations SET full_sync=true,cursor=NULL,cursor_digests=ARRAY[]::text[] WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(work.id).execute(&mut *c).await.map_err(db)?;
                    // The cursor chain is no longer authoritative until a complete full rebuild.
                    sqlx::query("UPDATE mdm_apple.ade_servers SET cursor=NULL,synced_at=NULL WHERE tenant_id=$1::uuid AND organization=$2").bind(tenant).bind(work.organization).execute(&mut *c).await.map_err(db)?;
                    ("pending",json!({"reason":"cursor_reset"}))
                }
                Err(client::RemoteError::Unauthorized)=>{
                    sqlx::query("UPDATE mdm_apple.ade_servers SET token_invalid=true WHERE tenant_id=$1::uuid AND organization=$2").bind(tenant).bind(work.organization).execute(&mut *c).await.map_err(db)?;
                    ("failed",json!({"reason":"token_invalid"}))
                }
                Err(client::RemoteError::Throttled)=>("pending",json!({"reason":"throttled"})),
                Err(client::RemoteError::Unknown)=> (if is_write(&work.kind){"unknown"}else{"pending"},json!({"reason":"external_outcome_unknown"})),
                Err(client::RemoteError::Invalid)=>("failed",json!({"reason":"invalid_response"})),
                Err(client::RemoteError::Cursor)=>("failed",json!({"reason":"invalid_cursor"})),
            }};
            if work.kind=="sync" && state!="pending" {
                sqlx::query("DELETE FROM mdm_apple.ade_sync_devices WHERE tenant_id=$1::uuid AND operation=$2").bind(tenant).bind(work.id).execute(&mut *c).await.map_err(db)?;
            }
            let delay=if state=="pending" && work.kind!="sync"{value.get("retryAfterSeconds").and_then(Value::as_i64).unwrap_or(60)}else if response.is_err(){30}else{0};
            sqlx::query("UPDATE mdm_apple.ade_operations SET state=$4,result=$5,lease=NULL,lease_until=NULL,next_attempt=$6 WHERE tenant_id=$1::uuid AND id=$2 AND lease=$3").bind(tenant).bind(work.id).bind(work.lease).bind(state).bind(value).bind(now(app)?+delay).execute(c).await.map_err(db)?;Ok(true)
        })).await?;
        if committed{let fact=Fact::business(audit,&format!("ade:{}:finish:{}",work.id,work.attempt),format!("{}:{}",work.id,work.attempt).as_bytes(),200,"success",Some(work.id))?;app.audit_store.append(tx,&fact,false).await.map_err(Error::from)?;}
        audit.mark_commit_started();Ok(())
    })).await;
    crate::operations::settle(result, &audit)
}
async fn apply(
    c: &mut sqlx::PgConnection,
    app: &HttpState,
    tenant: &str,
    work: &Work,
    value: &Value,
) -> Result<(&'static str, Value), Error> {
    if work.kind == "sync" {
        return match sync_page(c, app, tenant, work, value).await {
            Err(Error::Malformed) => Ok(("failed", json!({"reason":"invalid_page"}))),
            other => other,
        };
    }
    let command: Command =
        serde_json::from_value(work.request.clone()).map_err(|_| Error::Malformed)?;
    match command {
        Command::Profile {
            id,
            expected_revision,
            ..
        } => {
            let Some(remote) = value
                .get("profile_uuid")
                .and_then(Value::as_str)
                .and_then(|s| Uuid::parse_str(s).ok())
                .filter(|u| !u.is_nil())
            else {
                return Ok(("unknown", json!({"reason":"missing_profile_receipt"})));
            };
            let count=sqlx::query("UPDATE mdm_apple.ade_profiles SET remote_uuid=$5 WHERE tenant_id=$1::uuid AND organization=$2 AND id=$3 AND revision=$4").bind(tenant).bind(work.organization).bind(id).bind(expected_revision+1).bind(remote).execute(c).await.map_err(db)?.rows_affected();
            Ok((
                if count == 1 { "succeeded" } else { "unknown" },
                json!({"remoteProfile":remote}),
            ))
        }
        Command::Assign {
            profile,
            revision,
            devices,
        } => {
            let remote:Option<Uuid>=sqlx::query_scalar("SELECT remote_uuid FROM mdm_apple.ade_profiles WHERE tenant_id=$1::uuid AND organization=$2 AND id=$3 AND revision=$4").bind(tenant).bind(work.organization).bind(profile).bind(revision).fetch_optional(&mut *c).await.map_err(db)?.flatten();
            if remote.is_none() {
                return Ok(("unknown", json!({"reason":"profile_changed"})));
            }
            assignment(c, app, tenant, work, &devices, remote, value).await
        }
        Command::Clear { devices } => assignment(c, app, tenant, work, &devices, None, value).await,
        Command::Reconcile { operation } => {
            let frozen:Value=sqlx::query_scalar("SELECT request FROM mdm_apple.ade_operations WHERE tenant_id=$1::uuid AND organization=$2 AND id=$3 AND state='unknown' AND kind IN('assign','clear') FOR UPDATE").bind(tenant).bind(work.organization).bind(operation).fetch_optional(&mut *c).await.map_err(db)?.ok_or(Error::Conflict)?;
            let old: Command = serde_json::from_value(frozen).map_err(|_| Error::Malformed)?;
            let (devices, expected) = match old {
                Command::Clear { devices } => (devices, None),
                Command::Assign {
                    profile,
                    revision,
                    devices,
                } => {
                    let remote:Option<Uuid>=sqlx::query_scalar("SELECT remote_uuid FROM mdm_apple.ade_profiles WHERE tenant_id=$1::uuid AND organization=$2 AND id=$3 AND revision=$4").bind(tenant).bind(work.organization).bind(profile).bind(revision).fetch_optional(&mut *c).await.map_err(db)?.flatten();
                    let Some(remote) = remote else {
                        return Ok(("failed", json!({"reason":"profile_changed"})));
                    };
                    (devices, Some(remote))
                }
                _ => return Err(Error::Malformed),
            };
            let Some(observed) = value.get("devices").and_then(Value::as_object) else {
                return Ok(("failed", json!({"reason":"missing_device_observation"})));
            };
            // Query all requested devices; absence never proves a successful clear.
            let mut observations = Vec::with_capacity(devices.len());
            let mut confirmed = true;
            for serial in &devices {
                let Some(d) = observed.get(serial).and_then(Value::as_object) else {
                    return Ok(("failed", json!({"reason":"incomplete_device_observation"})));
                };
                let actual = match d.get("profile_uuid") {
                    Some(Value::String(id)) if !id.is_empty() => {
                        let Ok(id) = Uuid::parse_str(id) else {
                            return Ok(("failed", json!({"reason":"invalid_device_observation"})));
                        };
                        if id.is_nil() {
                            return Ok(("failed", json!({"reason":"invalid_device_observation"})));
                        }
                        Some(id)
                    }
                    None | Some(Value::Null) | Some(Value::String(_))
                        if matches!(
                            d.get("profile_status").and_then(Value::as_str),
                            Some("empty" | "removed")
                        ) =>
                    {
                        None
                    }
                    _ => return Ok(("failed", json!({"reason":"incomplete_device_observation"}))),
                };
                confirmed &= actual == expected;
                observations.push((serial, actual));
            }
            // A complete authoritative read also resolves an effect that did not apply.
            // Publish each observation atomically before releasing the unknown barrier.
            for (serial, actual) in observations {
                sqlx::query("UPDATE mdm_apple.ade_devices SET remote_profile=$4,assignment_revision=assignment_revision+CASE WHEN remote_profile IS DISTINCT FROM $4 THEN 1 ELSE 0 END,observed_at=$5 WHERE tenant_id=$1::uuid AND organization=$2 AND serial=$3 AND NOT deleted").bind(tenant).bind(work.organization).bind(serial).bind(actual).bind(now(app)?).execute(&mut *c).await.map_err(db)?;
            }
            let resolved = if confirmed { "succeeded" } else { "failed" };
            let result = json!({"recoveredBy":work.id,"reason":if confirmed{"effect_confirmed"}else{"effect_not_confirmed"},"registration":"not_implied"});
            sqlx::query("UPDATE mdm_apple.ade_operations SET state=$3,result=$4 WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(operation).bind(resolved).bind(&result).execute(c).await.map_err(db)?;
            Ok(("succeeded", result))
        }
        Command::Resolve {
            operation,
            remote_profile,
        } => {
            let r=sqlx::query("SELECT request FROM mdm_apple.ade_operations WHERE tenant_id=$1::uuid AND organization=$2 AND id=$3 AND kind='profile' AND state='unknown' FOR UPDATE").bind(tenant).bind(work.organization).bind(operation).fetch_optional(&mut *c).await.map_err(db)?.ok_or(Error::Conflict)?;
            let Command::Profile {
                id,
                expected_revision,
                configuration,
            } = serde_json::from_value(r.try_get::<Value, _>("request").map_err(db)?)
                .map_err(|_| Error::Malformed)?
            else {
                return Err(Error::Conflict);
            };
            let expected = configuration.apple(format!(
                "{}/api/v1/apple/ade/enroll/{}/{id}",
                app.authentication.origin, work.organization
            ));
            if expected
                .as_object()
                .ok_or(Error::Malformed)?
                .iter()
                .any(|(k, v)| value.get(k) != Some(v))
            {
                return Ok(("failed", json!({"reason":"profile_mismatch"})));
            }
            let count=sqlx::query("UPDATE mdm_apple.ade_profiles SET remote_uuid=$5 WHERE tenant_id=$1::uuid AND organization=$2 AND id=$3 AND revision=$4").bind(tenant).bind(work.organization).bind(id).bind(expected_revision+1).bind(remote_profile).execute(&mut *c).await.map_err(db)?.rows_affected();
            if count != 1 {
                return Ok(("failed", json!({"reason":"profile_changed"})));
            }
            sqlx::query("UPDATE mdm_apple.ade_operations SET state='succeeded',result=$3 WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(operation).bind(json!({"remoteProfile":remote_profile,"recoveredBy":work.id})).execute(c).await.map_err(db)?;
            Ok(("succeeded", json!({"remoteProfile":remote_profile})))
        }
        _ => Err(Error::Malformed),
    }
}
async fn sync_page(
    c: &mut sqlx::PgConnection,
    app: &HttpState,
    tenant: &str,
    work: &Work,
    value: &Value,
) -> Result<(&'static str, Value), Error> {
    let devices = value
        .get("devices")
        .and_then(Value::as_array)
        .filter(|d| d.len() <= 1000)
        .ok_or(Error::Malformed)?;
    let cursor = value
        .get("cursor")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= 4096)
        .ok_or(Error::Malformed)?;
    let more = value
        .get("more_to_follow")
        .and_then(Value::as_bool)
        .ok_or(Error::Malformed)?;
    let cursor_digest = rss_mdm_registration_service::enrollment::digest(&cursor);
    let (at_limit,used):(bool,bool)=sqlx::query_as("SELECT cardinality(cursor_digests)>=10000,$3=ANY(cursor_digests) FROM mdm_apple.ade_operations WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(work.id).bind(&cursor_digest).fetch_one(&mut *c).await.map_err(db)?;
    if at_limit || (more && (used || work.cursor.as_deref() == Some(cursor))) {
        return Ok(("failed", json!({"reason":"cursor_no_progress"})));
    }
    // Validate the entire page before adding any rows to its private snapshot.
    let mut page = Vec::with_capacity(devices.len());
    for d in devices {
        let serial = d
            .get("serial_number")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty() && s.len() <= 128 && !s.chars().any(char::is_control))
            .ok_or(Error::Malformed)?;
        let deleted = match d.get("op_type").and_then(Value::as_str) {
            Some("added" | "modified") => false,
            Some("deleted") => true,
            None if work.full => false,
            _ => return Err(Error::Malformed),
        };
        let date = d
            .get(if work.full {
                "device_assigned_date"
            } else {
                "op_date"
            })
            .and_then(Value::as_str)
            .ok_or(Error::Malformed)?;
        time::OffsetDateTime::parse(date, &time::format_description::well_known::Rfc3339)
            .map_err(|_| Error::Malformed)?;
        let profile = d
            .get("profile_uuid")
            .filter(|v| !v.is_null())
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(Uuid::parse_str)
            .transpose()
            .map_err(|_| Error::Malformed)?;
        page.push((serial, date, deleted, profile));
    }
    for (serial, date, deleted, profile) in page {
        sqlx::query("INSERT INTO mdm_apple.ade_sync_devices(tenant_id,operation,serial,operation_date,deleted,remote_profile) VALUES($1::uuid,$2,$3,$4::text::timestamptz,$5,$6) ON CONFLICT(tenant_id,operation,serial) DO UPDATE SET operation_date=excluded.operation_date,deleted=excluded.deleted,remote_profile=excluded.remote_profile WHERE $7 OR excluded.operation_date>mdm_apple.ade_sync_devices.operation_date")
            .bind(tenant).bind(work.id).bind(serial).bind(date).bind(deleted).bind(profile).bind(work.full).execute(&mut *c).await.map_err(db)?;
    }
    sqlx::query("UPDATE mdm_apple.ade_operations SET cursor=$3,cursor_digests=array_append(cursor_digests,$4) WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(work.id).bind(cursor).bind(cursor_digest).execute(&mut *c).await.map_err(db)?;
    if !more {
        // A fenced full snapshot replaces current state; its assignment date is not an event version.
        sqlx::query("INSERT INTO mdm_apple.ade_devices(tenant_id,organization,serial,operation_date,deleted,seen_run,remote_profile,observed_at) SELECT tenant_id,$3,serial,operation_date,deleted,$2,remote_profile,$4 FROM mdm_apple.ade_sync_devices WHERE tenant_id=$1::uuid AND operation=$2 ON CONFLICT(tenant_id,organization,serial) DO UPDATE SET operation_date=excluded.operation_date,deleted=excluded.deleted,remote_profile=excluded.remote_profile,assignment_revision=mdm_apple.ade_devices.assignment_revision+CASE WHEN excluded.deleted IS DISTINCT FROM mdm_apple.ade_devices.deleted OR excluded.remote_profile IS DISTINCT FROM mdm_apple.ade_devices.remote_profile THEN 1 ELSE 0 END,seen_run=excluded.seen_run,observed_at=excluded.observed_at WHERE $5 OR excluded.operation_date>=mdm_apple.ade_devices.operation_date")
            .bind(tenant).bind(work.id).bind(work.organization).bind(now(app)?).bind(work.full).execute(&mut *c).await.map_err(db)?;
        if work.full {
            sqlx::query("UPDATE mdm_apple.ade_devices SET deleted=true,assignment_revision=assignment_revision+1,observed_at=$4 WHERE tenant_id=$1::uuid AND organization=$2 AND NOT EXISTS(SELECT 1 FROM mdm_apple.ade_sync_devices staged WHERE staged.tenant_id=mdm_apple.ade_devices.tenant_id AND staged.operation=$3 AND staged.serial=mdm_apple.ade_devices.serial) AND NOT deleted").bind(tenant).bind(work.organization).bind(work.id).bind(now(app)?).execute(&mut *c).await.map_err(db)?;
        }
        sqlx::query("UPDATE mdm_apple.ade_servers SET cursor=$3,synced_at=$4,next_sync=$4+1800 WHERE tenant_id=$1::uuid AND organization=$2").bind(tenant).bind(work.organization).bind(cursor).bind(now(app)?).execute(&mut *c).await.map_err(db)?;
        sqlx::query(
            "DELETE FROM mdm_apple.ade_sync_devices WHERE tenant_id=$1::uuid AND operation=$2",
        )
        .bind(tenant)
        .bind(work.id)
        .execute(c)
        .await
        .map_err(db)?;
    }
    Ok((
        if more { "pending" } else { "succeeded" },
        json!({"pageDevices":devices.len(),"moreToFollow":more,"registration":"not_implied"}),
    ))
}
async fn assignment(
    c: &mut sqlx::PgConnection,
    app: &HttpState,
    tenant: &str,
    work: &Work,
    devices: &[String],
    profile: Option<Uuid>,
    value: &Value,
) -> Result<(&'static str, Value), Error> {
    let outcomes = value
        .get("devices")
        .and_then(Value::as_object)
        .ok_or(Error::Malformed)?;
    let mut results = serde_json::Map::new();
    let mut throttled = false;
    let mut failed = false;
    let mut unknown = false;
    for serial in devices {
        let outcome = match previous_outcome(work, serial) {
            Some(old @ ("SUCCESS" | "FAILED" | "NOT_ACCESSIBLE")) => old,
            _ => outcomes
                .get(serial)
                .and_then(Value::as_str)
                .unwrap_or("UNKNOWN"),
        };
        let outcome = match outcome {
            "SUCCESS" | "FAILED" | "NOT_ACCESSIBLE" | "THROTTLED" => outcome,
            _ => "UNKNOWN",
        };
        results.insert(serial.clone(), json!(outcome));
        if outcome == "SUCCESS" {
            sqlx::query("UPDATE mdm_apple.ade_devices SET remote_profile=$4,assignment_revision=assignment_revision+CASE WHEN remote_profile IS DISTINCT FROM $4 THEN 1 ELSE 0 END,observed_at=$5 WHERE tenant_id=$1::uuid AND organization=$2 AND serial=$3 AND NOT deleted").bind(tenant).bind(work.organization).bind(serial).bind(profile).bind(now(app)?).execute(&mut *c).await.map_err(db)?;
        } else if outcome == "THROTTLED" {
            throttled = true;
        } else if matches!(outcome, "FAILED" | "NOT_ACCESSIBLE") {
            failed = true;
        } else {
            unknown = true;
        }
    }
    let delay = value
        .get("retry_after_seconds")
        .and_then(Value::as_i64)
        .unwrap_or(60);
    unknown |= throttled && !(1..=86400).contains(&delay);
    Ok((
        if unknown {
            "unknown"
        } else if throttled {
            "pending"
        } else if failed {
            "failed"
        } else {
            "succeeded"
        },
        json!({"devices":results,"retryAfterSeconds":if throttled && !unknown{Some(delay)}else{None},"registration":"not_implied"}),
    ))
}
