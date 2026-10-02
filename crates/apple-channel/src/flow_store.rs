use crate::device::DevicePrincipal;
use crate::{Error, database::db};
use rss_mdm_apple_mdm::protocol as wire;
use rss_mdm_execution_service::channels::{self, AppleCommand, AppleDispatch, Pending, Reception};
use sqlx::{PgConnection, Row};
use uuid::Uuid;
pub struct Store {
    pub protection: std::sync::Arc<rss_mdm_native_protection::Protector>,
}
impl channels::AppleStore for Store {
    fn prepare_native_collection<'a>(
        &'a self,
        c: &'a mut sqlx::PgConnection,
        tenant: String,
        id: Uuid,
    ) -> channels::Pending<'a, Vec<rss_mdm_audit_integration::Fact>> {
        Box::pin(async move {
            crate::collection::prepare_native(c, &self.protection, &tenant, id)
                .await
                .map_err(Into::into)
        })
    }
    fn push_due<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        configuration: [u8; 32],
    ) -> Pending<'a, bool> {
        Box::pin(async move {
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_apple.devices WHERE tenant_id=$1::uuid AND state='active' AND (push_outcome IS DISTINCT FROM 'rejected' OR push_configuration IS DISTINCT FROM $2) AND next_push<=clock_timestamp() AND (push_lease_until IS NULL OR push_lease_until<clock_timestamp()))").bind(tenant).bind(configuration.as_slice()).fetch_one(c).await.map_err(storage)
        })
    }
    fn push_candidates<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        configuration: [u8; 32],
    ) -> Pending<'a, Vec<channels::PushCandidate>> {
        Box::pin(async move {
            let rows=sqlx::query("SELECT registration,token,magic,token_revision FROM mdm_apple.devices WHERE tenant_id=$1::uuid AND state='active' AND (push_outcome IS DISTINCT FROM 'rejected' OR push_configuration IS DISTINCT FROM $2) AND next_push<=clock_timestamp() AND (push_lease_until IS NULL OR push_lease_until<clock_timestamp()) ORDER BY next_push,registration LIMIT 32 FOR UPDATE SKIP LOCKED").bind(&tenant).bind(configuration.as_slice()).fetch_all(&mut *c).await.map_err(storage)?;
            let mut result = Vec::new();
            for row in rows {
                let registration = row.try_get("registration").map_err(storage)?;
                if !rss_mdm_registration_service::device::store::active_source_in(
                    c,
                    &tenant,
                    registration,
                    rss_mdm_inventory::ReportSource::MdmApple,
                )
                .await
                .map_err(|e| channels::Rejection::from(Error::from(e)))?
                {
                    self.defer_push(c, tenant.clone(), registration).await?;
                    continue;
                }
                result.push(channels::PushCandidate {
                    registration,
                    revision: row.try_get("token_revision").map_err(storage)?,
                    token: row.try_get("token").map_err(storage)?,
                    magic: row.try_get("magic").map_err(storage)?,
                });
            }
            Ok(result)
        })
    }
    fn defer_push<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        registration: Uuid,
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            sqlx::query("UPDATE mdm_apple.devices SET next_push=clock_timestamp()+interval '30 seconds' WHERE tenant_id=$1::uuid AND registration=$2::uuid").bind(tenant).bind(registration).execute(c).await.map_err(storage)?;
            Ok(())
        })
    }
    fn lease_push<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        wake: Uuid,
        registration: Uuid,
        configuration: [u8; 32],
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            sqlx::query("UPDATE mdm_apple.devices SET push_failures=CASE WHEN push_configuration IS DISTINCT FROM $4 THEN 0 ELSE push_failures END,push_configuration=$4,push_id=$3::uuid,push_lease_until=clock_timestamp()+interval '15 seconds',next_push=clock_timestamp()+interval '30 seconds' WHERE tenant_id=$1::uuid AND registration=$2::uuid").bind(tenant).bind(registration).bind(wake).bind(configuration.as_slice()).execute(c).await.map_err(storage)?;
            Ok(())
        })
    }
    fn settle_push<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        wake: channels::Wake,
        status: Option<u16>,
        outcome: channels::PushOutcome,
    ) -> Pending<'a, Option<u64>> {
        Box::pin(async move {
            let unregistered = outcome == channels::PushOutcome::Unregistered;
            let outcome = outcome.as_str();
            let old=sqlx::query("SELECT push_lease_until IS NULL AS settled,push_status,push_outcome FROM mdm_apple.devices WHERE tenant_id=$1::uuid AND registration=$2::uuid AND push_id=$3::uuid AND token_revision=$4 FOR UPDATE").bind(&tenant).bind(wake.registration).bind(wake.id).bind(wake.revision).fetch_optional(&mut *c).await.map_err(storage)?;
            let Some(old) = old else { return Ok(None) };
            if old.try_get::<bool, _>("settled").map_err(storage)? {
                return Ok(Some(
                    if old
                        .try_get::<Option<i32>, _>("push_status")
                        .map_err(storage)?
                        == status.map(i32::from)
                        && old
                            .try_get::<Option<String>, _>("push_outcome")
                            .map_err(storage)?
                            .as_deref()
                            == Some(outcome)
                    {
                        0
                    } else {
                        2
                    },
                ));
            }
            Ok(Some(sqlx::query("UPDATE mdm_apple.devices SET push_lease_until=NULL,push_status=$5,push_outcome=$6,next_push=clock_timestamp()+make_interval(secs => CASE WHEN $6='retryable' THEN greatest(CASE WHEN $5>=500 THEN 900 ELSE 30 END,30*(1<<least(push_failures,5))) ELSE 30 END),push_failures=CASE WHEN $6='retryable' THEN least(push_failures+1,6) ELSE 0 END,token=CASE WHEN $7 THEN NULL ELSE token END,magic=CASE WHEN $7 THEN NULL ELSE magic END,state=CASE WHEN $7 THEN 'pending_token' ELSE state END WHERE tenant_id=$1::uuid AND registration=$2::uuid AND push_id=$3::uuid AND token_revision=$4 AND state='active' AND push_lease_until IS NOT NULL").bind(tenant).bind(wake.registration).bind(wake.id).bind(wake.revision).bind(status.map(i32::from)).bind(outcome).bind(unregistered).execute(c).await.map_err(storage)?.rows_affected()))
        })
    }
    fn renewal_due<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        registration: Uuid,
    ) -> Pending<'a, bool> {
        Box::pin(async move {
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_apple.attempts WHERE tenant_id=$1::uuid AND registration=$2::uuid AND phase='renew' AND state IN ('pending','sent','not_now') AND next_attempt<=clock_timestamp() AND deadline>clock_timestamp())").bind(tenant).bind(registration).fetch_one(c).await.map_err(storage)
        })
    }
    fn pending_collections<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        registration: Uuid,
        limit: usize,
    ) -> Pending<'a, Vec<channels::PendingCollection>> {
        Box::pin(async move {
            let mut result = Vec::new();
            let mut offset = 0i64;
            while result.len() < limit {
                let ids=sqlx::query_scalar::<_,Uuid>("SELECT collection FROM mdm_apple.attempts WHERE tenant_id=$1::uuid AND registration=$2::uuid AND collection IS NOT NULL AND state IN('pending','sent','not_now') AND deadline>clock_timestamp() AND next_attempt<=clock_timestamp() GROUP BY collection ORDER BY min(next_attempt),collection LIMIT 64 OFFSET $3").bind(&tenant).bind(registration).bind(offset).fetch_all(&mut *c).await.map_err(storage)?;
                let mut pending = rss_mdm_inventory_service::collection::read::pending_apple_in(
                    c,
                    &tenant,
                    registration,
                    &ids,
                )
                .await
                .map_err(|e| channels::Rejection::from(Error::from(e)))?;
                for id in &ids {
                    if pending.remove(id) {
                        result.push(channels::PendingCollection { id: *id });
                        if result.len() == limit {
                            break;
                        }
                    }
                }
                if ids.len() < 64 {
                    break;
                }
                offset += 64;
            }
            Ok(result)
        })
    }
    fn defer_collection<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        collection: Uuid,
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            sqlx::query("UPDATE mdm_apple.attempts SET next_attempt=clock_timestamp()+interval '30 seconds' WHERE tenant_id=$1::uuid AND collection=$2::uuid").bind(tenant).bind(collection).execute(c).await.map_err(storage)?;
            Ok(())
        })
    }

    fn observations<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        operation: Uuid,
    ) -> Pending<'a, Vec<channels::Observation>> {
        Box::pin(async move {
            let rows=sqlx::query("SELECT id,registration,generation,phase,state,response,received_at FROM mdm_apple.attempts WHERE tenant_id=$1::uuid AND operation=$2::uuid ORDER BY ordinal,phase").bind(&tenant).bind(operation).fetch_all(c).await.map_err(|e|channels::Rejection::from(db(e)))?;
            rows.into_iter()
                .map(|r| {
                    Ok(channels::Observation {
                        phase: r
                            .try_get("phase")
                            .map_err(|e| channels::Rejection::from(db(e)))?,
                        state: r
                            .try_get("state")
                            .map_err(|e| channels::Rejection::from(db(e)))?,
                        response: r
                            .try_get::<Option<Vec<u8>>, _>("response")
                            .map_err(storage)?
                            .map(|sealed| {
                                crate::protection::open(
                                    &self.protection,
                                    &tenant,
                                    r.try_get("registration").map_err(db)?,
                                    r.try_get("generation").map_err(db)?,
                                    r.try_get("id").map_err(db)?,
                                    crate::protection::Part::Response,
                                    &sealed,
                                )
                                .map(|v| v.expose().to_vec())
                            })
                            .transpose()
                            .map_err(channels::Rejection::from)?,
                        received_at: r
                            .try_get("received_at")
                            .map_err(|e| channels::Rejection::from(db(e)))?,
                    })
                })
                .collect()
        })
    }
}
impl channels::AppleAttempt for super::attempt::Attempt {
    fn latest(&self) -> bool {
        self.latest
    }
    fn operation(&self) -> Option<Uuid> {
        self.operation
    }
    fn phase(&self) -> &str {
        &self.phase
    }
    fn settle<'a>(
        self: Box<Self>,
        c: &'a mut PgConnection,
        status: wire::Status,
    ) -> Pending<'a, ()> {
        Box::pin(async move { (*self).settle(c, status).await.map_err(Into::into) })
    }
}
impl channels::Apple for super::Apple {
    fn current<'a>(
        &'a self,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
        udid: &'a str,
    ) -> Pending<'a, ()> {
        Box::pin(async move { current(c, p, udid).await.map_err(Into::into) })
    }
    fn collect<'a>(
        &'a self,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
        id: Uuid,
        status: wire::Status,
        dictionary: &'a plist::Dictionary,
        bytes: &'a [u8],
    ) -> Pending<'a, (bool, Vec<rss_mdm_audit_integration::Fact>)> {
        Box::pin(async move {
            if let Some(facts) = crate::agent_collection::receive(
                c,
                &self.protection,
                p,
                id,
                status,
                dictionary,
                bytes,
            )
            .await
            .map_err(channels::Rejection::from)?
            {
                return Ok((true, facts));
            }
            let mut facts = Vec::new();
            let collected = crate::collection::receive(
                c,
                &self.protection,
                &mut facts,
                p,
                id,
                status,
                dictionary,
                bytes,
            )
            .await
            .map_err(channels::Rejection::from)?;
            Ok((collected, facts))
        })
    }
    fn lock_attempt<'a>(
        &'a self,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
        id: Uuid,
        bytes: &'a [u8],
    ) -> Pending<'a, Option<Reception>> {
        Box::pin(async move {
            Ok(super::attempt::lock(
                c,
                &self.protection,
                p,
                id,
                super::attempt::Owner::Command,
                bytes,
            )
            .await
            .map_err(channels::Rejection::from)?
            .map(|r| match r {
                super::attempt::Reception::Replay => Reception::Replay,
                super::attempt::Reception::Ready(a) => Reception::Ready(Box::new(a)),
            }))
        })
    }
    fn command<'a>(
        &'a self,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
        command: &'a AppleCommand,
    ) -> Pending<'a, AppleDispatch> {
        Box::pin(async move { send_command(c, self, p, command).await.map_err(Into::into) })
    }
    fn collection<'a>(
        &'a self,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
    ) -> Pending<'a, channels::Reply> {
        Box::pin(async move {
            let (mut bytes, facts) =
                crate::agent_collection::send(c, &self.protection, p, self.agent_identity.as_ref())
                    .await
                    .map_err(channels::Rejection::from)?;
            if bytes.is_empty() {
                bytes = crate::collection::send(c, &self.protection, p)
                    .await
                    .map_err(channels::Rejection::from)?;
            }
            Ok(channels::Reply { bytes, facts })
        })
    }
}
async fn current(c: &mut PgConnection, p: &DevicePrincipal, udid: &str) -> Result<(), Error> {
    crate::device::store::lock_channel(c, &p.tenant().to_string(), p.device(), p.channel()).await?;
    crate::device::store::revalidate_source(c, p, rss_mdm_inventory::ReportSource::MdmApple)
        .await?;
    let valid=sqlx::query_scalar::<_,bool>("SELECT true FROM mdm_apple.devices WHERE tenant_id=$1::uuid AND registration=$2::uuid AND state='active' AND udid=$3 FOR UPDATE").bind(p.tenant().to_string()).bind(p.registration()).bind(udid).fetch_optional(c).await.map_err(db)?.unwrap_or(false);
    if !valid {
        return Err(Error::Unauthorized);
    }
    Ok(())
}
async fn send_command(
    c: &mut PgConnection,
    apple: &super::Apple,
    p: &DevicePrincipal,
    command: &AppleCommand,
) -> Result<AppleDispatch, Error> {
    use rss_mdm_apple_mdm::native::{self, request::Request as A};
    if !matches!(
        command.target,
        rss_mdm_execution_service::NativeTarget::Device
    ) {
        return Err(Error::Unsupported);
    }
    let Some(context) = super::native::context(c, &apple.protection, p, command).await? else {
        return super::native::resolve(c, &apple.protection, p, command)
            .await
            .map(Into::into);
    };
    let rights:i32=sqlx::query_scalar("SELECT access_rights FROM mdm_apple.devices WHERE tenant_id=$1::uuid AND registration=$2 AND state='active'").bind(p.tenant().to_string()).bind(p.registration()).fetch_one(&mut *c).await.map_err(db)?;
    let rights = super::native::rights(rights);
    let target = native::Target {
        context: &context,
        access_rights: &rights,
    };
    let tenant = p.tenant().to_string();
    let rows=sqlx::query("SELECT id,phase,ordinal,state,request,next_attempt<=clock_timestamp() AS ready FROM mdm_apple.attempts WHERE tenant_id=$1::uuid AND operation=$2 AND phase IN('execute','observe') ORDER BY ordinal DESC,phase FOR UPDATE").bind(&tenant).bind(command.operation).fetch_all(&mut *c).await.map_err(db)?;
    let profile = matches!(
        command.request,
        A::InstallProfile { .. } | A::RemoveProfile { .. }
    );
    let software_query = match &command.request {
        A::Command { command } => rss_mdm_apple_mdm::software::observation(command)?,
        _ => None,
    };
    let executed = rows.iter().any(|r| {
        r.try_get::<String, _>("phase").ok().as_deref() == Some("execute")
            && matches!(
                r.try_get::<String, _>("state").ok().as_deref(),
                Some("sent" | "acknowledged")
            )
    });
    let phase = if (profile || software_query.is_some()) && executed {
        "observe"
    } else {
        "execute"
    };
    let id = Uuid::new_v4();
    let now = sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
        .fetch_one(&mut *c)
        .await
        .map_err(db)?;
    let compiled = if phase == "observe" {
        if let Some(query) = software_query {
            query.compile(&target)
        } else {
            native::Command::new("ProfileList", plist::Dictionary::new(), &target)
        }
    } else {
        match &command.request {
            A::Command { command } => command.compile(&target),
            A::InstallProfile { profile } => {
                let profile = match profile.compile(&target) {
                    Ok(profile) => profile,
                    Err(error) => return Ok(AppleDispatch::Rejected(error)),
                };
                let signed = apple.signer.sign(&profile.bytes, now)?;
                native::Command::new(
                    "InstallProfile",
                    wire::dictionary([("Payload", plist::Value::Data(signed))]),
                    &target,
                )
            }
            A::RemoveProfile { identifier, .. } => native::Command::new(
                "RemoveProfile",
                wire::dictionary([("Identifier", identifier.as_str().into())]),
                &target,
            ),
            A::Declarations { .. } => return Err(Error::Unsupported),
        }
    };
    let compiled = match compiled {
        Ok(compiled) => compiled,
        Err(error) => return Ok(AppleDispatch::Rejected(error)),
    };
    let mut ordinal = 0;
    if let Some(row) = rows
        .iter()
        .find(|r| r.try_get::<String, _>("phase").ok().as_deref() == Some(phase))
    {
        if !row.try_get::<bool, _>("ready").map_err(db)? {
            return Ok(AppleDispatch::Waiting);
        }
        let state: String = row.try_get("state").map_err(db)?;
        if matches!(state.as_str(), "pending" | "not_now") {
            // Explicit refusal permits only the same immutable native command.
            let id: Uuid = row.try_get("id").map_err(db)?;
            sqlx::query("UPDATE mdm_apple.attempts SET state='sent',next_attempt=clock_timestamp()+interval '30 seconds' WHERE tenant_id=$1::uuid AND id=$2").bind(&tenant).bind(id).execute(&mut *c).await.map_err(db)?;
            let sealed: Vec<u8> = row.try_get("request").map_err(db)?;
            let plain = crate::protection::open(
                &apple.protection,
                &tenant,
                p.registration(),
                p.generation(),
                id,
                crate::protection::Part::Request,
                &sealed,
            )?;
            return Ok(AppleDispatch::Ready(plain.expose().to_vec()));
        }
        // Unknown mutations are never reissued. Only an independent native read can advance.
        if phase != "observe" || !matches!(state.as_str(), "sent" | "acknowledged" | "error") {
            return Ok(AppleDispatch::Waiting);
        }
        ordinal = row
            .try_get::<i32, _>("ordinal")
            .map_err(db)?
            .checked_add(1)
            .ok_or(Error::Malformed)?;
        if ordinal > 32 {
            return Ok(AppleDispatch::Waiting);
        }
    }
    let bytes = compiled.encode(id).map_err(|_| Error::Malformed)?;
    let sealed = crate::protection::seal(
        &apple.protection,
        &tenant,
        p.registration(),
        p.generation(),
        id,
        crate::protection::Part::Request,
        &bytes,
    )?;
    sqlx::query("INSERT INTO mdm_apple.attempts(tenant_id,id,registration,generation,operation,phase,request,state,deadline,next_attempt,ordinal) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,'sent',to_timestamp($8),clock_timestamp()+interval '30 seconds',$9)").bind(&tenant).bind(id).bind(p.registration()).bind(p.generation()).bind(command.operation).bind(phase).bind(sealed).bind(command.deadline as f64).bind(ordinal).execute(&mut *c).await.map_err(db)?;
    crate::notify(c, "apple").await.map_err(db)?;
    Ok(AppleDispatch::Ready(bytes))
}

fn storage(e: sqlx::Error) -> channels::Rejection {
    channels::Rejection::from(db(e))
}
