//! Dedicated managed certificate profile with correlated ManagedOnly ProfileList confirmation.
use crate::{Apple, Error, Failure, attempt, database::db, device::DevicePrincipal, protocol};
use rss_mdm_agent_wire::pki::{Acknowledgement, Trust};
use rss_mdm_audit_integration::{Fact, RequestAudit};
use sqlx::{PgConnection, Row};
use uuid::Uuid;
fn unavailable() -> Error {
    Error::Unavailable(Failure::AppleStorage)
}
pub(crate) async fn send(
    c: &mut PgConnection,
    apple: &Apple,
    p: &DevicePrincipal,
) -> Result<(Vec<u8>, Vec<Fact>), Error> {
    let tenant = p.tenant().to_string();
    let trust = apple.device_trust().public().map_err(|_| Error::Conflict)?;
    let digest = trust.installation_digest();
    let done:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_pki.installations WHERE tenant_id=$1::uuid AND purpose='apple' AND registration=$2 AND revision=$3 AND digest=$4)")
        .bind(&tenant).bind(p.registration()).bind(trust.revision as i64).bind(&digest).fetch_one(&mut *c).await.map_err(db)?;
    if done {
        return Ok((vec![], vec![]));
    }
    let rights:i32=sqlx::query_scalar("SELECT access_rights FROM mdm_apple.devices WHERE tenant_id=$1::uuid AND registration=$2 AND state='active'")
        .bind(&tenant).bind(p.registration()).fetch_one(&mut *c).await.map_err(db)?;
    if rights & 3 != 3 {
        return Err(Error::Forbidden);
    }
    let delivery=sqlx::query("SELECT id,body,profile FROM mdm_apple.trust_deliveries WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3 AND revision=$4 AND digest=$5 FOR UPDATE")
        .bind(&tenant).bind(p.registration()).bind(p.generation()).bind(trust.revision as i64).bind(&digest).fetch_optional(&mut *c).await.map_err(db)?;
    let (delivery, profile, frozen) = if let Some(row) = delivery {
        let frozen: Trust = serde_json::from_slice(&row.try_get::<Vec<u8>, _>("body").map_err(db)?)
            .map_err(|_| unavailable())?;
        (
            row.try_get::<Uuid, _>("id").map_err(db)?,
            row.try_get::<Uuid, _>("profile").map_err(db)?,
            frozen,
        )
    } else {
        let id = Uuid::new_v4();
        let profile = Uuid::new_v4();
        sqlx::query("INSERT INTO mdm_apple.trust_deliveries(tenant_id,id,registration,generation,revision,digest,body,profile) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8)")
            .bind(&tenant).bind(id).bind(p.registration()).bind(p.generation()).bind(trust.revision as i64).bind(&digest).bind(serde_json::to_vec(&trust).map_err(|_|unavailable())?).bind(profile).execute(&mut *c).await.map_err(db)?;
        (id, profile, trust.clone())
    };
    if frozen.installation_digest() != digest {
        return Err(Error::Conflict);
    }
    let latest=sqlx::query("SELECT id,ordinal,state,phase,request,next_attempt<=clock_timestamp() AS due,deadline>clock_timestamp() AS live,accepted FROM mdm_apple.attempts WHERE tenant_id=$1::uuid AND trust=$2 ORDER BY ordinal DESC LIMIT 1 FOR UPDATE")
        .bind(&tenant).bind(delivery).fetch_optional(&mut *c).await.map_err(db)?;
    let mut facts = Vec::new();
    let (id, bytes) = if let Some(row) = latest.as_ref().filter(|r| {
        r.try_get::<bool, _>("live").unwrap_or(false)
            && r.try_get::<String, _>("state")
                .is_ok_and(|s| matches!(s.as_str(), "pending" | "sent" | "not_now"))
    }) {
        if !row.try_get::<bool, _>("due").map_err(db)? {
            return Ok((vec![], facts));
        }
        let id: Uuid = row.try_get("id").map_err(db)?;
        let bytes = crate::protection::open(
            &apple.protection,
            &tenant,
            p.registration(),
            p.generation(),
            id,
            crate::protection::Part::Request,
            &row.try_get::<Vec<u8>, _>("request").map_err(db)?,
        )?
        .expose()
        .to_vec();
        (id, bytes)
    } else {
        let ordinal = latest
            .as_ref()
            .map(|r| r.try_get::<i32, _>("ordinal").map_err(db))
            .transpose()?
            .map_or(0, |n| n + 1);
        if ordinal > 32 {
            return Err(Error::Conflict);
        }
        let phase = if latest.as_ref().is_some_and(|r| {
            r.try_get::<String, _>("phase")
                .is_ok_and(|s| s == "trust_verify")
                || (r.try_get::<bool, _>("accepted").is_ok_and(|v| v)
                    && r.try_get::<String, _>("state")
                        .is_ok_and(|s| s == "acknowledged"))
        }) {
            "trust_verify"
        } else {
            "trust_install"
        };
        let id = Uuid::new_v4();
        let command = if phase == "trust_install" {
            let authorities = apple.trust_certificates()?;
            let (profile, _) =
                rss_mdm_apple_mdm::profile::trust(&authorities, p.registration(), profile)?;
            let now: i64 =
                sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                    .fetch_one(&mut *c)
                    .await
                    .map_err(db)?;
            protocol::dictionary([
                ("RequestType", "InstallProfile".into()),
                (
                    "Payload",
                    plist::Value::Data(apple.signer.sign(&profile, now)?),
                ),
            ])
        } else {
            protocol::dictionary([
                ("RequestType", "ProfileList".into()),
                ("ManagedOnly", true.into()),
            ])
        };
        let bytes = protocol::command(id, command)?;
        let sealed = crate::protection::seal(
            &apple.protection,
            &tenant,
            p.registration(),
            p.generation(),
            id,
            crate::protection::Part::Request,
            &bytes,
        )?;
        sqlx::query("INSERT INTO mdm_apple.attempts(tenant_id,id,registration,generation,trust,phase,ordinal,request,state,deadline) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,'pending',clock_timestamp()+interval '15 minutes')")
            .bind(&tenant).bind(id).bind(p.registration()).bind(p.generation()).bind(delivery).bind(phase).bind(ordinal).bind(sealed).execute(&mut *c).await.map_err(db)?;
        let a = RequestAudit::new(tenant.clone(), "apple_pki_install");
        a.identify_device(p.registration());
        a.registration(p.registration());
        a.target(p.device());
        facts.push(Fact::business(
            &a,
            &format!("apple-pki:{id}:dispatch"),
            digest.as_bytes(),
            200,
            "success",
            Some(id),
        )?);
        (id, bytes)
    };
    sqlx::query("UPDATE mdm_apple.attempts SET state='sent',next_attempt=clock_timestamp()+interval '30 seconds' WHERE tenant_id=$1::uuid AND id=$2")
        .bind(&tenant).bind(id).execute(&mut *c).await.map_err(db)?;
    crate::notify(c, "apple").await.map_err(db)?;
    Ok((bytes, facts))
}
pub(crate) async fn receive(
    c: &mut PgConnection,
    apple: &Apple,
    p: &DevicePrincipal,
    id: Uuid,
    status: protocol::Status,
    report: &plist::Dictionary,
    bytes: &[u8],
) -> Result<Option<Vec<Fact>>, Error> {
    let row=sqlx::query("SELECT a.phase,a.deadline>clock_timestamp() AS live,d.body,d.profile FROM mdm_apple.attempts a JOIN mdm_apple.trust_deliveries d ON (d.tenant_id,d.id)=(a.tenant_id,a.trust) WHERE a.tenant_id=$1::uuid AND a.id=$2 AND a.registration=$3 AND a.generation=$4")
        .bind(p.tenant().to_string()).bind(id).bind(p.registration()).bind(p.generation()).fetch_optional(&mut *c).await.map_err(db)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let reception = attempt::lock(c, &apple.protection, p, id, attempt::Owner::Trust, bytes)
        .await?
        .ok_or(Error::Conflict)?;
    let attempt::Reception::Ready(a) = reception else {
        return Ok(Some(vec![]));
    };
    let valid = row.try_get::<bool, _>("live").map_err(db)?;
    a.settle(c, status, valid).await?;
    if !valid
        || status != protocol::Status::Acknowledged
        || row.try_get::<String, _>("phase").map_err(db)? != "trust_verify"
    {
        return Ok(Some(vec![]));
    }
    let frozen: Trust = serde_json::from_slice(&row.try_get::<Vec<u8>, _>("body").map_err(db)?)
        .map_err(|_| unavailable())?;
    let current = apple.device_trust().public().map_err(|_| Error::Conflict)?;
    if frozen.installation_digest() != current.installation_digest() {
        return Ok(Some(vec![]));
    }
    let (_, objects) = rss_mdm_apple_mdm::profile::trust(
        &apple.trust_certificates()?,
        p.registration(),
        row.try_get("profile").map_err(db)?,
    )?;
    if !rss_mdm_apple_mdm::native::profiles::observed_structure(report, &objects)? {
        return Ok(Some(vec![]));
    }
    rss_mdm_pki_service::registry::Registry::acknowledge_in(
        c,
        &p.tenant().to_string(),
        p.registration(),
        &current,
        &Acknowledgement {
            operation: id,
            version: 1,
            revision: current.revision,
            digest: current.installation_digest(),
        },
    )
    .await
    .map_err(|_| Error::Conflict)?;
    let a = RequestAudit::new(p.tenant().to_string(), "apple_pki_confirm");
    a.identify_device(p.registration());
    a.registration(p.registration());
    a.target(p.device());
    Ok(Some(vec![Fact::business(
        &a,
        &format!("apple-pki:{id}:confirmed"),
        current.installation_digest().as_bytes(),
        200,
        "success",
        Some(id),
    )?]))
}
