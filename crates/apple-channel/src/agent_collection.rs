//! Bounded built-in Agent queries use the existing native attempts and collection owner.
use crate::{Error, database::db, device::DevicePrincipal};
use rss_mdm_apple_mdm::{agent_install as wire, protocol};
use rss_mdm_flow_service::planning::policies::agent_install::Identity;
use rss_mdm_inventory::{AgentInstallation, ReportSource};
use rss_mdm_inventory_service::collection::channel::{self, AgentEvidence};
use sqlx::{PgConnection, Row};
use uuid::Uuid;
pub async fn receive(
    c: &mut PgConnection,
    p: &DevicePrincipal,
    id: Uuid,
    status: protocol::Status,
    d: &plist::Dictionary,
    bytes: &[u8],
) -> Result<Option<Vec<rss_mdm_audit_integration::Fact>>, Error> {
    let row=sqlx::query("SELECT collection,phase,request,deadline<=clock_timestamp() AS expired FROM mdm_apple.attempts WHERE tenant_id=$1::uuid AND id=$2 AND registration=$3 AND generation=$4 AND phase IN('collect_agent_platform','collect_agent')")
        .bind(p.tenant().to_string()).bind(id).bind(p.registration()).bind(p.generation()).fetch_optional(&mut *c).await.map_err(db)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let id_collection: Uuid = row.try_get("collection").map_err(db)?;
    let Some(attempt) =
        crate::attempt::lock(c, p, id, crate::attempt::Owner::Collection, bytes).await?
    else {
        return Err(Error::Conflict);
    };
    match attempt {
        crate::attempt::Reception::Replay => return Ok(Some(vec![])),
        crate::attempt::Reception::Ready(a) => a.settle(c, status).await?,
    }
    let mut facts = vec![];
    if row.try_get::<bool, _>("expired").map_err(db)? {
        facts.extend(
            channel::abandon_in(c, &p.tenant().to_string(), id_collection, "timeout").await?,
        );
        return Ok(Some(facts));
    }
    if status == protocol::Status::NotNow
        || row.try_get::<String, _>("phase").map_err(db)? == "collect_agent_platform"
    {
        return Ok(Some(facts));
    }
    let request = protocol::decode(&row.try_get::<Vec<u8>, _>("request").map_err(db)?)?;
    let bundle = request
        .get("Command")
        .and_then(plist::Value::as_dictionary)
        .and_then(|d| d.get("Identifiers"))
        .and_then(plist::Value::as_array)
        .and_then(|a| a.first())
        .and_then(plist::Value::as_string)
        .ok_or(Error::Malformed)?;
    let platform:Option<Vec<u8>>=sqlx::query_scalar("SELECT response FROM mdm_apple.attempts WHERE tenant_id=$1::uuid AND collection=$2 AND phase='collect_agent_platform'").bind(p.tenant().to_string()).bind(id_collection).fetch_one(&mut *c).await.map_err(db)?;
    let architecture = platform
        .and_then(|b| protocol::decode(&b).ok())
        .and_then(|d| wire::architecture(&d).ok())
        .map(str::to_owned);
    let presence = if status == protocol::Status::Acknowledged {
        wire::presence(d, bundle).ok()
    } else {
        None
    };
    let (state, version) = match presence {
        Some(wire::Presence::Absent) => (AgentInstallation::Absent, None),
        Some(wire::Presence::PresentUnverified { version }) => {
            (AgentInstallation::Unknown, Some(version))
        }
        _ => (AgentInstallation::Unknown, None),
    };
    facts.extend(
        channel::finish_in(
            c,
            p,
            id_collection,
            ReportSource::MdmApple,
            state,
            Some(AgentEvidence {
                identity: bundle.into(),
                publisher: None,
                version,
                architecture,
            }),
        )
        .await?,
    );
    Ok(Some(facts))
}
pub async fn send(
    c: &mut PgConnection,
    p: &DevicePrincipal,
    identity: Option<&Identity>,
) -> Result<(Vec<u8>, Vec<rss_mdm_audit_integration::Fact>), Error> {
    let Some(Identity::Macos { bundle, .. }) = identity else {
        return Ok((vec![], vec![]));
    };
    let tenant = p.tenant().to_string();
    let allowed:bool=sqlx::query_scalar("SELECT access_rights & 256 = 256 FROM mdm_apple.devices WHERE tenant_id=$1::uuid AND registration=$2 AND state='active'").bind(&tenant).bind(p.registration()).fetch_one(&mut *c).await.map_err(db)?;
    if !allowed {
        return Ok((vec![], vec![]));
    }
    let previous=sqlx::query("SELECT a.collection,a.deadline<=clock_timestamp() AS expired,r.sealed_at FROM mdm_apple.attempts a JOIN mdm_access.collection_runs r ON(r.tenant_id,r.id)=(a.tenant_id,a.collection) WHERE a.tenant_id=$1::uuid AND a.registration=$2 AND a.generation=$3 AND a.phase='collect_agent' ORDER BY a.collection_sequence DESC LIMIT 1 FOR UPDATE OF a")
        .bind(&tenant).bind(p.registration()).bind(p.generation()).fetch_optional(&mut *c).await.map_err(db)?;
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&mut *c)
            .await
            .map_err(db)?;
    let mut facts = vec![];
    let collection = if let Some(row) = previous {
        let id: Uuid = row.try_get("collection").map_err(db)?;
        if let Some(at) = row.try_get::<Option<i64>, _>("sealed_at").map_err(db)? {
            if now - at < 300 {
                return Ok((vec![], facts));
            }
            None
        } else if row.try_get::<bool, _>("expired").map_err(db)? {
            facts.extend(channel::abandon_in(c, &tenant, id, "timeout").await?);
            sqlx::query("UPDATE mdm_apple.attempts SET state='superseded' WHERE tenant_id=$1::uuid AND collection=$2 AND state IN('sent','not_now','pending')").bind(&tenant).bind(id).execute(&mut *c).await.map_err(db)?;
            return Ok((vec![], facts));
        } else {
            Some(id)
        }
    } else {
        None
    };
    let collection = if let Some(id) = collection {
        id
    } else {
        let (id, _, sequence) = channel::start_in(c, p, ReportSource::MdmApple).await?;
        for (phase, payload) in [
            ("collect_agent_platform", wire::platform()),
            ("collect_agent", wire::query(bundle)?),
        ] {
            let attempt = Uuid::new_v4();
            let request = protocol::command(attempt, payload)?;
            sqlx::query("INSERT INTO mdm_apple.attempts(tenant_id,id,registration,generation,collection,phase,request,state,collection_sequence,deadline) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,'pending',$8,clock_timestamp()+interval '5 minutes')")
                .bind(&tenant).bind(attempt).bind(p.registration()).bind(p.generation()).bind(id).bind(phase).bind(request).bind(sequence).execute(&mut *c).await.map_err(db)?;
        }
        id
    };
    let row=sqlx::query("SELECT id,request,state,next_attempt<=clock_timestamp() AS ready FROM mdm_apple.attempts WHERE tenant_id=$1::uuid AND collection=$2 AND state IN('pending','sent','not_now') ORDER BY CASE phase WHEN 'collect_agent_platform' THEN 0 ELSE 1 END LIMIT 1 FOR UPDATE")
        .bind(&tenant).bind(collection).fetch_optional(&mut *c).await.map_err(db)?;
    let Some(row) = row else {
        return Ok((vec![], facts));
    };
    if !row.try_get::<bool, _>("ready").map_err(db)? {
        return Ok((vec![], facts));
    }
    let id: Uuid = row.try_get("id").map_err(db)?;
    sqlx::query("UPDATE mdm_apple.attempts SET state='sent',next_attempt=clock_timestamp()+interval '30 seconds' WHERE tenant_id=$1::uuid AND id=$2").bind(&tenant).bind(id).execute(&mut *c).await.map_err(db)?;
    Ok((row.try_get("request").map_err(db)?, facts))
}
