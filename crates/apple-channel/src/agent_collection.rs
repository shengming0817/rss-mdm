//! Bounded built-in Agent queries use the existing native attempts and collection owner.
use crate::execution::channels::AppleReception;
use crate::{Error, database::db, device::DevicePrincipal};
use rss_mdm_apple_mdm::{protocol, software as wire};
use rss_mdm_execution_service::agent_install::Identity;
use rss_mdm_inventory::{AgentInstallation, ReportSource};
use rss_mdm_inventory_service::collection::channel::{self, AgentEvidence};
use sqlx::{PgConnection, Row};
use uuid::Uuid;
pub async fn receive(
    c: &mut PgConnection,
    protection: &rss_mdm_native_protection::Protector,
    p: &DevicePrincipal,
    id: Uuid,
    status: protocol::Status,
    d: &plist::Dictionary,
    bytes: &[u8],
) -> Result<Option<AppleReception>, Error> {
    let row=sqlx::query("SELECT collection,phase,request,deadline<=clock_timestamp() AS expired FROM mdm_apple.attempts WHERE tenant_id=$1::uuid AND id=$2 AND registration=$3 AND generation=$4 AND phase IN('collect_agent_platform','collect_agent')")
        .bind(p.tenant().to_string()).bind(id).bind(p.registration()).bind(p.generation()).fetch_optional(&mut *c).await.map_err(db)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let id_collection: Uuid = row.try_get("collection").map_err(db)?;
    let Some(attempt) = crate::attempt::lock(
        c,
        protection,
        p,
        id,
        crate::attempt::Owner::Collection,
        bytes,
    )
    .await?
    else {
        return Err(Error::Conflict);
    };
    match attempt {
        crate::attempt::Reception::Replay => return Ok(Some(AppleReception::Replay)),
        crate::attempt::Reception::Ready(a) => {
            a.settle(c, status, !row.try_get::<bool, _>("expired").map_err(db)?)
                .await?
        }
    }
    let mut facts = vec![];
    if row.try_get::<bool, _>("expired").map_err(db)? {
        facts.extend(
            channel::abandon_in(c, &p.tenant().to_string(), id_collection, "timeout").await?,
        );
        return Ok(Some(AppleReception::Collection { facts, run: None }));
    }
    if status != protocol::Status::NotNow
        && row.try_get::<String, _>("phase").map_err(db)? == "collect_agent_platform"
    {
        let platform_only:bool=sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM mdm_apple.attempts WHERE tenant_id=$1::uuid AND collection=$2 AND phase='collect_agent')").bind(p.tenant().to_string()).bind(id_collection).fetch_one(&mut *c).await.map_err(db)?;
        if platform_only {
            let saved:serde_json::Value=sqlx::query_scalar("SELECT evidence->'catalogDigest' FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND id=$2").bind(p.tenant().to_string()).bind(id_collection).fetch_one(&mut *c).await.map_err(db)?;
            facts.extend(
                channel::finish_in(
                    c,
                    p,
                    id_collection,
                    ReportSource::MdmApple,
                    AgentInstallation::Unknown,
                    Some(AgentEvidence {
                        catalog_digest: serde_json::from_value(saved)
                            .map_err(|_| Error::Malformed)?,
                        checked_identities: vec![],
                        provisioned: false,
                        identity: String::new(),
                        publisher: None,
                        version: None,
                        architecture: if status == protocol::Status::Acknowledged {
                            wire::architecture(d).ok().map(str::to_owned)
                        } else {
                            None
                        },
                    }),
                )
                .await?,
            );
            return Ok(Some(AppleReception::Collection { facts, run: None }));
        }
    }
    if status == protocol::Status::NotNow
        || row.try_get::<String, _>("phase").map_err(db)? == "collect_agent_platform"
    {
        return Ok(Some(AppleReception::Collection { facts, run: None }));
    }
    let sealed: Vec<u8> = row.try_get("request").map_err(db)?;
    let plain = crate::protection::open(
        protection,
        &p.tenant().to_string(),
        p.registration(),
        p.generation(),
        id,
        crate::protection::Part::Request,
        &sealed,
    )?;
    let request = protocol::decode(plain.expose())?;
    let bundles = request
        .get("Command")
        .and_then(plist::Value::as_dictionary)
        .and_then(|d| d.get("Identifiers"))
        .and_then(plist::Value::as_array)
        .ok_or(Error::Malformed)?
        .iter()
        .map(|v| v.as_string().map(str::to_owned).ok_or(Error::Malformed))
        .collect::<Result<Vec<_>, _>>()?;
    if bundles.is_empty() {
        return Err(Error::Malformed);
    }
    let platform = sqlx::query("SELECT id,response FROM mdm_apple.attempts WHERE tenant_id=$1::uuid AND collection=$2 AND phase='collect_agent_platform'").bind(p.tenant().to_string()).bind(id_collection).fetch_one(&mut *c).await.map_err(db)?;
    let platform = platform
        .try_get::<Option<Vec<u8>>, _>("response")
        .map_err(db)?
        .map(|sealed| {
            crate::protection::open(
                protection,
                &p.tenant().to_string(),
                p.registration(),
                p.generation(),
                platform.try_get("id").map_err(db)?,
                crate::protection::Part::Response,
                &sealed,
            )
        })
        .transpose()?;
    let architecture = platform
        .and_then(|b| protocol::decode(b.expose()).ok())
        .and_then(|d| wire::architecture(&d).ok())
        .map(str::to_owned);
    let mut absent = status == protocol::Status::Acknowledged;
    let mut version = None;
    let mut observed_identity = String::new();
    for bundle in &bundles {
        match wire::presence(d, bundle)
            .ok()
            .filter(|_| status == protocol::Status::Acknowledged)
        {
            Some(wire::Presence::Absent) => (),
            Some(wire::Presence::PresentUnverified { version: v }) => {
                absent = false;
                version = Some(v);
                observed_identity = bundle.clone();
            }
            _ => absent = false,
        }
    }
    let catalog = rss_mdm_execution_service::agent_install::detection_on(
        c,
        p.tenant(),
        ReportSource::MdmApple,
    )
    .await?;
    let saved:serde_json::Value=sqlx::query_scalar("SELECT evidence->'catalogDigest' FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND id=$2").bind(p.tenant().to_string()).bind(id_collection).fetch_one(&mut *c).await.map_err(db)?;
    let catalog_digest: [u8; 32] = serde_json::from_value(saved).map_err(|_| Error::Malformed)?;
    absent &= catalog.complete && catalog_digest == catalog.digest()?;
    let state = if absent {
        AgentInstallation::Absent
    } else {
        AgentInstallation::Unknown
    };
    facts.extend(
        channel::finish_in(
            c,
            p,
            id_collection,
            ReportSource::MdmApple,
            state,
            Some(AgentEvidence {
                catalog_digest,
                provisioned: false,
                checked_identities: bundles,
                identity: observed_identity,
                publisher: None,
                version,
                architecture,
            }),
        )
        .await?,
    );
    Ok(Some(AppleReception::Collection { facts, run: None }))
}
pub async fn send(
    c: &mut PgConnection,
    protection: &rss_mdm_native_protection::Protector,
    p: &DevicePrincipal,
) -> Result<(Vec<u8>, Vec<rss_mdm_audit_integration::Fact>), Error> {
    let catalog = rss_mdm_execution_service::agent_install::detection_on(
        c,
        p.tenant(),
        ReportSource::MdmApple,
    )
    .await?;
    let bundles: std::collections::BTreeSet<_> = catalog
        .identities
        .iter()
        .cloned()
        .filter_map(|i| match i {
            Identity::Macos { bundle, .. } => Some(bundle),
            _ => None,
        })
        .collect();
    let tenant = p.tenant().to_string();
    let allowed:bool=sqlx::query_scalar("SELECT access_rights & $3 = $3 FROM mdm_apple.devices WHERE tenant_id=$1::uuid AND registration=$2 AND state='active'").bind(&tenant).bind(p.registration()).bind(if bundles.is_empty(){16_i64}else{272_i64}).fetch_one(&mut *c).await.map_err(db)?;
    if !allowed {
        return Ok((vec![], vec![]));
    }
    let previous=sqlx::query("SELECT a.collection,a.deadline<=clock_timestamp() AS expired,r.sealed_at FROM mdm_apple.attempts a JOIN mdm_access.collection_runs r ON(r.tenant_id,r.id)=(a.tenant_id,a.collection) WHERE a.tenant_id=$1::uuid AND a.registration=$2 AND a.generation=$3 AND a.phase='collect_agent_platform' ORDER BY a.collection_sequence DESC LIMIT 1 FOR UPDATE OF a")
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
        let (id, _, sequence) =
            channel::start_in(c, p, ReportSource::MdmApple, catalog.digest()?).await?;
        let mut queries = vec![("collect_agent_platform", wire::platform())];
        if let Some(first) = bundles.first() {
            let mut query = wire::query(first)?;
            query.insert(
                "Identifiers".into(),
                plist::Value::Array(bundles.into_iter().map(plist::Value::String).collect()),
            );
            queries.push(("collect_agent", query));
        }
        for (phase, payload) in queries {
            let attempt = Uuid::new_v4();
            let request = protocol::command(attempt, payload)?;
            let request = crate::protection::seal(
                protection,
                &tenant,
                p.registration(),
                p.generation(),
                attempt,
                crate::protection::Part::Request,
                &request,
            )?;
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
    let sealed: Vec<u8> = row.try_get("request").map_err(db)?;
    let plain = crate::protection::open(
        protection,
        &tenant,
        p.registration(),
        p.generation(),
        row.try_get("id").map_err(db)?,
        crate::protection::Part::Request,
        &sealed,
    )?;
    Ok((plain.expose().to_vec(), facts))
}
