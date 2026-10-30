//! Same native registration recovers without replaying an unacknowledged installer.
use super::*;

pub(super) async fn after_activation(
    f: &mut Fixture,
    peer: &lifecycle::Peer,
    registration: Uuid,
    policy: Uuid,
    original: Uuid,
) -> Result<()> {
    use sqlx::{Connection, Row};
    // Initial enrollment proved the dynamic "absent Agent" group. Recovery must
    // remain authorized after native presence removes that group member.
    // Use the normal scope API, retaining the policy and both registrations.
    let (status, current) = f
        .browser
        .call(
            &f.router,
            Method::GET,
            &format!("/api/v1/policies/{policy}"),
            None,
        )
        .await?;
    ensure!(status == StatusCode::OK, "{current}");
    let scope = current["definition"]["scope"].as_str().context("scope")?;
    let path = format!("/api/v1/scopes/{scope}");
    let (status, current) = f.browser.call(&f.router, Method::GET, &path, None).await?;
    ensure!(status == StatusCode::OK, "{current}");
    let (status, updated) = f.browser.call(&f.router, Method::POST, &path, Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":current["revision"],"input":{"action":"put","definition":{"targets":[{"kind":"device","id":case_device()}],"limitations":null,"exclusions":[]}}}))).await?;
    ensure!(status == StatusCode::OK, "{updated}");
    let mut db =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(case_tenant())
        .execute(&mut db)
        .await?;
    // Do not rewrite command deadlines, source coordinates or sealed evidence.
    // Wait for the real attempt deadline and the production five-minute probe
    // interval. Only a new authenticated native reply may authorize recovery.
    let before = diagnosis(f, policy).await?;
    ensure!(
        before["taskAdmission"]["state"] == "installation_pending",
        "{before}"
    );
    let wait: i64 = sqlx::query_scalar("SELECT greatest(0,greatest((SELECT max(sealed_at)+301 FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND registration=$2 AND source='mdm.apple' AND evidence ? 'catalog_digest'),(SELECT deadline/1000000+61 FROM rss_device_command.commands WHERE tenant_id=$1::uuid AND command_id=$3),(SELECT floor(extract(epoch FROM max(coalesce(r.last_communication_received_at,r.first_authenticated_at,g.created_at))))::bigint+301 FROM mdm_access.agent_grants g JOIN mdm_access.registrations r ON(r.tenant_id,r.agent_grant_id)=(g.tenant_id,g.id) WHERE g.tenant_id=$1::uuid AND g.source='native' AND g.native_authority->>'registration'=$2::text AND r.channel='agent' AND r.purpose='primary'))-floor(extract(epoch FROM clock_timestamp()))::bigint)")
        .bind(case_tenant()).bind(registration).bind(original.to_string()).fetch_one(&mut db).await?;
    tokio::time::sleep(Duration::from_secs(wait.try_into()?)).await;
    let before = diagnosis(f, policy).await?;
    ensure!(
        before["taskAdmission"]["state"] == "recovery_observation_pending",
        "old absence authorized a new attempt: {before}"
    );
    let mut next = None;
    let mut refreshed = false;
    let mut idle_conflicts = 0;
    for _ in 0..100 {
        let bytes = match peer.pending_replies.lock().await.pop_front() {
            Some(bytes) => bytes,
            None => {
                let (status, bytes) = peer
                    .send(
                        "/mdm",
                        protocol::dictionary([
                            ("Status", "Idle".into()),
                            (
                                "UDID",
                                crate::test_support::case::name("rss-t2-apple").into(),
                            ),
                        ]),
                    )
                    .await?;
                // Idle has no command receipt. Retrying its transaction conflict
                // cannot replay a native write. Receipt conflicts remain fatal.
                if status == StatusCode::CONFLICT {
                    idle_conflicts += 1;
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    continue;
                }
                ensure!(status == StatusCode::OK, "recovery Idle: {status}");
                bytes
            }
        };
        if bytes.is_empty() {
            tokio::time::sleep(Duration::from_millis(300)).await;
            continue;
        }
        let dictionary = protocol::decode(&bytes)?;
        let id = Uuid::parse_str(protocol::text(&dictionary, "CommandUUID")?)?;
        let payload = dictionary["Command"]
            .as_dictionary()
            .context("native command")?;
        let kind = protocol::text(payload, "RequestType")?;
        if kind == "InstallEnterpriseApplication" {
            let operation = payload["Configuration"]
                .as_dictionary()
                .context("configuration")?["RSSInstallationOperation"]
                .as_string()
                .context("installation")?;
            let operation = Uuid::parse_str(operation)?;
            ensure!(
                refreshed && operation != original,
                "recovery replayed the old installer or used stale absence"
            );
            next = Some(operation);
            break;
        }
        ensure!(
            kind != "InstallProfile",
            "repair with a retained active Agent identity created another bootstrap identity"
        );
        let value = match kind {
            "DeviceInformation" => Some((
                "QueryResponses",
                protocol::dictionary([
                    ("OSVersion", "15.0".into()),
                    ("IsSupervised", true.into()),
                    ("IsAppleSilicon", true.into()),
                ])
                .into(),
            )),
            "InstalledApplicationList" => {
                refreshed = true;
                // Real macOS reports retained upgrade copies under the same bundle ID.
                // Presence stays unverified and the current version is ambiguous, but
                // the already bound, unresponsive Agent must still be repairable.
                Some((
                    "InstalledApplicationList",
                    plist::Value::Array(
                        ["1.2.2", "1.2.3"]
                            .into_iter()
                            .map(|version| {
                                protocol::dictionary([
                                    ("Identifier", "com.rss.agent".into()),
                                    ("Version", version.into()),
                                    ("Installing", false.into()),
                                ])
                                .into()
                            })
                            .collect(),
                    ),
                ))
            }
            "ProfileList" => Some(("ProfileList", plist::Value::Array(vec![]))),
            "RemoveProfile" => None,
            "SecurityInfo" => Some((
                "SecurityInfo",
                protocol::dictionary([(
                    "ManagementStatus",
                    protocol::dictionary([
                        ("EnrolledViaDEP", false.into()),
                        ("UserApprovedEnrollment", true.into()),
                        ("IsUserEnrollment", false.into()),
                    ])
                    .into(),
                )])
                .into(),
            )),
            _ => anyhow::bail!("unexpected recovery prerequisite {kind}"),
        };
        let bytes = peer.manage("Acknowledged", Some(id), value).await?;
        if !bytes.is_empty() {
            peer.pending_replies.lock().await.push_back(bytes);
        }
    }
    let next =
        next.context("fresh retained-bundle presence did not repair the bound unresponsive Agent")?;
    eprintln!("recovery confirmed after {idle_conflicts} Idle transaction conflicts");
    let rows=sqlx::query("SELECT o.id,o.registration,count(b.id) AS bootstraps FROM mdm_commands.operations o LEFT JOIN mdm_access.agent_bootstraps b ON(b.tenant_id,b.installation)=(o.tenant_id,o.id) WHERE o.tenant_id=$1::uuid AND o.registration=$2 AND o.authority->>'kind'='agent_install' AND o.authority->>'stage'='install' GROUP BY o.id,o.registration")
        .bind(case_tenant()).bind(registration).fetch_all(&mut db).await?;
    ensure!(
        rows.len() == 2,
        "recovery produced {} installers",
        rows.len()
    );
    ensure!(rows.iter().any(|row| row.get::<Uuid, _>("id") == next
        && row.get::<Uuid, _>("registration") == registration
        && row.get::<i64, _>("bootstraps") == 0));
    ensure!(
        f.operation(original).await?["agentInstallation"]["installation"] == "unknown",
        "recovery rewrote the old Unknown result"
    );
    let state = diagnosis(f, policy).await?;
    ensure!(
        state["taskAdmission"]["state"] == "installation_pending",
        "{state}"
    );
    db.close().await?;
    Ok(())
}

// Assignment cursors bind the asset projection; bootstrap cleanup can publish
// another revision while this read is in flight. Retry only that documented 409.
async fn diagnosis(f: &mut Fixture, policy: Uuid) -> Result<serde_json::Value> {
    for retry in 0..100 {
        let (status, value) = f
            .browser
            .call(
                &f.router,
                Method::GET,
                &format!("/api/v1/policies/{policy}/assignments"),
                None,
            )
            .await?;
        if status == StatusCode::CONFLICT && retry < 99 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        }
        ensure!(
            status == StatusCode::OK,
            "recovery assignments: {status}: {value}"
        );
        return value["items"]
            .as_array()
            .context("assignment items")?
            .iter()
            .find(|i| {
                i["target"]["device"] == case_device()
                    || (i["object"]["kind"] == "endpoint" && i["object"]["id"] == case_device())
            })
            .cloned()
            .context("missing recovery diagnosis");
    }
    anyhow::bail!("recovery diagnosis exceeded its retry bound")
}
