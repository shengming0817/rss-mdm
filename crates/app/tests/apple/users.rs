//! User GUIDs are scoped protocol coordinates under one device certificate, never accounts.
use super::*;
use lifecycle::{Peer, command};
use sqlx::{Connection, Row};
impl Peer {
    async fn user_token(&self, user: Uuid, value: u8) -> Result<()> {
        let response = self
            .send(
                "/checkin",
                protocol::dictionary([
                    ("MessageType", "TokenUpdate".into()),
                    (
                        "UDID",
                        crate::test_support::case::name("rss-t2-apple").into(),
                    ),
                    ("UserID", user.to_string().into()),
                    ("Topic", self.topic.clone().into()),
                    ("Token", plist::Value::Data(vec![value; 32])),
                    ("PushMagic", "user-magic".into()),
                ]),
            )
            .await?;
        ensure!(response.0 == StatusCode::OK, "user token {}", response.0);
        Ok(())
    }
    async fn user_manage(
        &self,
        user: Uuid,
        status: &str,
        id: Option<Uuid>,
        extra: Option<(&str, plist::Value)>,
    ) -> Result<(StatusCode, Vec<u8>)> {
        let mut body = protocol::dictionary([
            (
                "UDID",
                crate::test_support::case::name("rss-t2-apple").into(),
            ),
            ("UserID", user.to_string().into()),
            ("Status", status.into()),
        ]);
        if let Some(id) = id {
            body.insert("CommandUUID".into(), id.to_string().into());
        }
        if let Some((key, value)) = extra {
            body.insert(key.into(), value);
        }
        self.send("/mdm", body).await
    }
}
#[tokio::test]
#[ignore = "MODULE=apple.users: real mTLS user scope and APNs lease isolation"]
async fn user_commands_push_and_retirement_are_scoped() -> Result<()> {
    let mut f = Fixture::start().await?;
    let (peer, device) = f.ready_local_peer().await?;
    let user = Uuid::new_v4();
    let other = Uuid::new_v4();
    let auth = peer
        .send(
            "/checkin",
            protocol::dictionary([
                ("MessageType", "UserAuthenticate".into()),
                (
                    "UDID",
                    crate::test_support::case::name("rss-t2-apple").into(),
                ),
                ("UserID", user.to_string().into()),
            ]),
        )
        .await?;
    ensure!(
        auth.0 == StatusCode::OK
            && protocol::decode(&auth.1)?["DigestChallenge"].as_string() == Some("")
    );
    peer.user_token(user, 43).await?;
    peer.user_token(other, 44).await?;
    let id = Uuid::new_v4();
    let path = format!("/api/v3/devices/{}/operations", case_device());
    let task = json!({"platform":"macos","request":{"kind":"command","command":{"requestType":"InstalledApplicationList","fields":{}}}});
    let reply=f.browser.call(&f.router,Method::POST,&path,Some(json!({"operationId":id,"inputVersion":"user-v1","target":{"kind":"user","userId":user.to_string()},"task":task,"deadline":f.app.clock.unix_seconds()?+300}))).await?;
    ensure!(reply.0 == StatusCode::ACCEPTED, "user operation {reply:?}");
    for _ in 0..100 {
        if f.operation(id).await?["commandStatus"] == "published" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let (resolve, _) = peer.next("DeviceInformation").await?;
    let bytes = peer
        .manage(
            "Acknowledged",
            Some(resolve),
            Some((
                "QueryResponses",
                plist::Value::Dictionary(protocol::dictionary([
                    ("OSVersion", "15.0".into()),
                    ("IsSupervised", true.into()),
                    ("IsAppleSilicon", true.into()),
                ])),
            )),
        )
        .await?;
    let (security, _) = command(&bytes, "SecurityInfo")?;
    let bytes = peer
        .manage(
            "Acknowledged",
            Some(security),
            Some((
                "SecurityInfo",
                plist::Value::Dictionary(protocol::dictionary([(
                    "ManagementStatus",
                    plist::Value::Dictionary(protocol::dictionary([
                        ("EnrolledViaDEP", false.into()),
                        ("IsUserEnrollment", false.into()),
                        ("UserApprovedEnrollment", true.into()),
                    ])),
                )])),
            )),
        )
        .await?;
    ensure!(bytes.is_empty(), "user command escaped into device channel");
    let configuration = f.app.apple()?.channel.push_fixture().configuration;
    let wake = f
        .app
        .execution
        .apple_wake(&configuration)
        .await?
        .ok_or_else(|| anyhow::anyhow!("missing user wake"))?;
    ensure!(
        wake.user_key == user.to_string() && wake.token == vec![43; 32],
        "push selected another scope"
    );
    f.app
        .execution
        .apple_pushed(
            &wake,
            Some(410),
            rss_mdm_execution_service::channels::PushOutcome::Unregistered,
        )
        .await?;
    ensure!(
        peer.manage("Idle", None, None).await?.is_empty(),
        "user 410 broke device channel"
    );
    peer.user_token(user, 43).await?;

    ensure!(
        peer.user_manage(other, "Idle", None, None)
            .await?
            .1
            .is_empty()
    );
    let response = peer.user_manage(user, "Idle", None, None).await?;
    ensure!(response.0 == StatusCode::OK);
    let (execute, _) = command(&response.1, "InstalledApplicationList")?;
    ensure!(
        peer.user_manage(
            other,
            "Acknowledged",
            Some(execute),
            Some(("InstalledApplicationList", plist::Value::Array(vec![])))
        )
        .await?
        .0 == StatusCode::CONFLICT
    );
    peer.user_manage(
        user,
        "Acknowledged",
        Some(execute),
        Some(("InstalledApplicationList", plist::Value::Array(vec![]))),
    )
    .await?;
    ensure!(f.operation(id).await?["commandStatus"] == "applied");
    let mut pg =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    let rows=sqlx::query("SELECT user_key,material,token_revision FROM mdm_apple.channels WHERE tenant_id=$1::uuid AND state='active' ORDER BY user_key").bind(case_tenant()).fetch_all(&mut pg).await?;
    ensure!(rows.len() == 3);
    for row in &rows {
        let sealed: Vec<u8> = row.try_get("material")?;
        ensure!(
            protocol::decode(&sealed).is_err()
                && !sealed.windows(10).any(|bytes| bytes == b"user-magic")
        );
    }
    peer.user_token(user, 43).await?;
    let revision: i64 = sqlx::query_scalar(
        "SELECT token_revision FROM mdm_apple.channels WHERE tenant_id=$1::uuid AND user_key=$2",
    )
    .bind(case_tenant())
    .bind(user.to_string())
    .fetch_one(&mut pg)
    .await?;
    ensure!(revision == 2, "identical token update changed revision");
    let checkout = peer
        .send(
            "/checkin",
            protocol::dictionary([
                ("MessageType", "CheckOut".into()),
                (
                    "UDID",
                    crate::test_support::case::name("rss-t2-apple").into(),
                ),
            ]),
        )
        .await?;
    ensure!(checkout.0 == StatusCode::OK);
    let active:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_apple.channels WHERE tenant_id=$1::uuid AND (state<>'retired' OR material IS NOT NULL)").bind(case_tenant()).fetch_one(&mut pg).await?;
    ensure!(active == 0);
    pg.close().await?;
    drop(device);
    f.close().await
}

#[tokio::test]
#[ignore = "MODULE=apple.users: Bootstrap Token escrow over real mTLS and PG"]
async fn bootstrap_escrow_requires_evidence_and_clears_secrets() -> Result<()> {
    let mut f = Fixture::start().await?;
    f.grant_native_actions(&["device_control"]).await?;
    let (peer, device) = f.ready_local_peer().await?;
    let get = protocol::dictionary([
        ("MessageType", "GetBootstrapToken".into()),
        (
            "UDID",
            crate::test_support::case::name("rss-t2-apple").into(),
        ),
    ]);
    ensure!(peer.send("/checkin", get.clone()).await?.0 == StatusCode::NOT_IMPLEMENTED);
    let op=f.create_operation(|_|json!({"platform":"macos","request":{"kind":"command","command":{"requestType":"RestartDevice","fields":{}}}})).await?;
    let (resolve, _) = peer.next("DeviceInformation").await?;
    let next = peer
        .manage(
            "Acknowledged",
            Some(resolve),
            Some((
                "QueryResponses",
                plist::Value::Dictionary(protocol::dictionary([
                    ("OSVersion", "15.0".into()),
                    ("IsSupervised", true.into()),
                    ("IsAppleSilicon", true.into()),
                ])),
            )),
        )
        .await?;
    let (resolve, _) = command(&next, "SecurityInfo")?;
    let next = peer
        .manage(
            "Acknowledged",
            Some(resolve),
            Some((
                "SecurityInfo",
                plist::Value::Dictionary(protocol::dictionary([(
                    "ManagementStatus",
                    plist::Value::Dictionary(protocol::dictionary([
                        ("EnrolledViaDEP", true.into()),
                        ("IsUserEnrollment", false.into()),
                        ("UserApprovedEnrollment", true.into()),
                    ])),
                )])),
            )),
        )
        .await?;
    let (execute, _) = command(&next, "RestartDevice")?;
    peer.manage("Acknowledged", Some(execute), None).await?;
    ensure!(f.operation(op).await?["commandStatus"] == "received");
    let empty = peer.send("/checkin", get.clone()).await?;
    ensure!(
        empty.0 == StatusCode::OK && !protocol::decode(&empty.1)?.contains_key("BootstrapToken")
    );
    let secret = vec![97u8; 64];
    let mut set = protocol::dictionary([
        ("MessageType", "SetBootstrapToken".into()),
        (
            "UDID",
            crate::test_support::case::name("rss-t2-apple").into(),
        ),
        ("BootstrapToken", plist::Value::Data(secret.clone())),
    ]);
    ensure!(peer.send("/checkin", set.clone()).await?.0 == StatusCode::OK);
    let response = peer.send("/checkin", get.clone()).await?;
    ensure!(
        response.0 == StatusCode::OK
            && protocol::decode(&response.1)?["BootstrapToken"].as_data()
                == Some(secret.as_slice())
    );
    let mut pg =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    let sealed: Vec<u8> = sqlx::query_scalar(
        "SELECT bootstrap FROM mdm_apple.devices WHERE tenant_id=$1::uuid AND state='active'",
    )
    .bind(case_tenant())
    .fetch_one(&mut pg)
    .await?;
    ensure!(
        !sealed
            .windows(secret.len())
            .any(|bytes| bytes == secret.as_slice())
    );
    set.insert("BootstrapToken".into(), plist::Value::Data(vec![]));
    ensure!(peer.send("/checkin", set).await?.0 == StatusCode::OK);
    let response = peer.send("/checkin", get).await?;
    ensure!(
        response.0 == StatusCode::OK
            && !protocol::decode(&response.1)?.contains_key("BootstrapToken")
    );
    let stored: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT bootstrap FROM mdm_apple.devices WHERE tenant_id=$1::uuid AND state='active'",
    )
    .bind(case_tenant())
    .fetch_one(&mut pg)
    .await?;
    ensure!(stored.is_none());
    pg.close().await?;
    drop(device);
    f.close().await
}

async fn user_operation(f: &mut Fixture, user: Uuid, task: serde_json::Value) -> Result<Uuid> {
    let id = Uuid::new_v4();
    let path = format!("/api/v3/devices/{}/operations", case_device());
    let reply=f.browser.call(&f.router,Method::POST,&path,Some(json!({"operationId":id,"inputVersion":"user-v1","target":{"kind":"user","userId":user.to_string()},"task":task,"deadline":f.app.clock.unix_seconds()?+300}))).await?;
    ensure!(reply.0 == StatusCode::ACCEPTED, "user operation {reply:?}");
    for _ in 0..100 {
        if f.operation(id).await?["commandStatus"] == "published" {
            return Ok(id);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    anyhow::bail!("user publication deadline")
}
async fn resolve_user(peer: &Peer) -> Result<()> {
    let (id, _) = peer.next("DeviceInformation").await?;
    let next = peer
        .manage(
            "Acknowledged",
            Some(id),
            Some((
                "QueryResponses",
                plist::Value::Dictionary(protocol::dictionary([
                    ("OSVersion", "15.0".into()),
                    ("IsSupervised", true.into()),
                    ("IsAppleSilicon", true.into()),
                ])),
            )),
        )
        .await?;
    let (id, _) = command(&next, "SecurityInfo")?;
    let next = peer
        .manage(
            "Acknowledged",
            Some(id),
            Some((
                "SecurityInfo",
                plist::Value::Dictionary(protocol::dictionary([(
                    "ManagementStatus",
                    plist::Value::Dictionary(protocol::dictionary([
                        ("EnrolledViaDEP", false.into()),
                        ("IsUserEnrollment", false.into()),
                        ("UserApprovedEnrollment", true.into()),
                    ])),
                )])),
            )),
        )
        .await?;
    ensure!(next.is_empty(), "user mutation dispatched to device");
    Ok(())
}
#[tokio::test]
#[ignore = "MODULE=apple.users: Profile scope and complete manifests over real mTLS and PG"]
async fn same_profile_identifier_has_independent_user_and_device_ownership() -> Result<()> {
    let mut f = Fixture::start().await?;
    let (peer, device) = f.ready_local_peer().await?;
    let user = Uuid::new_v4();
    peer.user_token(user, 45).await?;
    let dock = |id| {
        let mut task = profile_task(id, true);
        task["request"]["profile"]["payloads"][0]["schema"] =
            json!("mdm/profiles/com.apple.dock.yaml");
        task["request"]["profile"]["payloads"][0]["fields"] =
            json!({"autohide":{"type":"boolean","value":true}});
        task
    };
    let device_profile = f.create_operation(dock).await?;
    let (execute, _) = peer.next("InstallProfile").await?;
    let next = peer.manage("Acknowledged", Some(execute), None).await?;
    let (observe, _) = command(&next, "ProfileList")?;
    peer.manage(
        "Acknowledged",
        Some(observe),
        Some((
            "ProfileList",
            profile_manifest(device_profile, "com.apple.dock"),
        )),
    )
    .await?;
    ensure!(f.operation(device_profile).await?["commandStatus"] == "applied");
    let user_profile = Uuid::new_v4();
    let installed = user_operation(&mut f, user, dock(user_profile)).await?;
    resolve_user(&peer).await?;
    let next = peer.user_manage(user, "Idle", None, None).await?;
    ensure!(next.0 == StatusCode::OK);
    let (execute, _) = command(&next.1, "InstallProfile")?;
    let next = peer
        .user_manage(user, "Acknowledged", Some(execute), None)
        .await?;
    let (observe, _) = command(&next.1, "ProfileList")?;
    let forged = peer
        .send(
            "/mdm",
            protocol::dictionary([
                (
                    "UDID",
                    crate::test_support::case::name("rss-t2-apple").into(),
                ),
                ("Status", "Acknowledged".into()),
                ("CommandUUID", observe.to_string().into()),
                (
                    "ProfileList",
                    profile_manifest(user_profile, "com.apple.dock"),
                ),
            ]),
        )
        .await?;
    ensure!(
        forged.0 == StatusCode::CONFLICT,
        "cross-scope manifest accepted"
    );
    peer.user_manage(
        user,
        "Acknowledged",
        Some(observe),
        Some((
            "ProfileList",
            profile_manifest(user_profile, "com.apple.dock"),
        )),
    )
    .await?;
    ensure!(f.operation(installed).await?["commandStatus"] == "applied");
    let removed = user_operation(&mut f, user, remove_profile_task(user_profile)).await?;
    resolve_user(&peer).await?;
    let next = peer.user_manage(user, "Idle", None, None).await?;
    let (execute, _) = command(&next.1, "RemoveProfile")?;
    let next = peer
        .user_manage(user, "Acknowledged", Some(execute), None)
        .await?;
    let (observe, _) = command(&next.1, "ProfileList")?;
    peer.user_manage(
        user,
        "Acknowledged",
        Some(observe),
        Some(("ProfileList", plist::Value::Array(vec![]))),
    )
    .await?;
    ensure!(f.operation(removed).await?["commandStatus"] == "applied");
    let mut pg =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    let present:bool=sqlx::query_scalar("SELECT present AND retired_at IS NULL FROM mdm_apple.profiles WHERE tenant_id=$1::uuid AND operation=$2").bind(case_tenant()).bind(device_profile).fetch_one(&mut pg).await?;
    ensure!(present, "user removal retired device profile");
    pg.close().await?;
    drop(device);
    f.close().await
}

#[tokio::test]
#[ignore = "MODULE=apple.users: another scope cannot truncate user dispatch or APNs pending scan"]
async fn user_queue_survives_a_full_page_of_received_device_commands() -> Result<()> {
    let mut f = Fixture::start().await?;
    f.grant_native_actions(&["device_control"]).await?;
    let (peer, device) = f.ready_local_peer().await?;
    let user = Uuid::new_v4();
    peer.user_token(user, 46).await?;
    for ordinal in 0..64 {
        let op = f.create_operation_at(Uuid::from_u128(1000+ordinal), |_|json!({"platform":"macos","request":{"kind":"command","command":{"requestType":"RestartDevice","fields":{}}}})).await?;
        let (id, _) = peer.next("RestartDevice").await?;
        peer.manage("Acknowledged", Some(id), None).await?;
        ensure!(f.operation(op).await?["commandStatus"] == "received");
    }
    let op = user_operation(&mut f,user,json!({"platform":"macos","request":{"kind":"command","command":{"requestType":"InstalledApplicationList","fields":{}}}})).await?;
    resolve_user(&peer).await?;
    let mut pg =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    // Keep the already acknowledged device scope out of this push observation window.
    sqlx::query("UPDATE mdm_apple.channels SET next_push=clock_timestamp()+interval '1 hour' WHERE tenant_id=$1::uuid AND user_key=''").bind(case_tenant()).execute(&mut pg).await?;
    pg.close().await?;
    let configuration = f.app.apple()?.channel.push_fixture().configuration;
    let wake = f
        .app
        .execution
        .apple_wake(&configuration)
        .await?
        .ok_or_else(|| anyhow::anyhow!("missing user wake after device page"))?;
    ensure!(wake.user_key == user.to_string());
    let next = peer.user_manage(user, "Idle", None, None).await?;
    let (execute, _) = command(&next.1, "InstalledApplicationList")?;
    peer.user_manage(
        user,
        "Acknowledged",
        Some(execute),
        Some(("InstalledApplicationList", plist::Value::Array(vec![]))),
    )
    .await?;
    ensure!(f.operation(op).await?["commandStatus"] == "applied");
    drop(device);
    f.close().await
}

#[tokio::test]
#[ignore = "MODULE=apple.users: device APNs 410 cannot revoke an active user protocol channel"]
async fn device_push_invalidation_preserves_user_idle_and_receipts() -> Result<()> {
    let mut f = Fixture::start().await?;
    let (peer, device) = f.ready_local_peer().await?;
    let user = Uuid::new_v4();
    peer.user_token(user, 47).await?;
    let profile = Uuid::new_v4();
    let mut dock = profile_task(profile, true);
    dock["request"]["profile"]["payloads"][0]["schema"] = json!("mdm/profiles/com.apple.dock.yaml");
    dock["request"]["profile"]["payloads"][0]["fields"] =
        json!({"autohide":{"type":"boolean","value":true}});
    let operation = user_operation(&mut f, user, dock).await?;
    resolve_user(&peer).await?;
    let next = peer.user_manage(user, "Idle", None, None).await?;
    let (execute, _) = command(&next.1, "InstallProfile")?;
    let next = peer
        .user_manage(user, "Acknowledged", Some(execute), None)
        .await?;
    let (observe, _) = command(&next.1, "ProfileList")?;
    let device_operation = f.create_operation(|_| json!({"platform":"macos","request":{"kind":"command","command":{"requestType":"InstalledApplicationList","fields":{}}}})).await?;
    let configuration = f.app.apple()?.channel.push_fixture().configuration;
    let mut wake = f
        .app
        .execution
        .apple_wake(&configuration)
        .await?
        .ok_or_else(|| anyhow::anyhow!("missing pending wake"))?;
    if !wake.user_key.is_empty() {
        ensure!(wake.user_key == user.to_string());
        f.app
            .execution
            .apple_pushed(
                &wake,
                Some(200),
                rss_mdm_execution_service::channels::PushOutcome::Accepted,
            )
            .await?;
        wake = f
            .app
            .execution
            .apple_wake(&configuration)
            .await?
            .ok_or_else(|| anyhow::anyhow!("missing device wake"))?;
    }
    ensure!(wake.user_key.is_empty());
    f.app
        .execution
        .apple_pushed(
            &wake,
            Some(410),
            rss_mdm_execution_service::channels::PushOutcome::Unregistered,
        )
        .await?;
    ensure!(peer.user_manage(user, "Idle", None, None).await?.0 == StatusCode::OK);
    let reply = peer
        .user_manage(
            user,
            "Acknowledged",
            Some(observe),
            Some(("ProfileList", profile_manifest(profile, "com.apple.dock"))),
        )
        .await?;
    ensure!(
        reply.0 == StatusCode::OK && f.operation(operation).await?["commandStatus"] == "applied"
    );
    let idle = protocol::dictionary([
        (
            "UDID",
            crate::test_support::case::name("rss-t2-apple").into(),
        ),
        ("Status", "Idle".into()),
    ]);
    ensure!(peer.send("/mdm", idle).await?.0 == StatusCode::UNAUTHORIZED);
    peer.token_value(48).await?;
    let (execute, _) = peer.next("InstalledApplicationList").await?;
    peer.manage(
        "Acknowledged",
        Some(execute),
        Some(("InstalledApplicationList", plist::Value::Array(vec![]))),
    )
    .await?;
    ensure!(f.operation(device_operation).await?["commandStatus"] == "applied");
    drop(device);
    f.close().await
}

#[tokio::test]
#[ignore = "MODULE=apple.users: corrupt encrypted material is isolated from healthy push candidates"]
async fn corrupt_user_material_does_not_block_healthy_device_push() -> Result<()> {
    async fn token_for_push(peer: &Peer, user: Uuid) -> Result<()> {
        let reply = peer
            .send(
                "/checkin",
                protocol::dictionary([
                    ("MessageType", "TokenUpdate".into()),
                    (
                        "UDID",
                        crate::test_support::case::name("rss-t2-apple").into(),
                    ),
                    ("UserID", user.to_string().into()),
                    ("Topic", peer.topic.clone().into()),
                    ("Token", plist::Value::Data(vec![48; 32])),
                    ("PushMagic", "fixture-magic".into()),
                ]),
            )
            .await?;
        ensure!(reply.0 == StatusCode::OK);
        Ok(())
    }
    let mut f = Fixture::start().await?;
    let (peer, device) = f.ready_local_peer().await?;
    let user = Uuid::new_v4();
    token_for_push(&peer, user).await?;
    let operation = f.create_operation(|_| json!({"platform":"macos","request":{"kind":"command","command":{"requestType":"InstalledApplicationList","fields":{}}}})).await?;
    let mut pg =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    sqlx::query("UPDATE mdm_apple.channels SET material=set_byte(material,octet_length(material)-1,get_byte(material,octet_length(material)-1)#1),next_push=clock_timestamp()-interval '2 seconds' WHERE tenant_id=$1::uuid AND user_key=$2")
        .bind(case_tenant()).bind(user.to_string()).execute(&mut pg).await?;
    sqlx::query("UPDATE mdm_apple.channels SET next_push=clock_timestamp()-interval '1 second' WHERE tenant_id=$1::uuid AND user_key=''")
        .bind(case_tenant()).execute(&mut pg).await?;
    let participant =
        crate::apple::push::test_support::Participant::start(vec![200], vec![42; 32]).await?;
    rss_mdm_apple_channel::push::wake(&participant.push, &f.app.execution).await?;
    let bad: (String, Option<Uuid>, Option<String>) = sqlx::query_as("SELECT state,push_id,push_outcome FROM mdm_apple.channels WHERE tenant_id=$1::uuid AND user_key=$2")
        .bind(case_tenant()).bind(user.to_string()).fetch_one(&mut pg).await?;
    ensure!(
        bad == ("pending_token".into(), None, Some("rejected".into())),
        "bad material not isolated {bad:?}"
    );
    let healthy: String = sqlx::query_scalar(
        "SELECT push_outcome FROM mdm_apple.channels WHERE tenant_id=$1::uuid AND user_key=''",
    )
    .bind(case_tenant())
    .fetch_one(&mut pg)
    .await?;
    ensure!(healthy == "accepted");
    participant.close().await?;
    ensure!(f.operation(operation).await?["commandStatus"] == "published");
    let (execute, _) = peer.next("InstalledApplicationList").await?;
    peer.manage(
        "Acknowledged",
        Some(execute),
        Some(("InstalledApplicationList", plist::Value::Array(vec![]))),
    )
    .await?;
    ensure!(f.operation(operation).await?["commandStatus"] == "applied");
    token_for_push(&peer, user).await?;
    let recovered: (String,i64,Option<String>) = sqlx::query_as("SELECT state,token_revision,push_outcome FROM mdm_apple.channels WHERE tenant_id=$1::uuid AND user_key=$2")
        .bind(case_tenant()).bind(user.to_string()).fetch_one(&mut pg).await?;
    ensure!(recovered == ("active".into(), 2, None));
    let _user_op = user_operation(&mut f,user,json!({"platform":"macos","request":{"kind":"command","command":{"requestType":"InstalledApplicationList","fields":{}}}})).await?;
    resolve_user(&peer).await?;
    sqlx::query("UPDATE mdm_apple.channels SET next_push=clock_timestamp()+interval '1 hour' WHERE tenant_id=$1::uuid AND user_key=''").bind(case_tenant()).execute(&mut pg).await?;
    let participant =
        crate::apple::push::test_support::Participant::start(vec![200], vec![48; 32]).await?;
    rss_mdm_apple_channel::push::wake(&participant.push, &f.app.execution).await?;
    let recovered: String = sqlx::query_scalar(
        "SELECT push_outcome FROM mdm_apple.channels WHERE tenant_id=$1::uuid AND user_key=$2",
    )
    .bind(case_tenant())
    .bind(user.to_string())
    .fetch_one(&mut pg)
    .await?;
    ensure!(recovered == "accepted");
    participant.close().await?;
    pg.close().await?;
    drop(device);
    f.close().await
}
