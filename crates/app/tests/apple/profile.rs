use super::*;
use lifecycle::{Peer, command};
use sqlx::Connection;
impl Fixture {
    pub async fn profile_cycle(&mut self, peer: &Peer) -> Result<()> {
        let installed = self
            .create_operation(|id| {
                let mut input = profile_task(id, true);
                input["request"]["profile"]["metadata"] =
                    json!({"PayloadDescription":{"type":"string","value":"界".repeat(7000)}});
                input
            })
            .await?;
        let request = peer.next_bytes("InstallProfile").await?;
        let (execute, payload) = command(&request, "InstallProfile")?;
        ensure!(payload["Payload"].as_data().is_some());
        ensure!(self.operation(installed).await?["commandStatus"] == "published");
        ensure!(peer.manage("NotNow", Some(execute), None).await?.is_empty());
        ensure!(self.operation(installed).await?["commandStatus"] == "published");
        let mut pg =
            sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
                .await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
            .bind(case_tenant())
            .execute(&mut pg)
            .await?;
        sqlx::query("UPDATE mdm_apple.attempts SET next_attempt=clock_timestamp()-interval '1 second' WHERE id=$1::uuid").bind(execute.to_string()).execute(&mut pg).await?;
        let sealed: Vec<u8> =
            sqlx::query_scalar("SELECT request FROM mdm_apple.attempts WHERE id=$1::uuid")
                .bind(execute.to_string())
                .fetch_one(&mut pg)
                .await?;
        ensure!(
            protocol::decode(&sealed).is_err(),
            "Apple attempt request remained plaintext"
        );
        let stored: Vec<Vec<u8>> = sqlx::query_scalar("SELECT request FROM mdm_apple.attempts WHERE tenant_id=$1::uuid UNION ALL SELECT response FROM mdm_apple.attempts WHERE tenant_id=$1::uuid AND response IS NOT NULL").bind(case_tenant()).fetch_all(&mut pg).await?;
        for value in stored {
            ensure!(
                protocol::decode(&value).is_err(),
                "Apple native attempt remained plaintext"
            );
        }
        pg.close().await?;
        let retried = peer.manage("Idle", None, None).await?;
        ensure!(
            retried == request && command(&retried, "InstallProfile")?.0 == execute,
            "NotNow retry changed UUID or bytes"
        );
        let bytes = peer.manage("Acknowledged", Some(execute), None).await?;
        let (observe, _) = command(&bytes, "ProfileList")?;
        ensure!(self.operation(installed).await?["commandStatus"] == "received");
        let profiles = profile_manifest(installed, "com.apple.security.firewall");
        ensure!(
            peer.manage(
                "Acknowledged",
                Some(observe),
                Some(("ProfileList", profiles.clone()))
            )
            .await?
            .is_empty()
        );
        ensure!(
            peer.manage(
                "Acknowledged",
                Some(observe),
                Some(("ProfileList", profiles))
            )
            .await?
            .is_empty()
        );
        let read = self.operation(installed).await?;
        ensure!(
            read["commandStatus"] == "applied"
                && read["observation"]["result"] == "matched"
                && read["observation"]["effect"] == "unknown",
            "profile presence receipt {read}"
        );
        ensure!(
            read["observation"]["receipts"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r.get("fields").is_some()),
            "authorized native Profile fields missing"
        );
        for permissions in [
            vec!["operation_read"],
            vec!["operation_read", "configuration_write"],
            vec!["operation_read", "inventory_collect"],
        ] {
            crate::test_support::identity::set_grants(
                case_tenant(),
                crate::test_support::case::admin(),
                crate::test_support::identity::device_grants(Some(case_device()), &permissions)?,
            )
            .await?;
            let limited = self.operation(installed).await?;
            ensure!(
                limited["observation"]["result"] == "matched",
                "limited Profile assessment lost"
            );
            ensure!(
                limited["observation"]["receipts"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|r| r.get("fields").is_none()),
                "limited reader obtained native ProfileList"
            );
        }
        self.grant_native_actions(&[]).await?;
        let removed = self
            .create_operation(|_| remove_profile_task(installed))
            .await?;
        let (execute, payload) = peer.next("RemoveProfile").await?;
        ensure!(payload["Identifier"].as_string() == Some(native_profile()));
        let bytes = peer.manage("Acknowledged", Some(execute), None).await?;
        let (observe, _) = command(&bytes, "ProfileList")?;
        ensure!(self.operation(removed).await?["commandStatus"] == "received");
        peer.manage(
            "Acknowledged",
            Some(observe),
            Some(("ProfileList", plist::Value::Array(vec![]))),
        )
        .await?;
        ensure!(self.operation(removed).await?["commandStatus"] == "applied");
        Ok(())
    }
    pub(super) async fn profile_mismatch(&mut self, peer: &Peer) -> Result<()> {
        let op = self.create_operation(|id| profile_task(id, true)).await?;
        let (id, _) = peer.next("InstallProfile").await?;
        let wrong = peer
            .send(
                "/mdm",
                protocol::dictionary([
                    ("Status", "Acknowledged".into()),
                    (
                        "UDID",
                        crate::test_support::case::name("rss-t2-apple").into(),
                    ),
                    ("CommandUUID", Uuid::new_v4().to_string().into()),
                ]),
            )
            .await?;
        ensure!(wrong.0 == StatusCode::CONFLICT);
        let next = peer.manage("Acknowledged", Some(id), None).await?;
        let (observe, _) = command(&next, "ProfileList")?;
        let wrong = plist::Value::Array(vec![plist::Value::Dictionary(protocol::dictionary([
            ("PayloadIdentifier", native_profile().into()),
            ("PayloadUUID", Uuid::new_v4().to_string().into()),
        ]))]);
        peer.manage("Acknowledged", Some(observe), Some(("ProfileList", wrong)))
            .await?;
        let state = self.operation(op).await?;
        ensure!(
            state["commandStatus"] == "received" && state["observation"]["result"] == "mismatched",
            "mismatch became Applied {state}"
        );
        let path = format!(
            "/api/v3/devices/{DEVICE}/operations",
            DEVICE = case_device()
        );
        let overlap=self.browser.call(&self.router,Method::POST,&path,Some(json!({"operationId":Uuid::new_v4(),"inputVersion":"1","target":{"kind":"device"},"task":profile_task(Uuid::new_v4(),false),"deadline":self.app.clock.unix_seconds()?+300}))).await?;
        ensure!(
            overlap.0 == StatusCode::CONFLICT,
            "overlapping profile ownership admitted"
        );
        let cancelled = self
            .browser
            .call(
                &self.router,
                Method::POST,
                &format!("{path}/{op}/cancel"),
                Some(json!({"requestId":Uuid::new_v4(),"expectedRevision":state["revision"]})),
            )
            .await?;
        ensure!(
            cancelled.0 == StatusCode::OK,
            "cancel mismatched profile {cancelled:?}"
        );
        Ok(())
    }
}

#[tokio::test]
#[ignore = "MODULE=apple.profile: native protocol and durable state"]
async fn profile_lifecycle() -> Result<()> {
    let mut f = Fixture::start().await?;
    let (peer, device) = f.ready_local_peer().await?;
    let invalid = f.create_operation_at(Uuid::from_u128(1), |_| json!({"platform":"macos","request":{"kind":"command","command":{"requestType":"DeviceInformation","fields":{"Invented":{"type":"boolean","value":true}}}}})).await?;
    f.profile_cycle(&peer).await?;
    let rejected = f.operation(invalid).await?;
    ensure!(
        rejected["commandStatus"] == "cancelled"
            && rejected["dispatchFailure"]["platform"] == "macos",
        "invalid native input blocked the device queue: {rejected}"
    );
    ensure!(
        rejected["observation"]["receipts"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["phase"] != "execute"),
        "server validation was reported as a device receipt"
    );
    f.profile_mismatch(&peer).await?;
    drop(device);
    f.close().await
}

#[tokio::test]
#[ignore = "MODULE=apple.profile: profile target authorization"]
async fn security_profile_replacement_and_removal_keep_target_permissions() -> Result<()> {
    use anyhow::Context;
    let mut f = Fixture::start().await.context("security fixture startup")?;
    let (peer, device) = f
        .ready_local_peer()
        .await
        .context("security fixture enrollment")?;
    let grant = |security: bool| {
        let mut operations = vec![
            "enrollment",
            "credentials",
            "inventory_read",
            "inventory_collect",
            "configuration_write",
            "operation_read",
            "operation_cancel",
        ];
        if security {
            operations.push("security_operate");
        }
        crate::test_support::identity::device_grants(Some(case_device()), &operations)
    };
    let path = format!("/api/v3/devices/{}/operations", case_device());
    let security_task = |id| {
        let mut task = profile_task(id, true);
        let payload = &mut task["request"]["profile"]["payloads"][0];
        payload["schema"] = json!("mdm/profiles/com.apple.MCX.FileVault2.yaml");
        payload["fields"] = json!({"Enable":{"type":"string","value":"On"}});
        task
    };
    let body = |id, task| json!({"operationId":id,"inputVersion":"1","target":{"kind":"device"},"task":task,"deadline":f.app.clock.unix_seconds().unwrap()+300});
    let denied = f
        .browser
        .call(
            &f.router,
            Method::POST,
            &path,
            Some(body(Uuid::new_v4(), security_task(Uuid::new_v4()))),
        )
        .await?;
    ensure!(
        denied.0 == StatusCode::FORBIDDEN,
        "ordinary configuration grant installed security profile: {denied:?}"
    );
    crate::test_support::identity::set_grants(
        case_tenant(),
        crate::test_support::case::admin(),
        grant(true).context("security device grants")?,
    )
    .await?;
    let installed = f.create_operation(security_task).await?;
    let (execute, _) = peer.next("InstallProfile").await?;
    let bytes = peer.manage("Acknowledged", Some(execute), None).await?;
    let (observe, _) = command(&bytes, "ProfileList")?;
    peer.manage(
        "Acknowledged",
        Some(observe),
        Some((
            "ProfileList",
            profile_manifest(installed, "com.apple.MCX.FileVault2"),
        )),
    )
    .await?;
    ensure!(f.operation(installed).await?["commandStatus"] == "applied");
    crate::test_support::identity::set_grants(
        case_tenant(),
        crate::test_support::case::admin(),
        grant(false)?,
    )
    .await?;
    let make_body = |id, task| json!({"operationId":id,"inputVersion":"1","target":{"kind":"device"},"task":task,"deadline":f.app.clock.unix_seconds().unwrap()+300});
    for task in [
        remove_profile_task(installed),
        profile_task(Uuid::new_v4(), false),
    ] {
        let denied = f
            .browser
            .call(
                &f.router,
                Method::POST,
                &path,
                Some(make_body(Uuid::new_v4(), task)),
            )
            .await?;
        ensure!(
            denied.0 == StatusCode::FORBIDDEN,
            "old security target authority omitted: {denied:?}"
        );
    }
    crate::test_support::identity::set_grants(
        case_tenant(),
        crate::test_support::case::admin(),
        grant(true).context("security device grants")?,
    )
    .await?;
    let replacement = f.create_operation(|id| profile_task(id, false)).await?;
    let mut pg =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    let required: serde_json::Value=sqlx::query_scalar("SELECT approval->'required' FROM mdm_commands.operations WHERE tenant_id=$1::uuid AND id=$2").bind(case_tenant()).bind(replacement).fetch_one(&mut pg).await?;
    ensure!(
        required
            .as_array()
            .unwrap()
            .contains(&json!("security_operate")),
        "target authority not frozen: {required}"
    );
    crate::test_support::identity::set_grants(
        case_tenant(),
        crate::test_support::case::admin(),
        grant(false)?,
    )
    .await?;
    ensure!(
        peer.manage("Idle", None, None).await?.is_empty(),
        "revoked old authority still dispatched replacement"
    );
    let attempts: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM mdm_apple.attempts WHERE tenant_id=$1::uuid AND operation=$2",
    )
    .bind(case_tenant())
    .bind(replacement)
    .fetch_one(&mut pg)
    .await?;
    ensure!(
        attempts == 0,
        "attempt persisted after target permission revocation"
    );
    pg.close().await?;
    drop(device);
    f.close().await
}

#[tokio::test]
#[ignore = "MODULE=apple.profile: protected history collisions and observed guard release"]
async fn cross_root_guards_require_complete_removal_evidence() -> Result<()> {
    let mut f = Fixture::start().await?;
    let (peer, device) = f.ready_local_peer().await?;
    let dock = |id| {
        let mut task = profile_task(id, true);
        task["request"]["profile"]["payloads"][0]["schema"] =
            json!("mdm/profiles/com.apple.dock.yaml");
        task["request"]["profile"]["payloads"][0]["fields"] =
            json!({"autohide":{"type":"boolean","value":true}});
        task
    };
    let original = f.create_operation(dock).await?;
    let (execute, _) = peer.next("InstallProfile").await?;
    let next = peer.manage("Acknowledged", Some(execute), None).await?;
    let (observe, _) = command(&next, "ProfileList")?;
    peer.manage(
        "Acknowledged",
        Some(observe),
        Some(("ProfileList", profile_manifest(original, "com.apple.dock"))),
    )
    .await?;
    let alternate = |id: Uuid, reuse: bool| {
        let mut task = dock(id);
        task["request"]["profile"]["identifier"] = json!(format!("{}.other", native_profile()));
        task["request"]["profile"]["payloads"][0]["identifier"] =
            json!(format!("{}.other.settings", native_profile()));
        if reuse {
            task["request"]["profile"]["payloads"][0]["uuid"] =
                json!(Uuid::from_u128(original.as_u128() ^ (1 << 127)));
        }
        task
    };
    let path = format!("/api/v3/devices/{}/operations", case_device());
    let blocked = Uuid::new_v4();
    let reply = f.browser.call(&f.router,Method::POST,&path,Some(json!({"operationId":blocked,"inputVersion":"1","target":{"kind":"device"},"task":alternate(blocked,true),"deadline":f.app.clock.unix_seconds()?+300}))).await?;
    ensure!(
        reply.0 == StatusCode::CONFLICT,
        "cross-root UUID collision {reply:?}"
    );
    let singleton = f.create_operation(|id| alternate(id, false)).await?;
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
                        ("EnrolledViaDEP", false.into()),
                        ("IsUserEnrollment", false.into()),
                        ("UserApprovedEnrollment", true.into()),
                    ])),
                )])),
            )),
        )
        .await?;
    ensure!(next.is_empty(), "singleton dispatched");
    ensure!(f.operation(singleton).await?["dispatchFailure"].is_object());
    let remove = f
        .create_operation(|_| remove_profile_task(original))
        .await?;
    let (execute, _) = peer.next("RemoveProfile").await?;
    let next = peer.manage("Acknowledged", Some(execute), None).await?;
    let (observe, _) = command(&next, "ProfileList")?;
    peer.manage("Acknowledged", Some(observe), None).await?;
    ensure!(f.operation(remove).await?["commandStatus"] == "received");
    let candidate = Uuid::new_v4();
    let reply = f.browser.call(&f.router,Method::POST,&path,Some(json!({"operationId":candidate,"inputVersion":"1","target":{"kind":"device"},"task":alternate(candidate,true),"deadline":f.app.clock.unix_seconds()?+300}))).await?;
    ensure!(
        reply.0 == StatusCode::CONFLICT,
        "incomplete manifest released UUID guard"
    );
    f.profile_query_due(remove).await?;
    let (observe, _) = peer.next("ProfileList").await?;
    peer.manage(
        "Acknowledged",
        Some(observe),
        Some(("ProfileList", plist::Value::Array(vec![]))),
    )
    .await?;
    ensure!(f.operation(remove).await?["commandStatus"] == "applied");
    let replacement = f.create_operation(|id| alternate(id, true)).await?;
    let (execute, _) = peer.next("InstallProfile").await?;
    let next = peer.manage("Acknowledged", Some(execute), None).await?;
    let (observe, _) = command(&next, "ProfileList")?;
    let mut manifest = profile_manifest(replacement, "com.apple.dock");
    let root = manifest.as_array_mut().unwrap()[0]
        .as_dictionary_mut()
        .unwrap();
    root.insert(
        "PayloadIdentifier".into(),
        format!("{}.other", native_profile()).into(),
    );
    let child = root
        .get_mut("PayloadContent")
        .unwrap()
        .as_array_mut()
        .unwrap()[0]
        .as_dictionary_mut()
        .unwrap();
    child.insert(
        "PayloadIdentifier".into(),
        format!("{}.other.settings", native_profile()).into(),
    );
    child.insert(
        "PayloadUUID".into(),
        Uuid::from_u128(original.as_u128() ^ (1 << 127))
            .to_string()
            .into(),
    );
    peer.manage(
        "Acknowledged",
        Some(observe),
        Some(("ProfileList", manifest)),
    )
    .await?;
    ensure!(f.operation(replacement).await?["commandStatus"] == "applied");
    drop(device);
    f.close().await
}

#[tokio::test]
#[ignore = "MODULE=apple.profile: native error requires complete contrary evidence to retire reservations"]
async fn failed_install_partial_manifest_keeps_ownership_until_proven_absent() -> Result<()> {
    let mut f = Fixture::start().await?;
    let (peer, device) = f.ready_local_peer().await?;
    let failed = f.create_operation(|id| profile_task(id, true)).await?;
    let (execute, _) = peer.next("InstallProfile").await?;
    let next = peer.manage("Error", Some(execute), None).await?;
    let (observe, _) = command(&next, "ProfileList")?;
    let mut partial = profile_manifest(failed, "com.apple.security.firewall");
    partial.as_array_mut().unwrap()[0]
        .as_dictionary_mut()
        .unwrap()
        .insert("PayloadContent".into(), plist::Value::Array(vec![]));
    peer.manage(
        "Acknowledged",
        Some(observe),
        Some(("ProfileList", partial)),
    )
    .await?;
    ensure!(f.operation(failed).await?["commandStatus"] == "published");
    let mut pg =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    let guarded:bool=sqlx::query_scalar("SELECT observed_at IS NULL AND retired_at IS NULL FROM mdm_apple.profiles WHERE tenant_id=$1::uuid AND operation=$2").bind(case_tenant()).bind(failed).fetch_one(&mut pg).await?;
    ensure!(
        guarded,
        "partial manifest released failed install reservation"
    );
    pg.close().await?;
    f.profile_query_due(failed).await?;
    let (observe, _) = peer.next("ProfileList").await?;
    peer.manage(
        "Acknowledged",
        Some(observe),
        Some(("ProfileList", plist::Value::Array(vec![]))),
    )
    .await?;
    ensure!(f.operation(failed).await?["commandStatus"] == "rejected");
    let replacement = f.create_operation(|id| profile_task(id, false)).await?;
    let (execute, _) = peer.next("InstallProfile").await?;
    let next = peer.manage("Acknowledged", Some(execute), None).await?;
    let (observe, _) = command(&next, "ProfileList")?;
    peer.manage(
        "Acknowledged",
        Some(observe),
        Some((
            "ProfileList",
            profile_manifest(replacement, "com.apple.security.firewall"),
        )),
    )
    .await?;
    ensure!(f.operation(replacement).await?["commandStatus"] == "applied");
    drop(device);
    f.close().await
}
