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
        let profiles = plist::Value::Array(vec![plist::Value::Dictionary(protocol::dictionary([
            ("PayloadIdentifier", NATIVE_PROFILE.into()),
            ("PayloadUUID", installed.to_string().into()),
            ("PayloadVersion", 1.into()),
        ]))]);
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
        let removed = self
            .create_operation(|_| remove_profile_task(installed))
            .await?;
        let (execute, payload) = peer.next("RemoveProfile").await?;
        ensure!(payload["Identifier"].as_string() == Some(NATIVE_PROFILE));
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
            ("PayloadIdentifier", NATIVE_PROFILE.into()),
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
    let mut f = Fixture::start().await?;
    let (peer, device) = f.ready_local_peer().await?;
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
        grant(true)?,
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
            plist::Value::Array(vec![plist::Value::Dictionary(protocol::dictionary([
                ("PayloadIdentifier", NATIVE_PROFILE.into()),
                ("PayloadUUID", installed.to_string().into()),
                ("PayloadVersion", 1.into()),
            ]))]),
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
        grant(true)?,
    )
    .await?;
    let replacement = f.create_operation(|id| profile_task(id, false)).await?;
    let mut pg =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    let required: Value=sqlx::query_scalar("SELECT approval->'required' FROM mdm_commands.operations WHERE tenant_id=$1::uuid AND id=$2").bind(case_tenant()).bind(replacement).fetch_one(&mut pg).await?;
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
