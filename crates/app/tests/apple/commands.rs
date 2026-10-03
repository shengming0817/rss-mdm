//! Real TLS/HTTP and PG verify native families separately from external effects.
use super::*;
use lifecycle::command;
fn task(kind: &str, fields: serde_json::Value) -> serde_json::Value {
    json!({"platform":"macos","request":{"kind":"command","command":{"requestType":kind,"fields":fields}}})
}
#[tokio::test]
#[ignore = "MODULE=apple.commands: native command families over real mTLS and PG"]
async fn native_families_keep_results_separate_from_effects() -> Result<()> {
    let mut f = Fixture::start().await?;
    let (peer, device) = f.ready_local_peer().await?;
    let query = f
        .create_operation(|_| task("InstalledApplicationList", json!({})))
        .await?;
    let (id, _) = peer.next("InstalledApplicationList").await?;
    peer.manage(
        "Acknowledged",
        Some(id),
        Some(("InstalledApplicationList", plist::Value::Array(vec![]))),
    )
    .await?;
    let result = f.operation(query).await?;
    ensure!(
        result["commandStatus"] == "applied"
            && result["observation"]["result"] == "query_result"
            && result["observation"]["effect"] == "unverified",
        "query {result}"
    );
    let security = f
        .create_operation(|_| {
            task(
                "VerifyRecoveryLock",
                json!({"Password":{"type":"string","value":"fixture-secret"}}),
            )
        })
        .await?;
    let (id, _) = peer.next("VerifyRecoveryLock").await?;
    peer.manage(
        "Acknowledged",
        Some(id),
        Some(("PasswordVerified", false.into())),
    )
    .await?;
    let result = f.operation(security).await?;
    ensure!(
        result["observation"]["result"] == "rejected" && result["commandStatus"] != "applied",
        "verification {result}"
    );
    let account = f
        .create_operation(|_| {
            task(
                "UnlockUserAccount",
                json!({"UserName":{"type":"string","value":"fixture-local"}}),
            )
        })
        .await?;
    let (id, _) = peer.next("UnlockUserAccount").await?;
    peer.manage("Acknowledged", Some(id), None).await?;
    ensure!(f.operation(account).await?["observation"]["result"] == "acknowledged");
    let control = f
        .create_operation(|_| task("RestartDevice", json!({})))
        .await?;
    let (id, _) = peer.next("RestartDevice").await?;
    peer.manage("Acknowledged", Some(id), None).await?;
    let result = f.operation(control).await?;
    ensure!(
        result["commandStatus"] == "received"
            && result["observation"]["result"] == "pending_restart",
        "restart {result}"
    );
    let pkg=f.create_operation(|_|task("InstallEnterpriseApplication",json!({"ManifestURL":{"type":"string","value":"https://packages.example.test/manifest.plist"}}))).await?;
    let (id, payload) = peer.next("InstallEnterpriseApplication").await?;
    ensure!(
        payload["ManifestURL"].as_string() == Some("https://packages.example.test/manifest.plist")
    );
    peer.manage("Acknowledged", Some(id), None).await?;
    let result = f.operation(pkg).await?;
    ensure!(
        result["commandStatus"] == "received" && result["observation"]["effect"] == "unverified",
        "PKG {result}"
    );
    let update=f.create_operation(|_|task("ScheduleOSUpdate",json!({"Updates":{"type":"array","value":[{"type":"dictionary","value":{"ProductKey":{"type":"string","value":"fixture-update"},"InstallAction":{"type":"string","value":"InstallLater"},"MaxUserDeferrals":{"type":"integer","value":"3"}}}]}}))).await?;
    let (id, _) = peer.next("ScheduleOSUpdate").await?;
    let next = peer
        .manage(
            "Acknowledged",
            Some(id),
            Some((
                "UpdateResults",
                plist::Value::Array(vec![plist::Value::Dictionary(protocol::dictionary([
                    ("ProductKey", "fixture-update".into()),
                    ("InstallAction", "InstallLater".into()),
                    ("Status", "Idle".into()),
                ]))]),
            )),
        )
        .await?;
    command(&next, "OSUpdateStatus")?;
    let result = f.operation(update).await?;
    ensure!(
        result["commandStatus"] == "received" && result["observation"]["result"] == "deferred",
        "OS update {result}"
    );
    drop(device);
    f.close().await
}
