//! Exact native versions, unordered evidence, user scope and loss of current authority.
use super::*;
use ddm::{manifest, native, report, subscription, task};
use lifecycle::command;
#[tokio::test]
#[ignore = "MODULE=apple.status: native status conflicts, scopes and revocation"]
async fn status_authority_and_user_scope_are_independent() -> Result<()> {
    let mut f = Fixture::start().await?;
    let (peer, device) = f.ready_local_peer().await?;
    let device_operation = f
        .create_operation(|_| task(vec![subscription("device-subscriptions")], vec![]))
        .await?;
    let (id, _) = peer.next("DeclarativeManagement").await?;
    peer.manage("Acknowledged", Some(id), None).await?;
    let device_manifest = manifest(&peer, None).await?;
    let first = report(&device_manifest, true, "15.0");
    native(&peer, None, "status", Some(&first)).await?;
    ensure!(f.operation(device_operation).await?["commandStatus"] == "applied");
    let item_only =
        json!({"StatusItems":{"device":{"operating-system":{"version":"15.1"}}},"Errors":[]});
    ensure!(native(&peer, None, "status", Some(&item_only)).await?.0 == StatusCode::OK);
    let value = f.operation(device_operation).await?;
    ensure!(value["observation"]["nativeStatus"]["synchronized"] == true);
    ensure!(
        value["observation"]["nativeStatus"]["items"]
            .get("device.operating-system.version")
            .is_none()
    );
    ensure!(
        value["observation"]["nativeStatus"]["unknownItems"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "device.operating-system.version")
    );
    let error_only = json!({"StatusItems":{},"Errors":[{"StatusItem":"device.operating-system.version","Reasons":[{"Code":"unavailable"}]}]});
    ensure!(native(&peer, None, "status", Some(&error_only)).await?.0 == StatusCode::OK);
    ensure!(
        f.operation(device_operation).await?["observation"]["nativeStatus"]["errors"]
            .as_array()
            .unwrap()
            .len()
            == 1
    );
    let conflicting = report(&device_manifest, false, "15.1");
    native(&peer, None, "status", Some(&conflicting)).await?;
    let result = f.operation(device_operation).await?;
    ensure!(
        result["commandStatus"] == "applied",
        "historical progress regressed"
    );
    ensure!(
        result["observation"]["nativeStatus"]["synchronized"] == false
            && result["observation"]["nativeStatus"]["declarations"][0]["native"]["valid"]
                == "unknown",
        "{result}"
    );
    ensure!(
        result["observation"]["nativeStatus"]["items"]
            .get("device.operating-system.version")
            .is_none()
    );
    ensure!(
        result["observation"]["effect"] == "unverified"
            && result["observation"]["compliance"] == "unknown"
    );
    let user = Uuid::new_v4();
    peer.user_token(user, 45).await?;
    let operation = Uuid::new_v4();
    let reply=f.browser.call(&f.router,Method::POST,&format!("/api/v3/devices/{}/operations",case_device()),
        Some(json!({"operationId":operation,"inputVersion":"user-v1","target":{"kind":"user","userId":user},"task":task(vec![subscription("user-subscriptions")],vec![]),"deadline":f.app.clock.unix_seconds()?+300}))).await?;
    ensure!(reply.0 == StatusCode::ACCEPTED, "user DDM {reply:?}");
    for _ in 0..100 {
        if f.operation(operation).await?["commandStatus"] == "published" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let (id, _) = peer.next("SecurityInfo").await?;
    peer.manage(
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
    let (status, bytes) = peer.user_manage(user, "Idle", None, None).await?;
    ensure!(status == StatusCode::OK);
    let (id, _) = command(&bytes, "DeclarativeManagement")?;
    peer.user_manage(user, "Acknowledged", Some(id), None)
        .await?;
    let user_manifest = manifest(&peer, Some(user)).await?;
    ensure!(user_manifest["DeclarationsToken"] != device_manifest["DeclarationsToken"]);
    ensure!(
        user_manifest["Declarations"]["Configurations"][0]["Identifier"] == "user-subscriptions"
    );
    ensure!(manifest(&peer, None).await? == device_manifest);
    native(
        &peer,
        Some(user),
        "status",
        Some(&report(&user_manifest, true, "15.0")),
    )
    .await?;
    ensure!(f.operation(operation).await?["commandStatus"] == "applied");
    ensure!(
        f.operation(device_operation).await?["observation"]["nativeStatus"]["synchronized"]
            == false,
        "user report changed device facts"
    );
    ensure!(
        native(&peer, Some(Uuid::new_v4()), "tokens", None).await?.0 == StatusCode::UNAUTHORIZED
    );
    crate::test_support::identity::set_grants(
        case_tenant(),
        crate::test_support::case::admin(),
        crate::test_support::identity::device_grants(
            Some(case_device()),
            &["operation_read", "inventory_read"],
        )?,
    )
    .await?;
    for user in [None, Some(user)] {
        let empty = manifest(&peer, user).await?;
        ensure!(
            empty["Declarations"]["Configurations"]
                .as_array()
                .unwrap()
                .is_empty(),
            "revoked publication {empty}"
        );
    }
    // Late authenticated evidence is retained, but cannot recover withdrawn authority.
    ensure!(native(&peer, None, "status", Some(&first)).await?.0 == StatusCode::OK);
    let read = f
        .browser
        .call(
            &f.router,
            Method::GET,
            &format!(
                "/api/v3/devices/{}/operations/{device_operation}",
                case_device()
            ),
            None,
        )
        .await?;
    ensure!(
        read.0 == StatusCode::FORBIDDEN,
        "revoked raw status read: {read:?}"
    );
    crate::test_support::identity::set_grants(
        case_tenant(),
        crate::test_support::case::admin(),
        crate::test_support::identity::device_grants(
            Some(case_device()),
            &["operation_read", "inventory_read", "configuration_write"],
        )?,
    )
    .await?;
    ensure!(f.operation(device_operation).await?["observation"]["synchronization"] == "withdrawn");
    ensure!(
        manifest(&peer, None).await?["Declarations"]["Configurations"]
            .as_array()
            .unwrap()
            .is_empty(),
        "restoring read permission resurrected a retired publication"
    );
    drop(device);
    f.close().await
}
