//! Three fixed controls use authenticated applicability and retain native effect uncertainty.
use super::*;
use sqlx::Connection;
#[tokio::test]
#[ignore = "MODULE=apple.commands: closed device controls over real mTLS and PG"]
async fn native_controls_are_closed_and_never_claim_effects() -> Result<()> {
    let mut f = Fixture::start().await?;
    f.grant_native_actions(&["device_control", "device_wipe"])
        .await?;
    let (peer, device) = f.ready_local_peer().await?;
    let path = format!("/api/v1/devices/{}/operations", case_device());
    for task in [
        json!({"platform":"macos","request":{"kind":"command","command":{"requestType":"InstalledApplicationList","fields":{}}}}),
        json!({"platform":"macos","request":{"kind":"command","command":{"requestType":"EraseDevice","fields":{}}}}),
        json!({"platform":"windows","request":{"kind":"sync_ml","request":{"kind":"node","node":"./Device/Vendor/MSFT/Reboot/RebootNow","instance":[],"operation":"exec","value":null}}}),
    ] {
        let response=f.browser.call(&f.router,Method::POST,&path,Some(json!({"operationId":Uuid::new_v4(),"deadline":f.app.clock.unix_seconds()?+300,"task":task}))).await?;
        ensure!(
            response.0 == StatusCode::BAD_REQUEST,
            "generic input accepted: {response:?}"
        );
    }
    let unknown=f.browser.call(&f.router,Method::POST,&path,Some(json!({"operationId":Uuid::new_v4(),"deadline":f.app.clock.unix_seconds()?+300,"action":{"kind":"restart"}}))).await?;
    ensure!(
        !unknown.0.is_success(),
        "missing native prerequisites accepted: {unknown:?}"
    );
    // A real Policy-owned Profile exchange supplies native context for this registration.
    f.policy_cycle(&peer).await?;
    f.grant_native_actions(&["device_control", "device_wipe"])
        .await?;
    let detail = f
        .browser
        .call(
            &f.router,
            Method::GET,
            &format!("/api/v1/devices/{}", case_device()),
            None,
        )
        .await?;
    ensure!(detail.0 == StatusCode::OK, "device detail: {detail:?}");
    let registration = &detail.1["primaryMdmRegistration"];
    ensure!(registration["source"] == "mdm.apple");
    let confirmation = json!({"confirmed":true,"expectedRegistrationId":registration["registrationId"],"expectedGeneration":registration["generation"]});
    for (kind, command) in [
        ("restart", "RestartDevice"),
        ("lock", "DeviceLock"),
        ("wipe", "EraseDevice"),
    ] {
        let id = Uuid::new_v4();
        let mut action = if kind == "restart" {
            json!({})
        } else {
            confirmation.clone()
        };
        action["kind"] = json!(kind);
        if kind == "lock" {
            action["pin"] = json!("781239")
        }
        let input =
            json!({"operationId":id,"deadline":f.app.clock.unix_seconds()?+300,"action":action});
        let accepted = f
            .browser
            .call(&f.router, Method::POST, &path, Some(input.clone()))
            .await?;
        ensure!(accepted.0 == StatusCode::ACCEPTED, "{kind}: {accepted:?}");
        ensure!(
            f.browser
                .call(&f.router, Method::POST, &path, Some(input))
                .await?
                == accepted
        );
        let (attempt, payload) = peer.next(command).await?;
        if kind == "lock" {
            ensure!(payload["PIN"].as_string() == Some("781239"))
        }
        if kind == "wipe" {
            ensure!(payload["ObliterationBehavior"].as_string() == Some("DoNotObliterate"));
            ensure!(!payload.contains_key("PIN"));
        }
        if kind == "restart" {
            let mut pg = sqlx::PgConnection::connect_with(&crate::device::test_support::options(
                "postgres",
            )?)
            .await?;
            sqlx::query("UPDATE mdm_commands.operations SET approval=(approval-'action'-'confirmation')||'{\"kind\":\"user\"}'::jsonb WHERE tenant_id=$1::uuid AND id=$2").bind(case_tenant()).bind(id).execute(&mut pg).await?;
            let audit = rss_mdm_audit_integration::RequestAudit::new(
                case_tenant().into(),
                "management_read",
            );
            f.app.execution.recover_operation(id, &audit).await?;
            audit.finalize(None);
            ensure!(f.operation(id).await?["commandStatus"] == "published");
            pg.close().await?;
        }
        peer.manage("Acknowledged", Some(attempt), None).await?;
        let result = f.operation(id).await?;
        ensure!(
            result["commandStatus"] == "received"
                && result["observation"]["effect"] == "unverified",
            "control ACK claimed effect: {result}"
        );
        ensure!(
            !result.to_string().contains("781239"),
            "PIN escaped operation projection"
        );
        let mut pg =
            sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
                .await?;
        let (authority,sealed):(String,Vec<u8>)=sqlx::query_as("SELECT approval::text,request FROM mdm_commands.operations WHERE tenant_id=$1::uuid AND id=$2").bind(case_tenant()).bind(id).fetch_one(&mut pg).await?;
        ensure!(
            !authority.contains("781239") && !sealed.windows(6).any(|v| v == b"781239"),
            "PIN persisted in plaintext"
        );
        pg.close().await?;
    }
    drop(device);
    f.close().await
}
