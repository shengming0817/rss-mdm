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
    let unknown=f.browser.call(&f.router,Method::POST,&path,Some(json!({"operationId":Uuid::new_v4(),"deadline":f.app.clock.unix_seconds()?+300,"action":{"kind":"restart"}}))).await?;
    ensure!(
        !unknown.0.is_success(),
        "missing native prerequisites accepted: {unknown:?}"
    );
    // The prerequisite context is legal preparation; this case owns control admission and wire mapping.
    f.native_context().await?;
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
        if kind == "restart" {
            ensure!(
                f.browser
                    .call(&f.router, Method::POST, &path, Some(input))
                    .await?
                    == accepted
            );
        }
        let (attempt, payload) = peer.next(command).await?;
        if kind == "lock" {
            ensure!(payload["PIN"].as_string() == Some("781239"))
        }
        if kind == "wipe" {
            ensure!(payload["ObliterationBehavior"].as_string() == Some("DoNotObliterate"));
            ensure!(!payload.contains_key("PIN"));
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
        let (authority,sealed):(String,Vec<u8>)=sqlx::query_as("SELECT authority::text,request FROM mdm_commands.operations WHERE tenant_id=$1::uuid AND id=$2").bind(case_tenant()).bind(id).fetch_one(&mut pg).await?;
        ensure!(
            !authority.contains("781239") && !sealed.windows(6).any(|v| v == b"781239"),
            "PIN persisted in plaintext"
        );
        pg.close().await?;
    }
    drop(device);
    f.close().await
}

#[tokio::test]
#[ignore = "MODULE=apple.commands: credential escrow and verification over real mTLS and PG"]
async fn recovery_material_is_escrowed_without_leaking_into_native_results() -> Result<()> {
    use openssl::{
        cms::{CMSOptions, CmsContentInfo},
        stack::Stack,
        symm::Cipher,
        x509::X509,
    };
    let mut f = Fixture::start().await?;
    let (peer, device) = f.ready_local_peer().await?;
    f.native_context().await?;
    f.grant_native_actions(&["security_operate", "credentials"])
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
    ensure!(detail.0 == StatusCode::OK);
    let registration = detail.1["primaryMdmRegistration"]["registrationId"].clone();
    let generation = detail.1["primaryMdmRegistration"]["generation"].clone();
    let path = format!("/api/v1/devices/{}/recovery-credentials", case_device());
    let operation = Uuid::new_v4();
    let accepted=f.browser.call(&f.router,Method::POST,&format!("{path}/operations"),Some(json!({"operationId":operation,"registration":registration,"generation":generation,"deadline":f.app.clock.unix_seconds()?+300,"action":{"kind":"collect_filevault","expectedRevision":0,"recipient":null}}))).await?;
    ensure!(
        accepted.0 == StatusCode::ACCEPTED,
        "credential create: {accepted:?}"
    );
    let (attempt, _) = peer.next("SecurityInfo").await?;
    let protection = f.app.execution.recovery_credentials().unwrap();
    let mut recipients = Stack::new()?;
    recipients.push(X509::from_der(
        &protection.active_recipient().certificate_der()?,
    )?)?;
    let secret = "ABCD-EFGH-IJKL-MNOP-QRST-UVWX";
    let cms = CmsContentInfo::encrypt(
        &recipients,
        secret.as_bytes(),
        Cipher::aes_256_cbc(),
        CMSOptions::BINARY,
    )?
    .to_der()?;
    let report = plist::Value::Dictionary(protocol::dictionary([
        ("FDE_Enabled", true.into()),
        ("FDE_PersonalRecoveryKeyCMS", plist::Value::Data(cms)),
    ]));
    peer.manage(
        "Acknowledged",
        Some(attempt),
        Some(("SecurityInfo", report.clone())),
    )
    .await?;
    peer.manage(
        "Acknowledged",
        Some(attempt),
        Some(("SecurityInfo", report)),
    )
    .await?;
    let (status, list) = f.browser.call(&f.router, Method::GET, &path, None).await?;
    ensure!(status == StatusCode::OK);
    let entries = list.as_array().unwrap();
    ensure!(entries.len() == 1);
    ensure!(entries[0]["validity"] == "unverified" && entries[0]["escrowed"] == true);
    let read = format!(
        "{path}/{}/versions/{}/secret",
        entries[0]["id"].as_str().unwrap(),
        entries[0]["version"]
    );
    let disclosed = f.browser.call(&f.router, Method::GET, &read, None).await?;
    ensure!(disclosed.0 == StatusCode::OK && disclosed.1["secret"] == secret);
    let ordinary = f.operation(operation).await?;
    ensure!(
        !ordinary.to_string().contains("FDE_PersonalRecoveryKeyCMS")
            && !ordinary.to_string().contains(secret)
    );

    let set = Uuid::new_v4();
    let accepted=f.browser.call(&f.router,Method::POST,&format!("{path}/operations"),Some(json!({"operationId":set,"registration":registration,"generation":generation,"deadline":f.app.clock.unix_seconds()?+300,"action":{"kind":"set_recovery_lock","expectedRevision":0,"current":null,"clear":false}}))).await?;
    ensure!(
        accepted.0 == StatusCode::ACCEPTED,
        "recovery lock create: {accepted:?}"
    );
    let (attempt, payload) = peer.next("SetRecoveryLock").await?;
    let password = payload["NewPassword"].as_string().unwrap().to_owned();
    peer.manage("Acknowledged", Some(attempt), None).await?;
    let (_, list) = f.browser.call(&f.router, Method::GET, &path, None).await?;
    let lock = list
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["binding"]["subject"]["kind"] == "recovery_lock")
        .unwrap();
    ensure!(lock["validity"] == "unknown");
    let verify = Uuid::new_v4();
    let accepted=f.browser.call(&f.router,Method::POST,&format!("{path}/operations"),Some(json!({"operationId":verify,"registration":registration,"generation":generation,"deadline":f.app.clock.unix_seconds()?+300,"action":{"kind":"verify_recovery_lock","material":{"id":lock["id"],"version":lock["version"]}}}))).await?;
    ensure!(accepted.0 == StatusCode::ACCEPTED);
    let (attempt, payload) = peer.next("VerifyRecoveryLock").await?;
    ensure!(payload["Password"].as_string() == Some(password.as_str()));
    peer.manage(
        "Acknowledged",
        Some(attempt),
        Some(("PasswordVerified", true.into())),
    )
    .await?;
    let (_, list) = f.browser.call(&f.router, Method::GET, &path, None).await?;
    ensure!(
        list.as_array()
            .unwrap()
            .iter()
            .any(|v| v["id"] == lock["id"] && v["validity"] == "verified" && v["current"] == true)
    );
    ensure!(!f.operation(verify).await?.to_string().contains(&password));
    drop(device);
    f.close().await
}
