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
    let failed = Uuid::new_v4();
    let accepted=f.browser.call(&f.router,Method::POST,&path,Some(json!({"operationId":failed,"deadline":f.app.clock.unix_seconds()?+300,"action":{"kind":"restart"}}))).await?;
    ensure!(accepted.0 == StatusCode::ACCEPTED);
    let (attempt, _) = peer.next("RestartDevice").await?;
    let canary = "native-error-must-not-disclose-password";
    let chain = plist::Value::Array(vec![plist::Value::Dictionary(protocol::dictionary([
        ("ErrorCode", 12021i64.into()),
        ("ErrorDomain", canary.into()),
        ("LocalizedDescription", canary.into()),
        ("USEnglishDescription", canary.into()),
        ("Password", canary.into()),
    ]))]);
    peer.manage("Error", Some(attempt), Some(("ErrorChain", chain)))
        .await?;
    let detail = f.operation(failed).await?;
    ensure!(
        detail["observation"]["error"]["ErrorChain"]["value"][0]["value"]["ErrorCode"]["value"]
            == "12021",
        "safe native diagnostic missing: {detail}"
    );
    ensure!(!detail.to_string().contains(canary));
    {
        use sqlx::Row;
        let mut pg =
            sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
                .await?;
        let row=sqlx::query("SELECT registration,generation,response FROM mdm_apple.attempts WHERE tenant_id=$1::uuid AND id=$2").bind(case_tenant()).bind(attempt).fetch_one(&mut pg).await?;
        let owner = serde_json::to_string(&(
            row.try_get::<Uuid, _>("registration")?,
            row.try_get::<i64, _>("generation")?,
            attempt,
        ))?;
        let aad = rss_mdm_native_protection::ProtectionContext::new(
            rss_request_context::TenantId::parse(case_tenant())?,
            &owner,
            "apple.attempt.response",
            1,
        )?
        .derive();
        let plain = f
            .app
            .protection
            .open_bytes(&row.try_get::<Vec<u8>, _>("response")?, &aad)?;
        ensure!(!String::from_utf8_lossy(plain.expose()).contains(canary));
        ensure!(
            protocol::decode(plain.expose())?["ErrorChain"]
                .as_array()
                .unwrap()[0]
                .as_dictionary()
                .unwrap()["ErrorCode"]
                .as_signed_integer()
                == Some(12021)
        );
        pg.close().await?;
    }
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
    f.grant_native_actions(&["security_operate"]).await?;
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
    let (attempt, _) = peer.next_security().await?;
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
    let entries = list["items"].as_array().unwrap();
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
    let lock = list["items"]
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
        list["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["id"] == lock["id"] && v["validity"] == "verified" && v["current"] == true)
    );
    ensure!(!f.operation(verify).await?.to_string().contains(&password));
    // A rejected replacement remains protected until the original password is independently verified.
    let replacement = Uuid::new_v4();
    let accepted=f.browser.call(&f.router,Method::POST,&format!("{path}/operations"),Some(json!({"operationId":replacement,"registration":registration,"generation":generation,"deadline":f.app.clock.unix_seconds()?+300,"action":{"kind":"set_recovery_lock","expectedRevision":1,"current":{"id":lock["id"],"version":1},"clear":false}}))).await?;
    ensure!(
        accepted.0 == StatusCode::ACCEPTED,
        "replacement {accepted:?}"
    );
    let (attempt, _) = peer.next("SetRecoveryLock").await?;
    peer.manage("Error", Some(attempt), None).await?;
    let accepted=f.browser.call(&f.router,Method::POST,&format!("{path}/operations"),Some(json!({"operationId":Uuid::new_v4(),"registration":registration,"generation":generation,"deadline":f.app.clock.unix_seconds()?+300,"action":{"kind":"verify_recovery_lock","material":{"id":lock["id"],"version":2}}}))).await?;
    ensure!(accepted.0 == StatusCode::ACCEPTED);
    let (attempt, _) = peer.next("VerifyRecoveryLock").await?;
    peer.manage(
        "Acknowledged",
        Some(attempt),
        Some(("PasswordVerified", false.into())),
    )
    .await?;
    let accepted=f.browser.call(&f.router,Method::POST,&format!("{path}/operations"),Some(json!({"operationId":Uuid::new_v4(),"registration":registration,"generation":generation,"deadline":f.app.clock.unix_seconds()?+300,"action":{"kind":"reconcile_recovery_lock","operation":replacement,"material":{"id":lock["id"],"version":1}}}))).await?;
    ensure!(
        accepted.0 == StatusCode::ACCEPTED,
        "reconcile old {accepted:?}"
    );
    let (attempt, payload) = peer.next("VerifyRecoveryLock").await?;
    ensure!(payload["Password"].as_string() == Some(password.as_str()));
    peer.manage(
        "Acknowledged",
        Some(attempt),
        Some(("PasswordVerified", true.into())),
    )
    .await?;
    let accepted=f.browser.call(&f.router,Method::POST,&format!("{path}/operations"),Some(json!({"operationId":Uuid::new_v4(),"registration":registration,"generation":generation,"deadline":f.app.clock.unix_seconds()?+300,"action":{"kind":"set_recovery_lock","expectedRevision":2,"current":{"id":lock["id"],"version":1},"clear":false}}))).await?;
    ensure!(accepted.0 == StatusCode::ACCEPTED, "next set {accepted:?}");
    let (attempt, _) = peer.next("SetRecoveryLock").await?;
    peer.manage("Acknowledged", Some(attempt), None).await?;
    let accepted=f.browser.call(&f.router,Method::POST,&format!("{path}/operations"),Some(json!({"operationId":Uuid::new_v4(),"registration":registration,"generation":generation,"deadline":f.app.clock.unix_seconds()?+300,"action":{"kind":"verify_recovery_lock","material":{"id":lock["id"],"version":3}}}))).await?;
    ensure!(accepted.0 == StatusCode::ACCEPTED);
    let (attempt, _) = peer.next("VerifyRecoveryLock").await?;
    peer.manage(
        "Acknowledged",
        Some(attempt),
        Some(("PasswordVerified", true.into())),
    )
    .await?;
    // A live verification command prevents final ciphertext deletion, but purging terminal copies
    // must still commit an audit fact and remove plaintext from both protected input stores.
    f.grant_native_actions(&["security_operate"]).await?;
    let pending = Uuid::new_v4();
    let accepted=f.browser.call(&f.router,Method::POST,&format!("{path}/operations"),Some(json!({"operationId":pending,"registration":registration,"generation":generation,"deadline":f.app.clock.unix_seconds()?+300,"action":{"kind":"verify_recovery_lock","material":{"id":lock["id"],"version":3}}}))).await?;
    ensure!(accepted.0 == StatusCode::ACCEPTED, "profile {accepted:?}");
    let mut pg =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    sqlx::query("UPDATE mdm_recovery.versions SET invalidated_at=floor(extract(epoch FROM clock_timestamp()))::bigint-7776001 WHERE tenant_id=$1::uuid AND entry=$2 AND version<3").bind(case_tenant()).bind(Uuid::parse_str(lock["id"].as_str().unwrap())?).execute(&mut pg).await?;
    let before: i64 =
        sqlx::query_scalar("SELECT count(*) FROM mdm_audit.receipts WHERE tenant_id=$1::uuid")
            .bind(case_tenant())
            .fetch_one(&mut pg)
            .await?;
    f.app.execution.maintain_recovery_credentials().await?;
    let after: i64 =
        sqlx::query_scalar("SELECT count(*) FROM mdm_audit.receipts WHERE tenant_id=$1::uuid")
            .bind(case_tenant())
            .fetch_one(&mut pg)
            .await?;
    ensure!(after > before, "partial purge omitted audit");
    let retained:bool=sqlx::query_scalar("SELECT sealed IS NOT NULL FROM mdm_recovery.versions WHERE tenant_id=$1::uuid AND entry=$2 AND version=1").bind(case_tenant()).bind(Uuid::parse_str(lock["id"].as_str().unwrap())?).fetch_one(&mut pg).await?;
    ensure!(retained, "purged material before all input copies settled");
    use sqlx::Row;
    let config: crate::config::Config =
        serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
    let key = config.native_protector()?;
    let row=sqlx::query("SELECT request,input_context,device,registration,registration_generation FROM mdm_commands.operations WHERE tenant_id=$1::uuid AND id=$2").bind(case_tenant()).bind(set).fetch_one(&mut pg).await?;
    // Identity field ordering is the owner's serialized struct order.
    let identity = format!(
        "{{\"operation\":{},\"device\":{},\"registration\":{},\"generation\":{}}}",
        serde_json::to_string(&set)?,
        serde_json::to_string(&row.try_get::<String, _>("device")?)?,
        serde_json::to_string(&row.try_get::<Uuid, _>("registration")?)?,
        row.try_get::<i64, _>("registration_generation")?
    );
    let metadata = row.try_get::<serde_json::Value, _>("input_context")?;
    let metadata = format!(
        "{{\"platform\":{},\"deadline\":{},\"inputVersion\":{},\"target\":{}}}",
        metadata["platform"], metadata["deadline"], metadata["inputVersion"], metadata["target"]
    );
    let field = format!("[\"native.operation.input/v1\",{metadata}]");
    let tenant = rss_request_context::TenantId::parse(case_tenant())?;
    let aad =
        rss_mdm_native_protection::ProtectionContext::new(tenant, &identity, &field, 1)?.derive();
    let plain = key.open_bytes(&row.try_get::<Vec<u8>, _>("request")?, &aad)?;
    ensure!(!String::from_utf8_lossy(plain.expose()).contains(&password));
    let rows=sqlx::query("SELECT id,registration,generation,request FROM mdm_apple.attempts WHERE tenant_id=$1::uuid AND operation=$2").bind(case_tenant()).bind(set).fetch_all(&mut pg).await?;
    ensure!(!rows.is_empty());
    for row in rows {
        let owner = serde_json::to_string(&(
            row.try_get::<Uuid, _>("registration")?,
            row.try_get::<i64, _>("generation")?,
            row.try_get::<Uuid, _>("id")?,
        ))?;
        let aad = rss_mdm_native_protection::ProtectionContext::new(
            tenant,
            &owner,
            "apple.attempt.request",
            1,
        )?
        .derive();
        let plain = key.open_bytes(&row.try_get::<Vec<u8>, _>("request")?, &aad)?;
        ensure!(!String::from_utf8_lossy(plain.expose()).contains(&password));
    }
    let (attempt, _) = peer.next("VerifyRecoveryLock").await?;
    peer.manage(
        "Acknowledged",
        Some(attempt),
        Some(("PasswordVerified", true.into())),
    )
    .await?;
    f.app.execution.maintain_recovery_credentials().await?;
    let erased:bool=sqlx::query_scalar("SELECT sealed IS NULL AND key_id IS NULL FROM mdm_recovery.versions WHERE tenant_id=$1::uuid AND entry=$2 AND version=1").bind(case_tenant()).bind(Uuid::parse_str(lock["id"].as_str().unwrap())?).fetch_one(&mut pg).await?;
    ensure!(erased);
    // Clear authenticates with the unverified candidate but removes the whole lock object.
    let accepted=f.browser.call(&f.router,Method::POST,&format!("{path}/operations"),Some(json!({"operationId":Uuid::new_v4(),"registration":registration,"generation":generation,"deadline":f.app.clock.unix_seconds()?+300,"action":{"kind":"set_recovery_lock","expectedRevision":3,"current":{"id":lock["id"],"version":3},"clear":false}}))).await?;
    ensure!(accepted.0 == StatusCode::ACCEPTED);
    let (attempt, _) = peer.next("SetRecoveryLock").await?;
    peer.manage("Acknowledged", Some(attempt), None).await?;
    let accepted=f.browser.call(&f.router,Method::POST,&format!("{path}/operations"),Some(json!({"operationId":Uuid::new_v4(),"registration":registration,"generation":generation,"deadline":f.app.clock.unix_seconds()?+300,"action":{"kind":"set_recovery_lock","expectedRevision":4,"current":{"id":lock["id"],"version":4},"clear":true}}))).await?;
    ensure!(accepted.0 == StatusCode::ACCEPTED);
    let (attempt, payload) = peer.next("SetRecoveryLock").await?;
    ensure!(payload["NewPassword"].as_string() == Some(""));
    peer.manage("Acknowledged", Some(attempt), None).await?;
    let (_, list) = f.browser.call(&f.router, Method::GET, &path, None).await?;
    for version in list
        .as_array()
        .unwrap()
        .iter()
        .filter(|v| v["id"] == lock["id"])
    {
        ensure!(
            version["current"] == false
                && (version["validity"] == "revoked" || version["validity"] == "superseded")
        );
    }
    let (_, reply) = f
        .browser
        .call(
            &f.router,
            Method::GET,
            &format!("{path}/{}/versions/3/secret", lock["id"].as_str().unwrap()),
            None,
        )
        .await?;
    ensure!(reply.get("secret").is_none());
    let pending:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_recovery.versions WHERE tenant_id=$1::uuid AND entry=$2 AND pending)").bind(case_tenant()).bind(Uuid::parse_str(lock["id"].as_str().unwrap())?).fetch_one(&mut pg).await?;
    ensure!(!pending);
    pg.close().await?;

    drop(device);
    f.close().await
}
