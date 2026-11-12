//! Real Policy role and Apple protocol consumers of configuration history.
use super::*;
use crate::planning_t2_support as planning;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::Acquire;
use std::{collections::BTreeMap, time::Duration};
fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}
async fn plist_send(
    d: &rss_mdm_apple_channel::delivery::Delivery,
    apple: &Arc<rss_mdm_apple_channel::Apple>,
    p: &rss_mdm_registration_service::DevicePrincipal,
    c: &Context,
    dict: plist::Dictionary,
) -> Result<Vec<u8>> {
    let mut bytes = vec![];
    plist::to_writer_xml(&mut bytes, &dict)?;
    manage(d, apple, p, c, bytes).await
}
async fn idle(
    d: &rss_mdm_apple_channel::delivery::Delivery,
    apple: &Arc<rss_mdm_apple_channel::Apple>,
    p: &rss_mdm_registration_service::DevicePrincipal,
    c: &Context,
) -> Result<plist::Dictionary> {
    let mut dict = plist::Dictionary::new();
    dict.insert("UDID".into(), p.device().into());
    dict.insert("Status".into(), "Idle".into());
    let bytes = plist_send(d, apple, p, c, dict).await?;
    Ok(if bytes.is_empty() {
        plist::Dictionary::new()
    } else {
        rss_mdm_apple_mdm::protocol::decode(&bytes)?
    })
}
async fn manifest(
    d: &rss_mdm_apple_channel::delivery::Delivery,
    apple: &Arc<rss_mdm_apple_channel::Apple>,
    p: &rss_mdm_registration_service::DevicePrincipal,
    c: &Context,
) -> Result<Value> {
    let mut dict = plist::Dictionary::new();
    dict.insert("MessageType".into(), "DeclarativeManagement".into());
    dict.insert("UDID".into(), p.device().into());
    dict.insert("Endpoint".into(), "declaration-items".into());
    let exchange = rss_mdm_apple_channel::ddm::prepare(apple.clone(), &dict, None)?;
    let reply = d
        .ddm(p, exchange, &audit(c))
        .await
        .map_err(|e| anyhow::anyhow!("DDM manifest {e:?}"))?;
    assert_eq!(reply.status, 200);
    Ok(serde_json::from_slice(&reply.bytes)?)
}
fn object(device: &str) -> Result<rss_mdm_inventory_service::objects::DeviceObject> {
    Ok(serde_json::from_value(
        json!({"object":{"kind":"endpoint","id":device},"associationVersion":null,"verified":true,"members":[{"device":device,"channel":"mdm"}]}),
    )?)
}
async fn persist_policy(
    c: &Context,
    id: Uuid,
    version: Uuid,
    definition: Value,
    frozen: Value,
) -> Result<()> {
    let actor = rss_mdm_authorization_service::Actor::Account {
        user: c.user(Uuid::new_v4()),
    };
    let kind = definition["action"]["kind"].as_str().unwrap().to_owned();
    let mut tx = command::seed_transaction(c).await?;
    sqlx::query("INSERT INTO mdm_policy.policies(tenant_id,id,revision,current_version,version_number,state,definition,author,updated_at) VALUES($1::uuid,$2,1,$3,1,'enabled',$4,$5,$6)").bind(c.tenant.to_string()).bind(id).bind(version).bind(definition).bind(serde_json::to_value(actor)?).bind(now()).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_policy.versions(tenant_id,id,policy,number,action_kind,resource,resource_version,frozen,fingerprint) VALUES($1::uuid,$2,$3,1,$4,'policy-apple-test','1',$5,$6)").bind(c.tenant.to_string()).bind(version).bind(id).bind(kind).bind(&frozen).bind(Sha256::digest(serde_json::to_vec(&frozen)?).to_vec()).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}
async fn seed_catalog(c: &Context) -> Result<()> {
    let mut tx = command::seed_transaction(c).await?;
    sqlx::query("SELECT mdm.seed_tenant_catalog($1::uuid)")
        .bind(c.tenant.to_string())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}
async fn next_command(
    d: &rss_mdm_apple_channel::delivery::Delivery,
    apple: &Arc<rss_mdm_apple_channel::Apple>,
    p: &rss_mdm_registration_service::DevicePrincipal,
    c: &Context,
    wanted: &str,
) -> Result<plist::Dictionary> {
    let mut profiles = Vec::new();
    let mut packet = idle(d, apple, p, c).await?;
    for _ in 0..12 {
        let command = packet
            .get("Command")
            .and_then(plist::Value::as_dictionary)
            .ok_or_else(|| anyhow::anyhow!("no Apple command while waiting for {wanted}"))?;
        let kind = command
            .get("RequestType")
            .and_then(plist::Value::as_string)
            .unwrap_or("");
        let template = command
            .get("Queries")
            .and_then(plist::Value::as_array)
            .is_some_and(|a| a.iter().any(|v| v.as_string() == Some("SerialNumber")));
        if kind == wanted && (wanted != "DeviceInformation" || template) {
            return Ok(packet);
        }
        let id = packet
            .get("CommandUUID")
            .and_then(plist::Value::as_string)
            .unwrap()
            .to_owned();
        let mut response = plist::Dictionary::new();
        response.insert("UDID".into(), p.device().into());
        response.insert("Status".into(), "Acknowledged".into());
        response.insert("CommandUUID".into(), id.into());
        match kind {
            "DeviceInformation" => {
                let mut values = plist::Dictionary::new();
                values.insert("OSVersion".into(), "26.0".into());
                values.insert("IsSupervised".into(), true.into());
                values.insert("IsAppleSilicon".into(), true.into());
                response.insert("QueryResponses".into(), values.into());
            }
            "InstallProfile" => {
                use tokio::io::AsyncWriteExt;
                let payload = command
                    .get("Payload")
                    .and_then(plist::Value::as_data)
                    .unwrap();
                let mut child = tokio::process::Command::new("openssl")
                    .args(["cms", "-verify", "-noverify", "-inform", "DER"])
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()?;
                child.stdin.as_mut().unwrap().write_all(payload).await?;
                drop(child.stdin.take());
                let result = child.wait_with_output().await?;
                assert!(result.status.success());
                let profile = plist::Value::from_reader(std::io::Cursor::new(result.stdout))?;
                profiles.push(profile);
            }
            "ProfileList" => {
                assert!(!profiles.is_empty());
                response.insert("ProfileList".into(), plist::Value::Array(profiles.clone()));
            }
            "SecurityInfo" => {
                let mut management = plist::Dictionary::new();
                management.insert("IsUserEnrollment".into(), false.into());
                management.insert("EnrolledViaDEP".into(), true.into());
                management.insert("UserApprovedEnrollment".into(), true.into());
                let mut security = plist::Dictionary::new();
                security.insert("ManagementStatus".into(), management.into());
                response.insert("SecurityInfo".into(), security.into());
            }
            _ => anyhow::bail!("unexpected prerequisite {kind}, expected {wanted}"),
        }
        let bytes = plist_send(d, apple, p, c, response).await?;
        packet = if bytes.is_empty() {
            idle(d, apple, p, c).await?
        } else {
            rss_mdm_apple_mdm::protocol::decode(&bytes)?
        };
    }
    anyhow::bail!("Apple prerequisites did not complete for {wanted}")
}
async fn reconcile(
    c: &Context,
    owner: &crate::owner_storage::OwnerRuntime,
    cfg: &Arc<rss_mdm_policy_service::configuration::Transactions>,
    device: &str,
) -> Result<()> {
    for pass in 0..3 {
        let audit = audit(c);
        audit.identify_service("policy-apple-test");
        rss_mdm_policy_service::transaction::run(
            &owner.audit,
            &owner.runtime,
            c.tenant,
            &audit,
            (cfg, device, &audit, &owner.audit),
            |ctx, tx| {
                Box::pin(async move {
                    ctx.3.prepare_in(tx, ctx.2, &[]).await?;
                    ctx.0.wake_devices_in(tx, &[ctx.1.to_owned()]).await?;
                    ctx.0.reconcile_in(tx, ctx.1, ctx.2).await
                })
            },
        )
        .await
        .map_err(|e| anyhow::anyhow!("configuration reconcile pass {pass}: {e:?}"))?;
        audit.finalize(None);
        let timer = rss_mdm_policy_service::clock::Timer::new();
        let cancel = tokio_util::sync::CancellationToken::new();
        let control = rss_reconcile::Control::new(&timer, Duration::from_secs(10), &cancel);
        while cfg.relay_once(&control).await? > 0 {}
    }
    Ok(())
}
#[tokio::test]
#[ignore = "T2: two real Policy owners share Apple DDM publication, retain after first exit and publish withdrawal without claiming native removal"]
async fn ddm_policy_coowners_share_publication_and_only_last_exit_withdraws() -> Result<()> {
    use rss_mdm_apple_mdm::native::{
        ddm::DeclarationInput,
        input::{FieldValue as F, Fields},
    };
    use rss_mdm_policy_service::configuration::{
        Configuration, NativeTarget, Owner, Protected, Task, frozen::Frozen,
    };
    let c = Context::open("shared", &[]).await?;
    seed_catalog(&c).await?;
    let n = identity::seed(&c, "apple").await?;
    let key = crate::device_material_support::protection(&c)?;
    let (apple, p) = support::apple(&c, &n, key.clone(), &[]).await?;
    let scope = planning::published(&c, &object(&n.device)?).await?.scope;
    let declaration = DeclarationInput {
        identifier: "policy-subscriptions".into(),
        declaration_type: "com.apple.configuration.management.status-subscriptions".into(),
        payload: Fields(BTreeMap::from([(
            "StatusItems".into(),
            F::Array(vec![F::Dictionary(Fields(BTreeMap::from([(
                "Name".into(),
                F::String("management.declarations".into()),
            )])))]),
        )])),
    };
    let native = Configuration {
        target: NativeTarget::Device,
        apply: Task::Macos {
            request: rss_mdm_apple_mdm::native::request::Request::Declarations {
                declarations: vec![declaration],
                assets: vec![],
            },
        },
        remove: Some(Task::Macos {
            request: rss_mdm_apple_mdm::native::request::Request::Declarations {
                declarations: vec![],
                assets: vec![],
            },
        }),
    };
    native.validate()?;
    let owner = planning::owner(&c, "mdm_policy_runtime").await?;
    let app = crate::assembly::policy::application(
        &owner,
        c.tenant,
        &[7; 32],
        Arc::new(crate::clock::SystemClock),
        key.clone(),
        None,
    )
    .await?;
    let cfg = app.configuration.as_ref().unwrap();
    let mut seed = command::seed_transaction(&c).await?;
    sqlx::query(
        "INSERT INTO mdm_planning.configuration_devices(tenant_id,device) VALUES($1::uuid,$2)",
    )
    .bind(c.tenant.to_string())
    .bind(&n.device)
    .execute(&mut *seed)
    .await?;
    seed.commit().await?;
    let a = Fixture::open(&c, false).await?;
    let d = delivery(&c, &a).await?;
    let first = Uuid::new_v4();
    let second = Uuid::new_v4();
    for (policy, initial) in [(first, true), (second, false)] {
        let version = Uuid::new_v4();
        let frozen = Frozen::Configuration {
            native: Protected::seal(&key, c.tenant, Owner::Policy { policy, version }, &native)?,
            platform: rss_mdm_policy::Platform::Macos,
            exit: rss_mdm_policy::Exit::Remove,
            resource_digest: [1; 32],
        };
        persist_policy(&c,policy,version,json!({"scope":scope,"action":{"resource":{"id":"policy-apple-test","version":"1","platform":"macos","architecture":"aarch64","variant":"default"},"kind":"configuration","exit":"remove"}}),serde_json::to_value(frozen)?).await?;
        reconcile(&c, &owner, cfg, &n.device).await?;
        if initial {
            let packet = next_command(&d, &apple, &p, &c, "DeclarativeManagement").await?;
            assert_eq!(
                packet
                    .get("Command")
                    .and_then(plist::Value::as_dictionary)
                    .and_then(|v| v.get("RequestType"))
                    .and_then(plist::Value::as_string),
                Some("DeclarativeManagement")
            );
            let id = Uuid::parse_str(
                packet
                    .get("CommandUUID")
                    .and_then(plist::Value::as_string)
                    .unwrap(),
            )?;
            manage(&d, &apple, &p, &c, receipt(&n.device, id, None)?).await?;
        }
    }
    let initial = manifest(&d, &apple, &p, &c).await?;
    assert!(
        !initial["Declarations"]["Configurations"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let commands: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM mdm_planning.configuration_operations WHERE tenant_id=$1::uuid",
    )
    .bind(c.tenant.to_string())
    .fetch_one(&c.operator)
    .await?;
    assert_eq!(commands, 1);
    let mut tx = command::seed_transaction(&c).await?;
    sqlx::query("UPDATE mdm_policy.policies SET state='disabled',revision=revision+1 WHERE tenant_id=$1::uuid AND id=$2").bind(c.tenant.to_string()).bind(first).execute(&mut *tx).await?;
    tx.commit().await?;
    reconcile(&c, &owner, cfg, &n.device).await?;
    assert_eq!(manifest(&d, &apple, &p, &c).await?, initial);
    let commands: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM mdm_planning.configuration_operations WHERE tenant_id=$1::uuid",
    )
    .bind(c.tenant.to_string())
    .fetch_one(&c.operator)
    .await?;
    assert_eq!(commands, 1);
    let mut tx = command::seed_transaction(&c).await?;
    sqlx::query("UPDATE mdm_policy.policies SET state='disabled',revision=revision+1 WHERE tenant_id=$1::uuid AND id=$2").bind(c.tenant.to_string()).bind(second).execute(&mut *tx).await?;
    tx.commit().await?;
    reconcile(&c, &owner, cfg, &n.device).await?;
    let packet = next_command(&d, &apple, &p, &c, "DeclarativeManagement").await?;
    assert_eq!(
        packet
            .get("Command")
            .and_then(plist::Value::as_dictionary)
            .and_then(|v| v.get("RequestType"))
            .and_then(plist::Value::as_string),
        Some("DeclarativeManagement")
    );
    let attempt = Uuid::parse_str(
        packet
            .get("CommandUUID")
            .and_then(plist::Value::as_string)
            .unwrap(),
    )?;
    manage(&d, &apple, &p, &c, receipt(&n.device, attempt, None)?).await?;
    assert!(
        manifest(&d, &apple, &p, &c).await?["Declarations"]["Configurations"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let status:String=sqlx::query_scalar("SELECT d.status FROM mdm_apple.attempts a JOIN rss_device_command.commands d ON(d.tenant_id,d.command_id)=(a.tenant_id,a.operation::text) WHERE a.tenant_id=$1::uuid AND a.id=$2").bind(c.tenant.to_string()).bind(attempt).fetch_one(&c.operator).await?;
    assert_eq!(status, "received");
    drop(d);
    Fixture::close(a).await?;
    drop(app);
    drop(owner);
    c.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "T2: Policy reserves and reads profiles under its real runtime role; signed dispatch and native observation retain ownership"]
async fn policy_profile_reservation_dispatch_and_observation() -> Result<()> {
    use rss_mdm_apple_mdm::native::{
        input::{FieldValue, Fields},
        profiles::{PayloadInput, ProfileInput},
    };
    use rss_mdm_policy_service::configuration::{
        Configuration, NativeTarget, Owner, Protected, Task, frozen::Frozen,
    };
    let c = Context::open("shared", &[]).await?;
    seed_catalog(&c).await?;
    let n = identity::seed(&c, "apple").await?;
    let key = crate::device_material_support::protection(&c)?;
    let (apple, p) = support::apple(&c, &n, key.clone(), &[]).await?;
    let scope = planning::published(&c, &object(&n.device)?).await?.scope;
    let profile = ProfileInput {
        identifier: "org.example.policy.firewall".into(),
        uuid: Uuid::new_v4(),
        metadata: Fields::default(),
        payloads: vec![PayloadInput {
            schema: "mdm/profiles/com.apple.security.firewall.yaml".into(),
            identifier: "org.example.policy.firewall.payload".into(),
            uuid: Uuid::new_v4(),
            metadata: Fields::default(),
            fields: Fields(BTreeMap::from([(
                "EnableFirewall".into(),
                FieldValue::Boolean(true),
            )])),
        }],
    };
    let native = Configuration {
        target: NativeTarget::Device,
        apply: Task::Macos {
            request: rss_mdm_apple_mdm::native::request::Request::InstallProfile { profile },
        },
        remove: None,
    };
    native.validate()?;
    let policy = Uuid::new_v4();
    let version = Uuid::new_v4();
    let frozen = Frozen::Configuration {
        native: Protected::seal(&key, c.tenant, Owner::Policy { policy, version }, &native)?,
        platform: rss_mdm_policy::Platform::Macos,
        exit: rss_mdm_policy::Exit::Retain,
        resource_digest: [2; 32],
    };
    persist_policy(&c, policy, version, json!({"scope":scope,"action":{"resource":{"id":"policy-apple-test","version":"1","platform":"macos","architecture":"aarch64","variant":"default"},"kind":"configuration","exit":"retain"}}), serde_json::to_value(frozen)?).await?;
    let owner = planning::owner(&c, "mdm_policy_runtime").await?;
    let app = crate::assembly::policy::application(
        &owner,
        c.tenant,
        &[7; 32],
        Arc::new(crate::clock::SystemClock),
        key.clone(),
        None,
    )
    .await?;
    let cfg = app.configuration.as_ref().unwrap();
    let a = Fixture::open(&c, false).await?;
    let d = delivery(&c, &a).await?;
    reconcile(&c, &owner, cfg, &n.device).await?;
    let packet = next_command(&d, &apple, &p, &c, "InstallProfile").await?;
    let payload = packet["Command"].as_dictionary().unwrap()["Payload"]
        .as_data()
        .unwrap();
    use tokio::io::AsyncWriteExt;
    let mut child = tokio::process::Command::new("openssl")
        .args(["cms", "-verify", "-noverify", "-inform", "DER"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    child.stdin.as_mut().unwrap().write_all(payload).await?;
    drop(child.stdin.take());
    let signed = child.wait_with_output().await?;
    assert!(signed.status.success());
    let manifest = plist::Value::from_reader(std::io::Cursor::new(signed.stdout))?;
    let attempt = Uuid::parse_str(packet["CommandUUID"].as_string().unwrap())?;
    let response = manage(&d, &apple, &p, &c, receipt(&n.device, attempt, None)?).await?;
    let query = if response.is_empty() {
        next_command(&d, &apple, &p, &c, "ProfileList").await?
    } else {
        rss_mdm_apple_mdm::protocol::decode(&response)?
    };
    assert_eq!(
        query["Command"].as_dictionary().unwrap()["RequestType"].as_string(),
        Some("ProfileList")
    );
    let mut report = plist::Dictionary::new();
    report.insert("UDID".into(), n.device.clone().into());
    report.insert("Status".into(), "Acknowledged".into());
    report.insert("CommandUUID".into(), query["CommandUUID"].clone());
    report.insert("ProfileList".into(), plist::Value::Array(vec![manifest]));
    plist_send(&d, &apple, &p, &c, report).await?;
    reconcile(&c, &owner, cfg, &n.device).await?;
    let observed: (i64,bool) = sqlx::query_as("SELECT count(*),bool_and(observed_at IS NOT NULL) FROM mdm_apple.profiles WHERE tenant_id=$1::uuid AND identifier='org.example.policy.firewall'").bind(c.tenant.to_string()).fetch_one(&c.operator).await?;
    assert_eq!(observed, (1, true));
    drop(d);
    Fixture::close(a).await?;
    drop(app);
    drop(owner);
    c.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "T2: exact Apple and Recovery permissions are admitted on a Policy login with forced tenant RLS"]
async fn policy_channel_permissions_are_exact_and_tenant_scoped() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let pool = c.inputs.pool("shared", "mdm_policy_runtime").await?;
    let mut connection = pool.acquire().await?;
    rss_mdm_apple_channel::flow_store::verify_policy_access_on(&mut connection).await?;
    rss_mdm_recovery_credentials::native::storage::verify_policy_access_on(&mut connection).await?;
    let other = identity::seed(&c, "apple").await?;
    let mut tx = connection.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(Uuid::new_v4().to_string())
        .execute(&mut *tx)
        .await?;
    let visible: i64 = sqlx::query_scalar(
        "SELECT count(tenant_id) FROM mdm_apple.profiles WHERE tenant_id=$1::uuid AND device=$2",
    )
    .bind(c.tenant.to_string())
    .bind(other.device)
    .fetch_one(&mut *tx)
    .await?;
    assert_eq!(visible, 0);
    tx.rollback().await?;
    drop(connection);
    pool.close().await;
    c.close().await;
    Ok(())
}
