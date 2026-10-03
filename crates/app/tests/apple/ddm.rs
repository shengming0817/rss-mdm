//! Production DDM native HTTP, protected Resource inputs and restart recovery.
use super::*;
use anyhow::Context;
use lifecycle::Peer;
use serde_json::Value;
use sqlx::{Connection, Row};

pub(super) fn declaration(id: &str, ty: &str, payload: Value) -> Value {
    fn field(value: Value) -> Value {
        match value {
            Value::String(v) => json!({"type":"string","value":v}),
            Value::Bool(v) => json!({"type":"boolean","value":v}),
            Value::Array(v) => {
                json!({"type":"array","value":v.into_iter().map(field).collect::<Vec<_>>()})
            }
            Value::Object(v) => {
                json!({"type":"dictionary","value":v.into_iter().map(|(k,v)|(k,field(v))).collect::<serde_json::Map<_,_>>()})
            }
            _ => {
                panic!("fixture payload supports native strings, booleans, dictionaries and arrays")
            }
        }
    }
    let fields = payload
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.clone(), field(v.clone())))
        .collect::<serde_json::Map<_, _>>();
    json!({"identifier":id,"declarationType":ty,"payload":fields})
}
pub(super) fn subscription(id: &str) -> Value {
    declaration(
        id,
        "com.apple.configuration.management.status-subscriptions",
        json!({"StatusItems":[{"Name":"management.declarations"},{"Name":"device.operating-system.version"}]}),
    )
}
pub(super) fn task(declarations: Vec<Value>, assets: Vec<Value>) -> Value {
    json!({"platform":"macos","request":{"kind":"declarations","declarations":declarations,"assets":assets}})
}
pub(super) async fn native(
    peer: &Peer,
    user: Option<Uuid>,
    endpoint: &str,
    data: Option<&Value>,
) -> Result<(StatusCode, Vec<u8>)> {
    let mut dictionary = protocol::dictionary([
        ("MessageType", "DeclarativeManagement".into()),
        (
            "UDID",
            crate::test_support::case::name("rss-t2-apple").into(),
        ),
        ("Endpoint", endpoint.into()),
    ]);
    if let Some(user) = user {
        dictionary.insert("UserID".into(), user.to_string().into());
    }
    if let Some(data) = data {
        dictionary.insert("Data".into(), plist::Value::Data(serde_json::to_vec(data)?));
    }
    let response = peer
        .client
        .put(format!("{}/checkin", peer.origin))
        .header("content-type", "application/xml")
        .body(protocol::xml(dictionary)?)
        .send()
        .await?;
    let status = response.status();
    if endpoint != "status" && status == StatusCode::OK {
        ensure!(
            response
                .headers()
                .get("content-type")
                .is_some_and(|v| v == "application/json")
        );
    }
    Ok((status, response.bytes().await?.to_vec()))
}
pub(super) async fn manifest(peer: &Peer, user: Option<Uuid>) -> Result<Value> {
    let (status, bytes) = native(peer, user, "declaration-items", None).await?;
    ensure!(
        status == StatusCode::OK,
        "native manifest {status}: {}",
        String::from_utf8_lossy(&bytes)
    );
    Ok(serde_json::from_slice(&bytes)?)
}
pub(super) fn report(manifest: &Value, active: bool, version: &str) -> Value {
    let mut declarations = serde_json::Map::new();
    for (family, native) in [
        ("Activations", "activations"),
        ("Configurations", "configurations"),
        ("Assets", "assets"),
        ("Management", "management"),
    ] {
        declarations.insert(native.into(), Value::Array(manifest["Declarations"][family].as_array().unwrap().iter().map(|v|
            json!({"identifier":v["Identifier"],"server-token":v["ServerToken"],"active":active,"valid":"valid"})
        ).collect()));
    }
    json!({"FullReport":true,"Errors":[],"StatusItems":{"management":{"declarations":declarations},"device":{"operating-system":{"version":version}}}})
}
pub(super) async fn grants(resources: bool) -> Result<()> {
    let mut grants = crate::test_support::identity::device_grants(
        Some(case_device()),
        &[
            "enrollment",
            "credentials",
            "inventory_read",
            "inventory_collect",
            "configuration_write",
            "operation_read",
            "operation_cancel",
        ],
    )?;
    if resources {
        for operation in [
            crate::authorization::Permission::ResourceRead,
            crate::authorization::Permission::ResourceWrite,
        ] {
            grants.push(crate::authorization::Grant {
                operation,
                scope: crate::authorization::Scope::Tenant,
            });
        }
    }
    crate::test_support::identity::set_grants(
        case_tenant(),
        crate::test_support::case::admin(),
        grants,
    )
    .await
}
#[tokio::test]
#[ignore = "MODULE=apple.ddm: real native four-family sync, assets and restart"]
async fn four_families_assets_recovery_and_withdrawal() -> Result<()> {
    let mut f = Fixture::start().await?;
    grants(true).await?;
    let (peer, device) = f.ready_local_peer().await?;
    let denied = f.browser.call(
        &f.router, Method::POST,
        &format!("/api/v3/devices/{}/operations", case_device()),
        Some(json!({"operationId":Uuid::new_v4(),"inputVersion":"interactive","target":{"kind":"device"},
            "task":task(vec![declaration("interactive","com.apple.configuration.legacy.interactive",
                json!({"ProfileURL":"https://external.invalid/sensitive.plist","VisibleName":"Interactive"}))],vec![]),
            "deadline":f.app.clock.unix_seconds()?+300})),
    ).await?;
    ensure!(
        denied.0 == StatusCode::UNPROCESSABLE_ENTITY,
        "interactive must fail admission: {denied:?}"
    );
    let resource = Uuid::new_v4();
    let content = json!({"fixture":"immutable-native-ddm-asset"});
    crate::test_support::planning_http::native_configuration_resource(
        &mut f.browser,
        &f.router,
        resource,
        "macos",
        "aarch64",
        content.clone(),
    )
    .await?;
    let reply = f
        .browser
        .call(
            &f.router,
            Method::GET,
            &format!("/api/v4/resources/{resource}"),
            None,
        )
        .await?;
    ensure!(reply.0 == StatusCode::OK, "Resource read {reply:?}");
    let asset = json!({"identifier":"asset","resource":resource,"version":"v1","variant":"default","versionDigest":reply.1["versions"][0]["digest"],"contentType":"application/json","profileSchemas":[]});
    let declarations = vec![
        subscription("subscriptions"),
        declaration(
            "activation",
            "com.apple.activation.simple",
            json!({"StandardConfigurations":["subscriptions"]}),
        ),
        declaration(
            "organization",
            "com.apple.management.organization-info",
            json!({"Name":"Fixture"}),
        ),
        declaration("asset", "com.apple.asset.data", json!({})),
    ];
    let operation = f
        .create_operation(|_| task(declarations, vec![asset]))
        .await?;
    let (id, command) = peer.next("DeclarativeManagement").await?;
    let initial = manifest(&peer, None).await?;
    for family in ["Activations", "Configurations", "Assets", "Management"] {
        ensure!(
            initial["Declarations"][family].as_array().unwrap().len() == 1,
            "{initial}"
        );
    }
    let token: Value = serde_json::from_slice(command["Data"].as_data().unwrap())?;
    ensure!(token["SyncTokens"]["DeclarationsToken"] == initial["DeclarationsToken"]);
    let (status, bytes) = native(&peer, None, "declaration/asset/asset", None).await?;
    ensure!(status == StatusCode::OK);
    let asset: Value = serde_json::from_slice(&bytes)?;
    ensure!(asset["Payload"]["Authentication"]["Type"] == "MDM");
    let url = asset["Payload"]["Reference"]["DataURL"]
        .as_str()
        .unwrap()
        .to_string();
    let response = peer.client.get(&url).send().await?;
    ensure!(response.status() == StatusCode::OK);
    ensure!(response.bytes().await?.as_ref() == serde_json::to_vec(&content)?);
    peer.manage("Acknowledged", Some(id), None).await?;
    ensure!(f.operation(operation).await?["commandStatus"] == "received");
    let status = report(&initial, true, "15.0");
    f.app
        .execution
        .inject_fault(rss_transactional_messaging_postgres::PgTransactionFault::CommitPending);
    ensure!(
        native(&peer, None, "status", Some(&status)).await?.0 == StatusCode::SERVICE_UNAVAILABLE
    );
    let mut fault_pg =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    let rolled_back:(i64,bool)=sqlx::query_as("SELECT (SELECT count(*) FROM mdm_apple.status_reports WHERE tenant_id=$1::uuid),projection IS NULL FROM mdm_apple.declarations WHERE tenant_id=$1::uuid AND operation=$2").bind(case_tenant()).bind(operation).fetch_one(&mut fault_pg).await?;
    ensure!(
        rolled_back == (0, true),
        "report or projection escaped failed transaction"
    );
    fault_pg.close().await?;
    ensure!(f.operation(operation).await?["commandStatus"] == "received");
    ensure!(native(&peer, None, "status", Some(&status)).await?.0 == StatusCode::OK);
    ensure!(native(&peer, None, "status", Some(&status)).await?.0 == StatusCode::OK);
    let result = f.operation(operation).await?;
    ensure!(
        result["commandStatus"] == "applied"
            && result["observation"]["effect"] == "unverified"
            && result["observation"]["compliance"] == "unknown",
        "{result}"
    );
    let mut pg =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    let row=sqlx::query("SELECT (SELECT count(*) FROM mdm_apple.status_reports WHERE tenant_id=$1::uuid) AS reports,snapshot FROM mdm_apple.declarations WHERE tenant_id=$1::uuid AND operation=$2")
        .bind(case_tenant()).bind(operation).fetch_one(&mut pg).await?;
    ensure!(
        row.try_get::<i64, _>("reports")? == 1,
        "duplicate report retained twice"
    );
    let encrypted: Vec<u8> = row.try_get("snapshot")?;
    ensure!(
        !encrypted
            .windows(b"immutable-native-ddm".len())
            .any(|v| v == b"immutable-native-ddm")
    );
    let cache: Vec<u8> = sqlx::query_scalar(
        "SELECT projection FROM mdm_apple.declarations WHERE tenant_id=$1::uuid AND operation=$2",
    )
    .bind(case_tenant())
    .bind(operation)
    .fetch_one(&mut pg)
    .await?;
    ensure!(
        serde_json::from_slice::<Value>(&cache).is_err(),
        "projection remained plaintext"
    );
    // Corrupt retained history as a storage fault: online reads must use protected accumulated claims.
    sqlx::query("UPDATE mdm_apple.status_reports SET evidence=$2 WHERE tenant_id=$1::uuid")
        .bind(case_tenant())
        .bind(vec![0u8; 68])
        .execute(&mut pg)
        .await?;
    pg.close().await?;
    let address = format!(
        "127.0.0.1:{}",
        reqwest::Url::parse(&peer.origin)?.port().unwrap()
    )
    .parse()?;
    f.close().await?;
    let mut f = Fixture::with_endpoint(None, Some(address), true).await?;
    ensure!(
        manifest(&peer, None).await? == initial,
        "restart changed native token"
    );
    ensure!(
        peer.client.get(&url).send().await?.bytes().await?.as_ref()
            == serde_json::to_vec(&content)?
    );
    ensure!(
        f.operation(operation).await?["observation"]["nativeStatus"]["synchronized"] == true,
        "restart lost accumulated native claims"
    );
    let replacement = f
        .create_operation(|_| task(vec![subscription("subscriptions")], vec![]))
        .await?;
    let (id, _) = peer.next("DeclarativeManagement").await?;
    peer.manage("Acknowledged", Some(id), None).await?;
    let next = manifest(&peer, None).await?;
    ensure!(next["DeclarationsToken"] != initial["DeclarationsToken"]);
    ensure!(
        native(&peer, None, "declaration/asset/asset", None)
            .await?
            .0
            == StatusCode::NOT_FOUND
    );
    ensure!(
        peer.client.get(&url).send().await?.status() == StatusCode::NOT_FOUND,
        "retired publication must return ordinary absence"
    );
    native(&peer, None, "status", Some(&status)).await?;
    ensure!(
        f.operation(replacement).await?["commandStatus"] == "received",
        "old token completed new input"
    );
    native(&peer, None, "status", Some(&report(&next, true, "15.0"))).await?;
    ensure!(f.operation(replacement).await?["commandStatus"] == "applied");
    // Removing an old asset requires its authority once; the replacement owns no asset.
    grants(false).await?;
    let withdrawal = f.create_operation(|_| task(vec![], vec![])).await?;
    let (id, _) = peer.next("DeclarativeManagement").await?;
    peer.manage("Acknowledged", Some(id), None).await?;
    let empty = manifest(&peer, None).await?;
    ensure!(
        ["Activations", "Configurations", "Assets", "Management"]
            .iter()
            .all(|family| empty["Declarations"][family].as_array().unwrap().is_empty())
    );
    native(&peer, None, "status", Some(&report(&empty, false, "15.0"))).await?;
    ensure!(
        f.operation(withdrawal).await?["commandStatus"] == "received",
        "unversioned absence fabricated effect"
    );
    let mut pg =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    let unguarded:bool=sqlx::query_scalar("SELECT bool_and(legacy_released_at IS NOT NULL) FROM mdm_apple.declarations WHERE tenant_id=$1::uuid").bind(case_tenant()).fetch_one(&mut pg).await?;
    ensure!(unguarded, "non-Legacy publication entered absence guards");
    sqlx::query("UPDATE mdm_apple.declarations SET snapshot=$2 WHERE tenant_id=$1::uuid AND retired_at IS NOT NULL").bind(case_tenant()).bind(vec![0u8;68]).execute(&mut pg).await?;
    pg.close().await?;
    f.create_operation(|id| profile_task(id, true)).await?;
    peer.next("InstallProfile").await?;
    drop(device);
    f.close().await
}

#[tokio::test]
#[ignore = "MODULE=apple.ddm: managed Profile takeover and independent withdrawal proof"]
async fn legacy_takeover_retains_guards_until_correlated_absence() -> Result<()> {
    let mut f = Fixture::start().await?;
    grants(true).await?;
    let (peer, device) = f.ready_local_peer().await?;
    let classic = f.create_operation(|id| profile_task(id, true)).await?;
    let (execute, payload) = peer.next("InstallProfile").await?;
    // Import unsigned native bytes from the actual attached CMS command payload.
    let signed = f.root.join("legacy-signed.der");
    let unsigned = f.root.join("legacy-unsigned.plist");
    std::fs::write(&signed, payload["Payload"].as_data().unwrap())?;
    scep_client::openssl(&[
        "cms".as_ref(),
        "-verify".as_ref(),
        "-binary".as_ref(),
        "-noverify".as_ref(),
        "-inform".as_ref(),
        "DER".as_ref(),
        "-in".as_ref(),
        signed.as_os_str(),
        "-out".as_ref(),
        unsigned.as_os_str(),
    ])?;
    let native_profile_bytes = std::fs::read(unsigned)?;
    let bytes = peer.manage("Acknowledged", Some(execute), None).await?;
    let (observe, query) = lifecycle::command(&bytes, "ProfileList")?;
    ensure!(
        query["ManagedOnly"].as_boolean() == Some(true),
        "takeover lacks managed-only native query"
    );
    let managed = profile_manifest(classic, "com.apple.security.firewall");
    peer.manage(
        "Acknowledged",
        Some(observe),
        Some(("ProfileList", managed.clone())),
    )
    .await?;
    ensure!(f.operation(classic).await?["commandStatus"] == "applied");
    let resource = Uuid::new_v4();
    crate::test_support::planning_http::native_configuration_bytes(
        &mut f.browser,
        &f.router,
        resource,
        "macos",
        "aarch64",
        &native_profile_bytes,
    )
    .await?;
    let reply = f
        .browser
        .call(
            &f.router,
            Method::GET,
            &format!("/api/v4/resources/{resource}"),
            None,
        )
        .await?;
    ensure!(reply.0 == StatusCode::OK);
    let asset = json!({"identifier":"legacy","resource":resource,"version":"v1","variant":"default","versionDigest":reply.1["versions"][0]["digest"],"contentType":"application/x-apple-aspen-config","profileSchemas":["mdm/profiles/com.apple.security.firewall.yaml"]});
    let takeover = f
        .create_operation(|_| {
            task(
                vec![
                    declaration("legacy", "com.apple.configuration.legacy", json!({})),
                    declaration(
                        "activation",
                        "com.apple.activation.simple",
                        json!({"StandardConfigurations":["legacy"]}),
                    ),
                ],
                vec![asset],
            )
        })
        .await?;
    let (execute, _) = peer.next("DeclarativeManagement").await?;
    peer.manage("Acknowledged", Some(execute), None).await?;
    let published = manifest(&peer, None).await?;
    native(
        &peer,
        None,
        "status",
        Some(&report(&published, true, "15.0")),
    )
    .await?;
    ensure!(f.operation(takeover).await?["commandStatus"] == "applied");
    let mut pg =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    let retired:bool=sqlx::query_scalar("SELECT retired_at IS NOT NULL FROM mdm_apple.profiles WHERE tenant_id=$1::uuid AND operation=$2").bind(case_tenant()).bind(classic).fetch_one(&mut pg).await?;
    ensure!(retired, "native takeover retained classic ownership");
    let withdrawal = f.create_operation(|_| task(vec![], vec![])).await?;
    let (execute, _) = peer.next("DeclarativeManagement").await?;
    let bytes = peer.manage("Acknowledged", Some(execute), None).await?;
    let (observe, _) = lifecycle::command(&bytes, "ProfileList")?;
    peer.manage(
        "Acknowledged",
        Some(observe),
        Some(("ProfileList", managed)),
    )
    .await?;
    ensure!(f.operation(withdrawal).await?["commandStatus"] == "received");
    let protected:bool=sqlx::query_scalar("SELECT retired_at IS NOT NULL AND legacy_released_at IS NULL FROM mdm_apple.declarations WHERE tenant_id=$1::uuid AND operation=$2").bind(case_tenant()).bind(takeover).fetch_one(&mut pg).await?;
    ensure!(protected, "ACK or present Profile released withdrawn guard");
    f.profile_query_due(withdrawal).await?;
    let (observe, _) = peer.next("ProfileList").await?;
    peer.manage(
        "Acknowledged",
        Some(observe),
        Some(("ProfileList", plist::Value::Array(vec![]))),
    )
    .await?;
    ensure!(f.operation(withdrawal).await?["commandStatus"] == "applied");
    let released:bool=sqlx::query_scalar("SELECT legacy_released_at IS NOT NULL FROM mdm_apple.declarations WHERE tenant_id=$1::uuid AND operation=$2").bind(case_tenant()).bind(takeover).fetch_one(&mut pg).await?;
    ensure!(released);
    pg.close().await?;
    let replacement = f.create_operation(|id| profile_task(id, false)).await?;
    let (execute, _) = peer.next("InstallProfile").await?;
    let bytes = peer.manage("Acknowledged", Some(execute), None).await?;
    let (observe, _) = lifecycle::command(&bytes, "ProfileList")?;
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

#[tokio::test]
#[ignore = "MODULE=apple.ddm: coowner publication and logical policy withdrawal"]
async fn policy_coowners_share_native_publication_without_fabricating_removal() -> Result<()> {
    let mut f = Fixture::start().await?;
    let mut grants = crate::test_support::identity::device_grants(
        Some(case_device()),
        &[
            "enrollment",
            "credentials",
            "inventory_read",
            "inventory_collect",
            "configuration_write",
            "operation_read",
            "operation_cancel",
        ],
    )?;
    for operation in [
        crate::authorization::Permission::ResourceRead,
        crate::authorization::Permission::ResourceWrite,
        crate::authorization::Permission::PolicyRead,
        crate::authorization::Permission::PolicyWrite,
        crate::authorization::Permission::ScopeRead,
        crate::authorization::Permission::ScopeWrite,
    ] {
        grants.push(crate::authorization::Grant {
            operation,
            scope: crate::authorization::Scope::Tenant,
        });
    }
    grants.extend(crate::test_support::identity::device_grants(
        None,
        &["inventory_read", "configuration_write"],
    )?);
    crate::test_support::identity::set_grants(
        case_tenant(),
        crate::test_support::case::admin(),
        grants,
    )
    .await?;
    let (peer, device) = f.ready_local_peer().await?;
    let mut owner = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(15))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let automation = crate::automation::Automation::connect(
        f.app.flow.planning.clone(),
        f.app.flow.assets.clone(),
        f.app.flow.compliance.clone(),
        crate::device::test_support::options("mdm_flow_runtime")?.password("runtime-fixture"),
    )
    .await?;
    let mut startup = owner.startup()?;
    startup.stage_resource(rss_runtime::DynManagedResource::new_box(
        crate::automation::Resource(automation.clone()),
    ));
    let mut launch = startup.commit();
    launch.stage_deferred_task_with_token(automation.registration(f.signals.flow()).critical());
    launch.finish();
    let resource = Uuid::new_v4();
    crate::test_support::planning_http::native_configuration_resource(&mut f.browser,&f.router,resource,"macos","aarch64",
        json!({"target":{"kind":"device"},"apply":task(vec![subscription("policy-subscriptions")],vec![]),"remove":task(vec![],vec![])})).await?;
    let scope = Uuid::new_v4();
    f.policy_post(&format!("/api/v2/scopes/{scope}"),0,json!({"action":"put","definition":{"targets":[{"kind":"device","id":case_device()}],"limitations":null,"exclusions":[]}})).await?;
    let definition = json!({"scope":scope,"action":{"resource":{"id":resource,"version":"v1","platform":"macos","architecture":"aarch64","variant":"default"},"kind":"configuration","exit":"remove"}});
    let first = Uuid::new_v4();
    let second = Uuid::new_v4();
    f.policy_post(
        &format!("/api/v3/policies/{first}"),
        0,
        json!({"action":"put","enabled":true,"definition":definition}),
    )
    .await?;
    let applied = f.policy_operation(first).await?;
    let (execute, _) = peer.next("DeclarativeManagement").await?;
    peer.manage("Acknowledged", Some(execute), None).await?;
    let initial = manifest(&peer, None).await?;
    native(&peer, None, "status", Some(&report(&initial, true, "15.0"))).await?;
    ensure!(f.operation(applied).await?["commandStatus"] == "applied");
    f.policy_post(
        &format!("/api/v3/policies/{second}"),
        0,
        json!({"action":"put","enabled":true,"definition":definition}),
    )
    .await?;
    ensure!(f.policy_operation(second).await? == applied);
    f.policy_post(
        &format!("/api/v3/policies/{first}"),
        1,
        json!({"action":"disable"}),
    )
    .await?;
    ensure!(f.policy_operation(second).await? == applied);
    ensure!(
        manifest(&peer, None).await? == initial,
        "one coowner removed a shared declaration"
    );
    f.policy_post(
        &format!("/api/v3/policies/{second}"),
        1,
        json!({"action":"disable"}),
    )
    .await?;
    let (execute, _) = peer.next("DeclarativeManagement").await?;
    peer.manage("Acknowledged", Some(execute), None).await?;
    ensure!(
        manifest(&peer, None).await?["Declarations"]["Configurations"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let mut pg =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    let withdrawal: Uuid = sqlx::query_scalar(
        "SELECT operation FROM mdm_apple.attempts WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(case_tenant())
    .bind(execute)
    .fetch_one(&mut pg)
    .await?;
    tokio::time::timeout(Duration::from_secs(30),async { loop {
        let count:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_planning.configuration_claims WHERE tenant_id=$1::uuid AND device=$2").bind(case_tenant()).bind(case_device()).fetch_one(&mut pg).await?;
        if count==0 {return Ok::<_,anyhow::Error>(());}
        tokio::time::sleep(Duration::from_millis(50)).await;
    }}).await.context("logical configuration claims were not released after publication withdrawal")??;
    ensure!(
        f.operation(withdrawal).await?["commandStatus"] == "received",
        "publication withdrawal claimed native removal"
    );
    ensure!(f.operation(withdrawal).await?["observation"]["effect"] == "unverified");
    let retained = Uuid::new_v4();
    let mut retain_definition = definition.clone();
    retain_definition["action"]["exit"] = json!("retain");
    f.policy_post(
        &format!("/api/v3/policies/{retained}"),
        0,
        json!({"action":"put","enabled":true,"definition":retain_definition}),
    )
    .await?;
    let retained_operation = f.policy_operation(retained).await?;
    let (execute, _) = peer.next("DeclarativeManagement").await?;
    peer.manage("Acknowledged", Some(execute), None).await?;
    let retained_manifest = manifest(&peer, None).await?;
    native(
        &peer,
        None,
        "status",
        Some(&report(&retained_manifest, true, "15.0")),
    )
    .await?;
    ensure!(f.operation(retained_operation).await?["commandStatus"] == "applied");
    f.policy_post(
        &format!("/api/v3/policies/{retained}"),
        1,
        json!({"action":"disable"}),
    )
    .await?;
    ensure!(
        manifest(&peer, None).await? == retained_manifest,
        "retain changed native collection"
    );
    crate::test_support::identity::set_grants(
        case_tenant(),
        crate::test_support::case::admin(),
        crate::test_support::identity::device_grants(
            Some(case_device()),
            &["inventory_read", "operation_read"],
        )?,
    )
    .await?;
    ensure!(
        manifest(&peer, None).await?["Declarations"]["Configurations"]
            .as_array()
            .unwrap()
            .is_empty(),
        "retained publication outlived current authority"
    );
    pg.close().await?;
    ensure!(owner.shutdown().join().await?.is_clean());
    drop(device);
    f.close().await
}
