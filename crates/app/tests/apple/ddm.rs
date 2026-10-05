//! Production DDM native HTTP, protected Resource inputs and restart recovery.
use super::*;
use anyhow::Context;
use lifecycle::Peer;
use serde_json::Value;
use sqlx::Connection;

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
#[tokio::test]
#[ignore = "MODULE=apple.ddm: coowner publication and logical policy withdrawal"]
async fn policy_coowners_share_native_publication_without_fabricating_removal() -> Result<()> {
    let mut f = Fixture::start().await?;
    f.policy_grants().await?;
    let (peer, device) = f.ready_local_peer().await?;
    let owner = f.policy_worker().await?;
    let resource = Uuid::new_v4();
    crate::test_support::planning_http::native_configuration_resource(&mut f.browser,&f.router,resource,"macos","aarch64",
        json!({"target":{"kind":"device"},"apply":task(vec![subscription("policy-subscriptions")],vec![]),"remove":task(vec![],vec![])})).await?;
    let scope = Uuid::new_v4();
    f.policy_post(&format!("/api/v1/scopes/{scope}"),0,json!({"action":"put","definition":{"targets":[{"kind":"device","id":case_device()}],"limitations":null,"exclusions":[]}})).await?;
    let definition = json!({"scope":scope,"action":{"resource":{"id":resource,"version":"v1","platform":"macos","architecture":"aarch64","variant":"default"},"kind":"configuration","exit":"remove"}});
    let first = Uuid::new_v4();
    let second = Uuid::new_v4();
    f.policy_post(
        &format!("/api/v1/policies/{first}"),
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
        &format!("/api/v1/policies/{second}"),
        0,
        json!({"action":"put","enabled":true,"definition":definition}),
    )
    .await?;
    ensure!(f.policy_operation(second).await? == applied);
    f.policy_post(
        &format!("/api/v1/policies/{first}"),
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
        &format!("/api/v1/policies/{second}"),
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
        &format!("/api/v1/policies/{retained}"),
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
        &format!("/api/v1/policies/{retained}"),
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

#[tokio::test]
#[ignore = "MODULE=apple.ddm: managed Profile takeover and independent withdrawal proof"]
async fn legacy_takeover_retains_guards_until_correlated_absence() -> Result<()> {
    let mut f = Fixture::start().await?;
    f.policy_grants().await?;
    let (peer, device) = f.ready_local_peer().await?;
    let owner = f.policy_worker().await?;
    let profile = Uuid::new_v4();
    let (classic_policy, classic) = f
        .configuration_policy(profile_task(profile, true), None, "retain")
        .await?;
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
    let managed = profile_manifest(profile, "com.apple.security.firewall");
    peer.manage(
        "Acknowledged",
        Some(observe),
        Some(("ProfileList", managed.clone())),
    )
    .await?;
    ensure!(f.operation(classic).await?["commandStatus"] == "applied");
    f.policy_post(
        &format!("/api/v1/policies/{classic_policy}"),
        1,
        json!({"action":"disable"}),
    )
    .await?;
    f.policy_claims_released(classic_policy).await?;
    let mut pg =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    let guarded: bool = sqlx::query_scalar("SELECT retired_at IS NULL FROM mdm_apple.profiles WHERE tenant_id=$1::uuid AND operation=$2")
        .bind(case_tenant()).bind(classic).fetch_one(&mut pg).await?;
    ensure!(
        guarded,
        "classic Policy retain released native ownership before takeover"
    );
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
            &format!("/api/v1/resources/{resource}"),
            None,
        )
        .await?;
    ensure!(reply.0 == StatusCode::OK);
    let asset = json!({"identifier":"legacy","resource":resource,"version":"v1","variant":"default","versionDigest":reply.1["versions"][0]["digest"],"contentType":"application/x-apple-aspen-config","profileSchemas":["mdm/profiles/com.apple.security.firewall.yaml"]});
    let (takeover_policy, takeover) = f
        .configuration_policy(
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
            ),
            Some(task(vec![], vec![])),
            "remove",
        )
        .await?;
    let (execute, _) = peer.next("DeclarativeManagement").await?;
    peer.manage("Acknowledged", Some(execute), None).await?;
    let published = manifest(&peer, None).await?;
    let guarded: bool = sqlx::query_scalar("SELECT retired_at IS NULL FROM mdm_apple.profiles WHERE tenant_id=$1::uuid AND operation=$2")
        .bind(case_tenant()).bind(classic).fetch_one(&mut pg).await?;
    ensure!(
        guarded,
        "DDM publication ACK retired classic ownership before native takeover truth"
    );
    native(
        &peer,
        None,
        "status",
        Some(&report(&published, true, "15.0")),
    )
    .await?;
    ensure!(f.operation(takeover).await?["commandStatus"] == "applied");

    let retired:bool=sqlx::query_scalar("SELECT retired_at IS NOT NULL FROM mdm_apple.profiles WHERE tenant_id=$1::uuid AND operation=$2").bind(case_tenant()).bind(classic).fetch_one(&mut pg).await?;
    ensure!(retired, "native takeover retained classic ownership");
    f.policy_post(
        &format!("/api/v1/policies/{takeover_policy}"),
        1,
        json!({"action":"disable"}),
    )
    .await?;
    let (execute, _) = peer.next("DeclarativeManagement").await?;
    let withdrawal: Uuid = sqlx::query_scalar(
        "SELECT operation FROM mdm_apple.attempts WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(case_tenant())
    .bind(execute)
    .fetch_one(&mut pg)
    .await?;
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
    f.policy_claims_released(takeover_policy).await?;
    let replacement_profile = Uuid::new_v4();
    let (_, replacement) = f
        .configuration_policy(profile_task(replacement_profile, false), None, "retain")
        .await?;
    let (execute, _) = peer.next("InstallProfile").await?;
    let bytes = peer.manage("Acknowledged", Some(execute), None).await?;
    let (observe, _) = lifecycle::command(&bytes, "ProfileList")?;
    peer.manage(
        "Acknowledged",
        Some(observe),
        Some((
            "ProfileList",
            profile_manifest(replacement_profile, "com.apple.security.firewall"),
        )),
    )
    .await?;
    ensure!(f.operation(replacement).await?["commandStatus"] == "applied");
    ensure!(owner.shutdown().join().await?.is_clean());
    drop(device);
    f.close().await
}
