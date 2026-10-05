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
