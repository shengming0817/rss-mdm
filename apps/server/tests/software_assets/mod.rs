//! Real HTTP handlers, owner roles, immutable arrays and durable query execution.
mod fixture;
use crate::{authority_t2_support::Context, planning_t2_support as planning};
use anyhow::{Context as _, Result};
use fixture::{Fixture, Http, definitions, facts, installation};
use rss_mdm_authorization_service::Permission as P;
use rss_mdm_inventory::Scalar;
use rss_mdm_inventory_service::assets::software as s;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;

fn response(value: &Value) -> &Value {
    &value["asset"]["response"]
}
async fn put(http: &Http, path: &str, revision: u64, input: Value) -> Result<Value> {
    let (status, value) = http
        .call(
            reqwest::Method::PUT,
            path,
            Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":revision,"input":input})),
        )
        .await?;
    anyhow::ensure!(status == 200, "PUT {path}: {status} {value}");
    Ok(value)
}
async fn query(c: &Context, fixture: &Fixture, http: &Http, input: Value) -> Result<Uuid> {
    let id = Uuid::new_v4();
    let (status, value) = http
        .call(
            reqwest::Method::POST,
            "/software-asset-queries",
            Some(json!({"operationId":id,"expectedRevision":0,"input":input})),
        )
        .await?;
    anyhow::ensure!(status == 202, "query: {status} {value}");
    assert_eq!(value["asset"]["task"], id.to_string());
    fixture.settle(c, id).await?;
    let value = http.get(&format!("/software-asset-queries/{id}")).await?;
    assert_eq!(response(&value)["status"], "completed", "{value}");
    Ok(id)
}
const ADMIN: &[P] = &[
    P::InventoryRead,
    P::InventorySensitiveRead,
    P::InventorySoftwareWrite,
    P::GroupRead,
    P::GroupWrite,
    P::GroupRecompute,
];

#[tokio::test]
#[ignore = "T2: complete Win32 coverage cannot prove a missing Store list empty for tenant software thresholds"]
async fn missing_mapping_source_is_unknown_until_its_complete_empty_list() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let fixture = Fixture::open(&c).await?;
    let account = c.account(ADMIN).await?;
    let http = Http::open(&c, &fixture, Arc::new(c.authenticate(&account).await?)).await?;
    let collection = fixture::definitions_for(
        &c,
        &[
            s::SoftwareSource::WindowsStore,
            s::SoftwareSource::WindowsWin32,
        ],
    )
    .await?;
    let a = planning::endpoint(&c).await?;
    let b = planning::endpoint(&c).await?;
    let mut store: std::collections::BTreeMap<String, Scalar> = [
        ("id", "editor"),
        ("origin", "windows.appx"),
        ("name", "Editor"),
        ("publisher", "Acme"),
        ("version", "1"),
        ("architecture", "x64"),
        ("registered_users_native", "2"),
        ("collection_scope", "device"),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), Scalar::String(v.into())))
    .collect();
    for key in ["is_bundle", "is_framework", "is_provisioned"] {
        store.insert(key.into(), Scalar::Boolean(false));
    }
    store.insert("package_status".into(), Scalar::Integer(0));
    fixture::facts_for(
        &c,
        &a,
        &collection,
        s::SoftwareSource::WindowsStore,
        vec![Scalar::Object(store)],
    )
    .await?;
    fixture::facts_for(&c, &b, &collection, s::SoftwareSource::WindowsWin32, vec![]).await?;
    let standard = Uuid::new_v4();
    let path = format!("/standard-software/{standard}");
    let definition = |threshold| json!({"action":"put","definition":{"name":"Editor","risk":"medium","assessments":{"endpoint":{"threshold":threshold}}}});
    put(&http, &path, 0, definition(2)).await?;
    put(&http,&format!("/software-mappings/{}",Uuid::new_v4()),0,json!({"action":"put","definition":{
        "standard":standard,"enabled":true,"source":"device.software.windows.store","platform":"windows","filter":"nativeId==editor"
    }})).await?;
    let task = query(&c, &fixture, &http, json!({"context":"endpoint"})).await?;
    let proof = c.authenticate(&account).await?;
    assert_eq!(
        fixture
            .assets
            .query_receipt(&proof, task)
            .await?
            .unwrap()
            .state
            .as_deref(),
        Some("completed")
    );
    assert_eq!(
        fixture
            .assets
            .operation_receipt(&proof, task)
            .await?
            .unwrap()
            .accepted,
        Some(true)
    );

    let rows = http
        .get(&format!("/software-asset-queries/{task}/software"))
        .await?;
    assert_eq!(response(&rows)["items"][0]["assessmentDevices"], 1);
    assert_eq!(response(&rows)["items"][0]["thresholdState"], "unknown");
    let coverage = http
        .get(&format!("/software-asset-queries/{task}/coverage"))
        .await?;
    let missing = response(&coverage)["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["object"]["id"] == b.members[0].device)
        .context("missing Store device")?;
    assert_eq!(missing["unknown"], true);
    put(&http, &path, 1, definition(1)).await?;
    let task = query(&c, &fixture, &http, json!({"context":"endpoint"})).await?;
    let rows = http
        .get(&format!("/software-asset-queries/{task}/software"))
        .await?;
    assert_eq!(response(&rows)["items"][0]["thresholdState"], "reached");
    put(&http, &path, 2, definition(2)).await?;
    // Only a complete Store list can clear that source's uncertainty. A still has no Win32 list.
    fixture::facts_for(&c, &b, &collection, s::SoftwareSource::WindowsStore, vec![]).await?;
    let task = query(&c, &fixture, &http, json!({"context":"endpoint"})).await?;
    let rows = http
        .get(&format!("/software-asset-queries/{task}/software"))
        .await?;
    assert_eq!(response(&rows)["items"][0]["assessmentDevices"], 1);
    assert_eq!(response(&rows)["items"][0]["thresholdState"], "below");
    http.close().await;
    drop(fixture);
    c.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "T2: configuration readers wait for the configuration transaction before binding revision and records"]
async fn configuration_capture_is_serialized_with_writes() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let fixture = Fixture::open(&c).await?;
    let account = c.account(ADMIN).await?;
    let http = Http::open(&c, &fixture, Arc::new(c.authenticate(&account).await?)).await?;
    let id = Uuid::new_v4();
    put(
        &http,
        &format!("/standard-software/{id}"),
        0,
        json!({"action":"put","definition":{"name":"Before","risk":"low"}}),
    )
    .await?;
    let mut tx = crate::command_runtime_t2_support::seed_transaction(&c).await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::text,3026))")
        .bind(c.tenant.to_string())
        .execute(&mut *tx)
        .await?;
    let rows = {
        let request = http.get("/standard-software");
        tokio::pin!(request);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(200), &mut request)
                .await
                .is_err()
        );
        sqlx::query("UPDATE mdm_assets.software_records SET revision=2,document=jsonb_set(document,'{name}','\"After\"') WHERE tenant_id=$1::uuid AND id=$2").bind(c.tenant.to_string()).bind(id).execute(&mut *tx).await?;
        sqlx::query("UPDATE mdm_assets.software_heads SET revision=2 WHERE tenant_id=$1::uuid")
            .bind(c.tenant.to_string())
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        request.await?
    };
    assert_eq!(response(&rows)["items"][0]["revision"], 2);
    assert_eq!(response(&rows)["items"][0]["definition"]["name"], "After");
    let task = query(&c, &fixture, &http, json!({"context":"endpoint"})).await?;
    assert_eq!(
        response(&http.get(&format!("/software-asset-queries/{task}")).await?)["coordinates"]["configurationRevision"],
        2
    );
    http.close().await;
    drop(fixture);
    c.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "T2: software result recovery and release use bounded durable worker steps, receipts and keep Inventory facts"]
async fn result_recovery_release_and_capacity() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let fixture = Fixture::open(&c).await?;
    let account = c.account(ADMIN).await?;
    let http = Http::open(&c, &fixture, Arc::new(c.authenticate(&account).await?)).await?;
    let definition = definitions(&c).await?;
    let endpoint = planning::endpoint(&c).await?;
    facts(
        &c,
        &endpoint,
        &definition,
        (0..1001)
            .map(|i| installation(&format!("editor-{i}"), &i.to_string()))
            .collect(),
    )
    .await?;
    let task = Uuid::new_v4();
    let input = json!({"operationId":task,"expectedRevision":0,"input":{"context":"endpoint"}});
    assert_eq!(
        http.call(
            reqwest::Method::POST,
            "/software-asset-queries",
            Some(input)
        )
        .await?
        .0,
        202
    );
    assert!(!fixture.work(&c, task, 1).await?);
    // A newly opened owner resumes the persisted array scan and unique memberships.
    drop(fixture);
    let fixture = Fixture::open(&c).await?;
    fixture.settle(&c, task).await?;
    let rows = http
        .get(&format!("/software-asset-queries/{task}/software"))
        .await?;
    assert_eq!(response(&rows)["items"][0]["devices"], 1);
    let release = json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{}});
    let path = format!("/software-asset-queries/{task}/release");
    let (status, first) = http
        .call(reqwest::Method::POST, &path, Some(release.clone()))
        .await?;
    assert_eq!(status, 200, "{first}");
    assert_eq!(
        http.call(reqwest::Method::POST, &path, Some(release.clone()))
            .await?
            .1,
        first
    );
    assert_eq!(
        response(
            &http
                .get(&format!(
                    "/software-asset-operations/{}",
                    release["operationId"].as_str().unwrap()
                ))
                .await?
        )["receipt"]["task"],
        task.to_string()
    );
    assert_eq!(
        http.call(
            reqwest::Method::GET,
            &format!("/software-asset-queries/{task}/software"),
            None
        )
        .await?
        .0,
        409
    );
    assert!(!fixture.work(&c, task, 1).await?);
    let mut tx = crate::command_runtime_t2_support::seed_transaction(&c).await?;
    let remaining: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM mdm_assets.software_evidence WHERE tenant_id=$1::uuid AND run=$2",
    )
    .bind(c.tenant.to_string())
    .bind(task)
    .fetch_one(&mut *tx)
    .await?;
    assert_eq!(remaining, 1);
    tx.commit().await?;
    drop(fixture);
    let fixture = Fixture::open(&c).await?;
    fixture.settle(&c, task).await?;
    assert_eq!(
        response(&http.get(&format!("/software-asset-queries/{task}")).await?)["resultState"],
        "released"
    );
    let mut tx = crate::command_runtime_t2_support::seed_transaction(&c).await?;
    let facts: i64 =
        sqlx::query_scalar("SELECT count(*) FROM mdm.array_items WHERE tenant_id=$1::uuid")
            .bind(c.tenant.to_string())
            .fetch_one(&mut *tx)
            .await?;
    assert_eq!(facts, 1001);
    let evidence: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM mdm_assets.software_evidence WHERE tenant_id=$1::uuid AND run=$2",
    )
    .bind(c.tenant.to_string())
    .bind(task)
    .fetch_one(&mut *tx)
    .await?;
    assert_eq!(evidence, 0);
    tx.commit().await?;
    // A superseded task must drain automatically, without a client release request.
    let superseded = Uuid::new_v4();
    assert_eq!(http.call(reqwest::Method::POST,"/software-asset-queries",Some(json!({"operationId":superseded,"expectedRevision":0,"input":{"context":"endpoint"}}))).await?.0,202);
    put(
        &http,
        &format!("/standard-software/{}", Uuid::new_v4()),
        0,
        json!({"action":"put","definition":{"name":"New configuration","risk":"low"}}),
    )
    .await?;
    fixture.settle(&c, superseded).await?;
    let failed = http
        .get(&format!("/software-asset-queries/{superseded}"))
        .await?;
    assert_eq!(response(&failed)["status"], "failed");
    assert_eq!(response(&failed)["failure"], "superseded");
    assert_eq!(response(&failed)["resultState"], "released");
    let mut tasks = Vec::new();
    for _ in 0..32 {
        let task = Uuid::new_v4();
        tasks.push(task);
        assert_eq!(
            http.call(
                reqwest::Method::POST,
                "/software-asset-queries",
                Some(
                    json!({"operationId":task,"expectedRevision":0,"input":{"context":"endpoint"}})
                )
            )
            .await?
            .0,
            202
        );
    }
    assert_eq!(http.call(reqwest::Method::POST,"/software-asset-queries",Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"context":"endpoint"}}))).await?.0,503);
    let cancel = tasks[0];
    assert_eq!(
        http.call(
            reqwest::Method::POST,
            &format!("/software-asset-queries/{cancel}/release"),
            Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{}}))
        )
        .await?
        .0,
        200
    );
    fixture.settle(&c, cancel).await?;
    let status = http
        .get(&format!("/software-asset-queries/{cancel}"))
        .await?;
    assert_eq!(response(&status)["status"], "cancelled");
    assert_eq!(response(&status)["resultState"], "released");
    assert_eq!(http.call(reqwest::Method::POST,"/software-asset-queries",Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"context":"endpoint"}}))).await?.0,202);
    http.close().await;
    drop(fixture);
    c.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "T2: software configuration CAS, actor receipts, authorization and tenant isolation use real HTTP and owner transactions"]
async fn configuration_http_and_receipts() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let fixture = Fixture::open(&c).await?;
    let admin = c.account(ADMIN).await?;
    let proof = Arc::new(c.authenticate(&admin).await?);
    let http = Http::open(&c, &fixture, proof.clone()).await?;
    let id = Uuid::new_v4();
    let operation = Uuid::new_v4();
    let path = format!("/standard-software/{id}");
    let change = json!({"operationId":operation,"expectedRevision":0,"input":{"action":"put","definition":{"name":"Editor","risk":"medium"}}});
    let (status, first) = http
        .call(reqwest::Method::PUT, &path, Some(change.clone()))
        .await?;
    assert_eq!(status, 200, "{first}");
    let (status, replay) = http
        .call(reqwest::Method::PUT, &path, Some(change.clone()))
        .await?;
    assert_eq!(status, 200);
    assert_eq!(first, replay);
    let receipt = http
        .get(&format!("/software-asset-operations/{operation}"))
        .await?;
    assert_eq!(response(&receipt)["receipt"]["revision"], 1);
    let mut wrong = change.clone();
    wrong["input"]["definition"]["name"] = json!("Other");
    assert_eq!(
        http.call(reqwest::Method::PUT, &path, Some(wrong)).await?.0,
        409
    );
    put(
        &http,
        &path,
        1,
        json!({"action":"put","definition":{"name":"Renamed","risk":"high"}}),
    )
    .await?;
    assert_eq!(
        response(&http.get(&path).await?)["record"]["id"],
        id.to_string()
    );
    assert_eq!(
        response(&http.get(&path).await?)["record"]["definition"]["name"],
        "Renamed"
    );
    let stale = Uuid::new_v4();
    let (status, _) = http
        .call(
            reqwest::Method::PUT,
            &path,
            Some(json!({
                "operationId":stale,"expectedRevision":1,
                "input":{"action":"put","definition":{"name":"Stale overwrite","risk":"low"}}
            })),
        )
        .await?;
    assert_eq!(status, 409);
    assert_eq!(response(&http.get(&path).await?)["record"]["revision"], 2);
    assert_eq!(
        response(&http.get(&path).await?)["record"]["definition"]["name"],
        "Renamed"
    );
    assert!(
        response(
            &http
                .get(&format!("/software-asset-operations/{stale}"))
                .await?
        )["receipt"]
            .is_null()
    );
    let second = Uuid::new_v4();
    put(
        &http,
        &format!("/standard-software/{second}"),
        0,
        json!({"action":"put","definition":{"name":"Second","risk":"low"}}),
    )
    .await?;
    let page = http.get("/standard-software?limit=1").await?;
    assert_eq!(response(&page)["items"].as_array().unwrap().len(), 1);
    let token = response(&page)["nextCursor"]
        .as_str()
        .context("directory continuation")?;
    put(
        &http,
        &path,
        2,
        json!({"action":"put","definition":{"name":"Renamed","risk":"low"}}),
    )
    .await?;
    assert_eq!(
        http.call(
            reqwest::Method::GET,
            &format!("/standard-software?limit=1&cursor={token}"),
            None
        )
        .await?
        .0,
        409
    );
    for risk in [json!(null), json!("critical")] {
        assert_eq!(http.call(reqwest::Method::PUT,&format!("/standard-software/{}",Uuid::new_v4()),Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","definition":{"name":"bad","risk":risk}}}))).await?.0,400);
    }
    let reader = c
        .account(&[P::InventoryRead, P::InventorySensitiveRead, P::GroupRead])
        .await?;
    let readonly = Http::open(&c, &fixture, Arc::new(c.authenticate(&reader).await?)).await?;
    assert_eq!(
        readonly
            .call(reqwest::Method::PUT, &path, Some(change))
            .await?
            .0,
        403
    );
    assert!(
        response(
            &readonly
                .get(&format!("/software-asset-operations/{operation}"))
                .await?
        )["receipt"]
            .is_null()
    );
    let foreign = Context::open("shared", &[]).await?;
    let foreign_fixture = Fixture::open(&foreign).await?;
    let account = foreign.account(ADMIN).await?;
    let foreign_http = Http::open(
        &foreign,
        &foreign_fixture,
        Arc::new(foreign.authenticate(&account).await?),
    )
    .await?;
    assert_eq!(
        foreign_http
            .call(reqwest::Method::GET, &path, None)
            .await?
            .0,
        404
    );
    assert!(
        response(&foreign_http.get("/standard-software").await?)["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    foreign_http.close().await;
    drop(foreign_fixture);
    foreign.close().await;
    readonly.close().await;
    http.close().await;
    drop(fixture);
    c.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "T2: software aggregation validates actual arrays, deduplicates devices, freezes pages and separates filtered counts from tenant thresholds"]
async fn aggregate_complete_results_and_revalidate_inputs() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let fixture = Fixture::open(&c).await?;
    let account = c.account(ADMIN).await?;
    let proof = Arc::new(c.authenticate(&account).await?);
    let http = Http::open(&c, &fixture, proof.clone()).await?;
    let definition = definitions(&c).await?;
    let a = planning::endpoint(&c).await?;
    let b = planning::endpoint(&c).await?;
    facts(
        &c,
        &a,
        &definition,
        vec![
            installation("editor-v1", "1"),
            installation("editor-v2", "2"),
            installation("editor-plugin", "2"),
        ],
    )
    .await?;
    facts(
        &c,
        &b,
        &definition,
        vec![installation("editor-component", "3")],
    )
    .await?;
    let standard = Uuid::new_v4();
    let map = Uuid::new_v4();
    let definition = json!({"name":"Editor","risk":"medium","assessments":{"endpoint":{"threshold":2,"allowedGroups":null}}});
    put(
        &http,
        &format!("/standard-software/{standard}"),
        0,
        json!({"action":"put","definition":definition}),
    )
    .await?;
    put(&http,&format!("/software-mappings/{map}"),0,json!({"action":"put","definition":{"standard":standard,"enabled":true,"source":"device.software.installations","platform":"windows","origin":"win32.uninstall.64","filter":"name==Editor;publisher==Acme"}})).await?;
    let task = query(
        &c,
        &fixture,
        &http,
        json!({"context":"endpoint","dimensions":["version","component"]}),
    )
    .await?;
    let buckets = http
        .get(&format!("/software-asset-queries/{task}/software"))
        .await?;
    let bucket = &response(&buckets)["items"][0];
    assert_eq!(bucket["devices"], 2, "{buckets}");
    assert_eq!(bucket["assessmentDevices"], 2);
    assert_eq!(bucket["thresholdState"], "reached");
    let key = bucket["id"].as_str().unwrap();
    let base = format!("/software-asset-queries/{task}/software/{key}");
    let versions = http.get(&format!("{base}/breakdowns/version")).await?;
    assert_eq!(response(&versions)["items"].as_array().unwrap().len(), 3);
    assert!(
        response(&versions)["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|v| v["devices"] == 1)
    );
    let page = http.get(&format!("{base}/devices?limit=1")).await?;
    let cursor = response(&page)["nextCursor"]
        .as_str()
        .context("device continuation")?;
    let next = http
        .get(&format!("{base}/devices?limit=1&cursor={cursor}"))
        .await?;
    assert_ne!(
        response(&page)["items"][0]["object"],
        response(&next)["items"][0]["object"]
    );
    let object = format!("endpoint:{}", a.members[0].device);
    let evidence = http
        .get(&format!("{base}/devices/{object}/evidence"))
        .await?;
    assert_eq!(response(&evidence)["items"].as_array().unwrap().len(), 3);
    assert!(
        response(&evidence)["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|v| v["confirmed"] == true)
    );
    let filtered = query(
        &c,
        &fixture,
        &http,
        json!({"context":"endpoint","software":{"filter":"version==1"}}),
    )
    .await?;
    let filtered = http
        .get(&format!("/software-asset-queries/{filtered}/software"))
        .await?;
    assert_eq!(response(&filtered)["items"][0]["devices"], 1);
    assert_eq!(response(&filtered)["items"][0]["assessmentDevices"], 2);
    assert_eq!(response(&filtered)["items"][0]["thresholdState"], "reached");
    // Indeterminate current evidence exposes its retained observation without counting it as an installation.
    let mut tx = crate::command_runtime_t2_support::seed_transaction(&c).await?;
    sqlx::query("UPDATE mdm.inventory SET state='unknown_incomplete',last_known_version=value_version,last_known_batch=batch_id,last_known_observed=observed_at,last_known_received=received_at,value_version=NULL,value=NULL WHERE tenant_id=$1::uuid AND registration=$2 AND field='device.software.installations'")
        .bind(c.tenant.to_string()).bind(a.members[0].device.to_string()).execute(&mut *tx).await?;
    tx.commit().await?;
    let uncertain = query(&c, &fixture, &http, json!({"context":"endpoint"})).await?;
    let uncertain_rows = http
        .get(&format!("/software-asset-queries/{uncertain}/software"))
        .await?;
    assert_eq!(response(&uncertain_rows)["items"][0]["devices"], 1);
    assert_eq!(
        response(&uncertain_rows)["items"][0]["thresholdState"],
        "unknown"
    );
    let coverage = http
        .get(&format!("/software-asset-queries/{uncertain}/coverage"))
        .await?;
    let covered = response(&coverage)["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["object"]["id"] == a.members[0].device)
        .unwrap();
    assert_eq!(covered["unknown"], true);
    assert!(
        covered["quality"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["lastKnown"].as_array().is_some_and(|a| !a.is_empty()))
    );
    let def = definitions_for_read(&c).await?;
    facts(
        &c,
        &a,
        &def,
        vec![
            installation("editor-v1", "1"),
            installation("editor-v2", "2"),
            installation("editor-plugin", "2"),
        ],
    )
    .await?;
    let other_map = Uuid::new_v4();
    let other_standard = Uuid::new_v4();
    put(
        &http,
        &format!("/standard-software/{other_standard}"),
        0,
        json!({"action":"put","definition":{"name":"Different","risk":"high"}}),
    )
    .await?;
    put(&http,&format!("/software-mappings/{other_map}"),0,json!({"action":"put","definition":{"standard":other_standard,"enabled":true,"source":"device.software.installations","platform":"windows","origin":"win32.uninstall.64","filter":"nativeId==editor-v1"}})).await?;
    assert_eq!(
        http.call(
            reqwest::Method::GET,
            &format!("{base}/devices?cursor={cursor}&limit=1"),
            None
        )
        .await?
        .0,
        409
    );
    let conflicted = query(&c, &fixture, &http, json!({"context":"endpoint"})).await?;
    let conflicts = http
        .get(&format!("/software-asset-queries/{conflicted}/software"))
        .await?;
    assert!(
        response(&conflicts)["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["identity"]["kind"] == "conflict")
    );
    // A complete empty replacement clears installations without changing the old fixed result.
    let def = definitions_for_read(&c).await?;
    facts(&c, &a, &def, vec![]).await?;
    let empty = query(&c, &fixture, &http, json!({"context":"endpoint"})).await?;
    let empty = http
        .get(&format!("/software-asset-queries/{empty}/software"))
        .await?;
    assert_eq!(response(&empty)["items"][0]["devices"], 1, "{empty}");
    // A live permission change rejects all pages of the previous query.
    let mut tx = crate::command_runtime_t2_support::seed_transaction(&c).await?;
    sqlx::query("UPDATE mdm_access.authorization_rules SET revision=revision+1,document=NULL WHERE tenant_id=$1::uuid AND id=$2").bind(c.tenant.to_string()).bind(account.rule).execute(&mut *tx).await?;
    tx.commit().await?;
    assert_eq!(
        http.call(
            reqwest::Method::GET,
            &format!("/software-asset-queries/{task}"),
            None
        )
        .await?
        .0,
        403
    );
    http.close().await;
    drop(fixture);
    c.close().await;
    Ok(())
}
async fn definitions_for_read(_c: &Context) -> Result<rss_mdm_inventory::CollectionDefinition> {
    use rss_mdm_inventory::*;
    Ok(CollectionDefinition::new(
        "software-assets",
        1,
        Source::MdmWindows,
        builtin::fields()
            .into_iter()
            .filter(|f| {
                matches!(
                    f.key.as_str(),
                    "device.os.name" | "device.software.installations"
                )
            })
            .map(|definition| CollectionField {
                definition,
                scope: CollectionScope::Device,
            })
            .collect(),
    )?)
}

#[tokio::test]
#[ignore = "T2: allowed Group union uses frozen three-valued decisions and both object domains share immutable Inventory input"]
async fn group_assessment_and_associated_domain() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let fixture = Fixture::open(&c).await?;
    let account = c.account(ADMIN).await?;
    let proof = Arc::new(c.authenticate(&account).await?);
    let http = Http::open(&c, &fixture, proof.clone()).await?;
    let definition = definitions(&c).await?;
    let a = planning::endpoint(&c).await?;
    let b = fixture::agent_endpoint(&c).await?;
    facts(&c, &a, &definition, vec![installation("editor", "1")]).await?;
    facts(&c, &b, &definition, vec![installation("editor", "1")]).await?;
    let owners = super::owner_boundaries_t2::Owners::open(&c).await?;
    let group = owners.create(&c, &proof, None).await?;
    let standard = Uuid::new_v4();
    let mapping = Uuid::new_v4();
    let definition = json!({"name":"Editor","risk":"high","assessments":{"endpoint":{"threshold":3,"allowedGroups":[group]},"associatedDevice":{"threshold":2,"allowedGroups":null}}});
    put(
        &http,
        &format!("/standard-software/{standard}"),
        0,
        json!({"action":"put","definition":definition}),
    )
    .await?;
    put(&http,&format!("/software-mappings/{mapping}"),0,json!({"action":"put","definition":{"standard":standard,"enabled":true,"source":"device.software.installations","platform":"windows","origin":"win32.uninstall.64","filter":"nativeId==editor"}})).await?;
    let task = query(&c, &fixture, &http, json!({"context":"endpoint"})).await?;
    let rows = http
        .get(&format!("/software-asset-queries/{task}/software"))
        .await?;
    assert_eq!(
        response(&rows)["items"][0]["compliance"]["nonCompliant"],
        2,
        "{rows}"
    );
    assert_eq!(response(&rows)["items"][0]["thresholdState"], "below");
    let changed = owners
        .groups
        .execute(
            &rss_mdm_group_service::Command::Group {
                id: group,
                change: Box::new(rss_mdm_group_service::operation::Operation {
                    operation_id: Uuid::new_v4(),
                    expected_revision: 1,
                    input: rss_mdm_group_service::GroupChange::Members {
                        add: vec![a.object.clone()],
                        remove: vec![],
                    },
                }),
            },
            &c.request(&proof)?,
            &proof,
        )
        .await?;
    if let Some(task) = changed.get("task").and_then(Value::as_str) {
        owners.settle(&c, Uuid::parse_str(task)?).await?;
    }
    assert_eq!(
        http.call(
            reqwest::Method::GET,
            &format!("/software-asset-queries/{task}/software"),
            None
        )
        .await?
        .0,
        409
    );
    let task = query(&c, &fixture, &http, json!({"context":"endpoint"})).await?;
    let rows = http
        .get(&format!("/software-asset-queries/{task}/software"))
        .await?;
    assert_eq!(
        response(&rows)["items"][0]["compliance"]["compliant"],
        1,
        "{rows}"
    );
    assert_eq!(response(&rows)["items"][0]["compliance"]["nonCompliant"], 1);
    // Fixed, already projected Device-owned inputs are lawful independent consumer prerequisites.
    let budget =
        rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(6));
    let cut = rss_mdm_inventory_service::assets::cut::capture(&c.audit, c.tenant, &budget).await?;
    let snapshot = Uuid::new_v4();
    let mut tx = crate::command_runtime_t2_support::seed_transaction(&c).await?;
    sqlx::query("INSERT INTO mdm_devices.object_cuts(tenant_id,id,asset_cut,through) VALUES($1::uuid,$2,$3,1)").bind(c.tenant.to_string()).bind(snapshot).bind(cut.to_json()).execute(&mut *tx).await?;
    let association = Uuid::new_v4();
    let paired = rss_mdm_inventory_service::objects::DeviceObject {
        object: rss_mdm_inventory_service::objects::ObjectRef::Association(association),
        association_version: Some(1),
        verified: true,
        members: vec![a.members[0].clone(), b.members[0].clone()],
    };
    sqlx::query("INSERT INTO mdm_devices.associations(tenant_id,id,version,state,evidence,hardware,confirmed_by,confirmed_at) VALUES($1::uuid,$2,1,'confirmed','verified software fixture','{}','fixture',1)").bind(c.tenant.to_string()).bind(association).execute(&mut *tx).await?;
    for member in &paired.members {
        sqlx::query("INSERT INTO mdm_devices.members (tenant_id, association_id, device, channel) VALUES (CAST($1 AS uuid), $2, $3, $4)")
            .bind(c.tenant.to_string()).bind(association).bind(&member.device).bind(member.channel.as_str()).execute(&mut *tx).await?;
    }
    sqlx::query("INSERT INTO mdm_devices.object_versions(tenant_id,object,revision,input,devices) VALUES($1::uuid,$2,1,$3,$4)")
        .bind(c.tenant.to_string()).bind(paired.object.key()).bind(serde_json::to_value(&paired)?).bind(paired.members.iter().map(|m|m.device.clone()).collect::<Vec<_>>()).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_devices.checkpoints(tenant_id,from_cut,rebuilding,object_revision,current_cut) VALUES($1::uuid,$2,false,1,$3) ON CONFLICT(tenant_id) DO UPDATE SET from_cut=excluded.from_cut,rebuilding=false,object_revision=1,current_cut=excluded.current_cut").bind(c.tenant.to_string()).bind(cut.to_json()).bind(snapshot).execute(&mut *tx).await?;
    tx.commit().await?;
    let associated = query(&c, &fixture, &http, json!({})).await?;
    let rows = http
        .get(&format!("/software-asset-queries/{associated}/software"))
        .await?;
    assert_eq!(
        response(&rows)["coordinates"]["context"],
        "associated_device"
    );
    assert_eq!(response(&rows)["items"][0]["devices"], 1, "{rows}");
    assert_eq!(response(&rows)["items"][0]["compliance"]["disabled"], 1);
    assert_eq!(response(&rows)["items"][0]["assessmentDevices"], 1);
    assert_eq!(response(&rows)["items"][0]["thresholdState"], "below");
    let mut tx = crate::command_runtime_t2_support::seed_transaction(&c).await?;
    sqlx::query("UPDATE mdm_devices.checkpoints SET relation_revision=relation_revision+1 WHERE tenant_id=$1::uuid").bind(c.tenant.to_string()).execute(&mut *tx).await?;
    tx.commit().await?;
    assert_eq!(
        http.call(
            reqwest::Method::GET,
            &format!("/software-asset-queries/{associated}/software"),
            None
        )
        .await?
        .0,
        409
    );
    // Publish the definition task; leave its separate member-calculation task pending.
    let pending = owners.create(&c, &proof, Some(serde_json::from_value(json!({
        "selector":{"kind":"device"},"quantifier":"one","criteria":{
            "kind":"predicate","field":"device.os.name","op":"eq","value":{"kind":"string","value":"Windows"}
        }
    }))?)).await?;
    put(&http,&format!("/standard-software/{standard}"),1,json!({"action":"put","definition":{"name":"Editor","risk":"high","assessments":{"endpoint":{"threshold":3,"allowedGroups":[pending]}}}})).await?;
    let uncertain = query(&c, &fixture, &http, json!({"context":"endpoint"})).await?;
    let rows = http
        .get(&format!("/software-asset-queries/{uncertain}/software"))
        .await?;
    assert_eq!(
        response(&rows)["items"][0]["compliance"]["unknown"],
        2,
        "{rows}"
    );
    assert_eq!(response(&rows)["items"][0]["thresholdState"], "below");
    http.close().await;
    drop(owners);
    drop(fixture);
    c.close().await;
    Ok(())
}
