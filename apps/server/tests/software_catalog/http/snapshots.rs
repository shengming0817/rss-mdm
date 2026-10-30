//! One current-source lifecycle regression; consumer edits go through the real Resource owner.
use crate::test_support::software::{Fixture, seed_software_version, write};
use crate::test_support::{process::*, runtime::*, *};

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "MODULE=software.http: source JSON replacement, receipts and independent consumer data"]
async fn current_json_snapshot_and_consumer_data_are_independent() -> Result<()> {
    let mut f = Fixture::open(false).await?;
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async {
        let source = Uuid::new_v4().to_string();
        let path = format!("/api/v1/software/source-snapshots/{source}");
        let first = json!({
            "packages":[
                {"id":"same","version":"1","vendor":{"unrecognized":[true,42]}},
                {"id":"same","version":"2","name":"Second"},
                {"description":"not used; never needs manual completion"},
                null
            ],
            "unselected":{"retained":true}
        });
        let operation = Uuid::new_v4();
        let request = json!({"operationId":operation,"expectedRevision":0,"input":{
            "document":first,"extraction":{"records":"/packages","packageId":"/id","name":"/name","version":"/version"}
        }});
        let imported = f.user.call(&f.router, Method::POST, &path, Some(request.clone())).await?;
        ensure!(imported.0 == StatusCode::OK, "snapshot import: {imported:?}");
        ensure!(imported.1["revision"] == 1 && imported.1["entryCount"] == 4);
        let saved = f.user.call(&f.router, Method::GET, &path, None).await?;
        ensure!(saved.0 == StatusCode::OK && saved.1["document"] == first);
        let listed = f.user.call(&f.router, Method::GET,
            &format!("/api/v1/software/source-snapshots?filter=source=={source}"), None).await?;
        ensure!(listed.0 == StatusCode::OK && listed.1["items"].as_array().unwrap().len() == 1);
        let entries = f.user.call(&f.router, Method::GET, &format!("{path}/entries"), None).await?;
        ensure!(entries.0 == StatusCode::OK, "entries: {entries:?}");
        let rows = entries.1["items"].as_array().unwrap();
        ensure!(rows.len() == 4 && rows.iter().filter(|v| v["packageId"] == "same").count() == 2);
        ensure!(rows.iter().filter(|v| v["packageId"].is_null()).count() == 2);
        let chosen = rows.iter().find(|v| v["version"] == "1").unwrap();
        ensure!(chosen["name"].is_null());
        let entry_path = format!("{path}/entries/{}", chosen["entryId"].as_str().unwrap());
        let selected = f.user.call(&f.router, Method::GET, &entry_path, None).await?;
        ensure!(selected.0 == StatusCode::OK && selected.1["data"] == first["packages"][0]);
        let page_url = format!("{path}/entries?limit=1");
        let page = f.user.call(&f.router, Method::GET, &page_url, None).await?;
        ensure!(page.0 == StatusCode::OK);
        let cursor = page.1["nextCursor"].as_str().expect("four records require another page");
        let continuation = format!("{page_url}&cursor={cursor}");
        let next = f.user.call(&f.router, Method::GET, &continuation, None).await?;
        ensure!(next.0 == StatusCode::OK && next.1["items"][0]["entryId"] != page.1["items"][0]["entryId"]);
        // A real software Resource owns the copied descriptive data and its subsequent edits.
        let definition = publication_support::private_definition(f.registered["snapshot"].clone(), b"abc");
        let (resource, digest) = seed_software_version(&f.software_runtime, definition).await?;
        let resource_path = format!("/api/v1/resources/{resource}");
        let before = f.user.call(&f.router, Method::GET, &resource_path, None).await?;
        ensure!(before.0 == StatusCode::OK);
        let mut copied = selected.1["data"].clone();
        copied["name"] = json!("Enterprise name");
        let mut revision = before.1["revision"].as_u64().unwrap();
        write(&mut f.user, &f.router, &resource_path, revision,
            json!({"action":"present","presentation":{"sourceData":copied}})).await?;
        revision += 1;
        copied["name"] = json!("Edited independently");
        write(&mut f.user, &f.router, &resource_path, revision,
            json!({"action":"present","presentation":{"sourceData":copied}})).await?;
        let unchanged = f.user.call(&f.router, Method::GET, &entry_path, None).await?;
        ensure!(unchanged == selected, "consumer mutation changed the source document");
        // Failed replacement and fingerprint conflicts must preserve the current snapshot.
        let bad = json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"input":{
            "document":{"different":true},"extraction":{"name":"/bad~2escape"}
        }});
        ensure!(f.user.call(&f.router, Method::POST, &path, Some(bad)).await?.0 == StatusCode::BAD_REQUEST);
        ensure!(f.user.call(&f.router, Method::GET, &path, None).await? == saved);
        let mut conflict = request.clone();
        conflict["input"]["document"] = json!({"changed":true});
        ensure!(f.user.call(&f.router, Method::POST, &path, Some(conflict)).await?.0 == StatusCode::CONFLICT);
        let replaced = write(&mut f.user, &f.router, &path, 1,
            json!({"document":{"new":"current document with no required software fields"}})).await?;
        ensure!(replaced["revision"] == 2 && replaced["entryCount"] == 1);
        ensure!(f.user.call(&f.router, Method::GET, &continuation, None).await?.0 == StatusCode::CONFLICT);
        ensure!(f.user.call(&f.router, Method::GET, &entry_path, None).await?.0 == StatusCode::NOT_FOUND);
        let replay = f.user.call(&f.router, Method::POST, &path, Some(request)).await?;
        ensure!(replay == imported, "replay did not preserve the original receipt");
        let receipt = f.user.call(&f.router, Method::GET, &format!("{path}/operations/{operation}"), None).await?;
        ensure!(receipt == imported);
        let current = f.user.call(&f.router, Method::GET, &path, None).await?;
        ensure!(current.1["revision"] == 2 && current.1["document"]["new"].is_string());
        let consumer = f.user.call(&f.router, Method::GET, &resource_path, None).await?;
        ensure!(consumer.0 == StatusCode::OK && consumer.1["presentation"]["sourceData"] == copied);
        ensure!(consumer.1["versions"][0]["digest"] == digest, "snapshot replacement changed executable software");
        let counts = pg(&format!(
            "SELECT jsonb_build_array((SELECT count(*) FROM mdm_software_snapshots.current WHERE tenant_id='{}' AND source='{source}'),(SELECT count(*) FROM mdm_software_snapshots.entries WHERE tenant_id='{}' AND source='{source}'),(SELECT count(*) FROM mdm_software_snapshots.operations WHERE tenant_id='{}' AND source='{source}' AND response ? 'document'))",
            case_tenant(), case_tenant(), case_tenant()
        ))?;
        ensure!(serde_json::from_str::<Value>(counts.trim())? == json!([1,1,0]));
        // Raw HTTP is necessary here: the test client must not round the number before upload.
        let raw = r#"{"名字":"完整","number":18446744073709551617,"decimal":0.123456789012345678901,"unused":"\u0000"}"#;
        let raw_request = format!(r#"{{"operationId":"{}","expectedRevision":2,"input":{{"document":[{}]}}}}"#, Uuid::new_v4(), raw);
        let cookie = f.user.cookies.iter().map(|(k,v)|format!("{k}={v}")).collect::<Vec<_>>().join("; ");
        let posted = f.client.post(format!("{}{path}", f.origin))
            .header("host","mdm.example.test").header("origin","https://mdm.example.test")
            .header("x-identity-request","1").header("x-csrf-token",f.user.csrf.as_ref().unwrap())
            .header("cookie",&cookie).header("content-type","application/json")
            .body(raw_request).send().await?;
        ensure!(posted.status() == StatusCode::OK, "raw source JSON was rejected");
        let rows = f.user.call(&f.router, Method::GET, &format!("{path}/entries"), None).await?;
        let raw_path = format!("{path}/entries/{}",rows.1["items"][0]["entryId"].as_str().unwrap());
        let response = f.client.get(format!("{}{raw_path}",f.origin))
            .header("host","mdm.example.test").header("cookie",&cookie).send().await?;
        ensure!(response.status() == StatusCode::OK);
        let response = response.text().await?;
        let fields: BTreeMap<String, &serde_json::value::RawValue> = serde_json::from_str(&response)?;
        ensure!(fields["data"].get() == raw, "raw JSON changed through HTTP/PG");
        Ok(())
    }).await
}
