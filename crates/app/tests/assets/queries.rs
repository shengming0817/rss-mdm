use super::*;
use anyhow::Context;
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=assets.queries: real Router and persisted assets"]
async fn query_snapshots_saved_ownership_and_stable_pagination() -> Result<()> {
    let fixture = AssetHttp::open().await?;
    pg(&format!(
        "INSERT INTO mdm_access.devices(tenant_id,id) VALUES('{tenant}','asset-a'),('{tenant}','asset-b')",
        tenant = case_tenant()
    ))?;
    let router = &fixture.router;
    let subject = &fixture.author_id;
    let mut browser = fixture.author.clone();
    let floor = "/api/v1/devices/asset-a/manual-fields/custom.office_floor";
    ok(
        &mut browser,
        router,
        Method::PUT,
        floor,
        Some(request(
            0,
            json!({"action":"set","value":{"kind":"integer","value":3}}),
        )),
    )
    .await?;
    let query = json!({"sort":[{"field":"custom.office_floor"}],"fields":["custom.office_floor"]});
    let result = ok(
        &mut browser,
        router,
        Method::POST,
        "/api/v1/device-queries",
        Some(query),
    )
    .await?;
    let items_path = format!(
        "/api/v1/device-queries/{}/items",
        result["asset"]["snapshot"].as_str().unwrap()
    );
    let first = ok(
        &mut browser,
        router,
        Method::GET,
        &format!("{items_path}?limit=1"),
        None,
    )
    .await?;
    ensure!(
        first["asset"]["summary"]["total"] == 2
            && first["asset"]["items"][0]["device"] == "asset-a"
    );
    let frozen = first["asset"]["items"].clone();
    ensure!(
        frozen[0]["fields"]["custom.office_floor"]["state"]["value"]
            == json!({"kind":"integer","value":3})
    );
    let second = format!(
        "{items_path}?limit=1&cursor={}",
        first["asset"]["nextCursor"].as_str().unwrap()
    );
    ensure!(
        ok(&mut browser, router, Method::GET, &second, None).await?["asset"]["items"][0]["device"]
            == "asset-b"
    );
    let saved = Uuid::new_v4();
    let saved_path = format!("/api/v1/saved-queries/{saved}");
    let put = request(
        0,
        json!({"action":"put","definition":{"name":"Floor 3","query":{"filter":"custom.office_floor==3"}}}),
    );
    let receipt = ok(
        &mut browser,
        router,
        Method::PUT,
        &saved_path,
        Some(put.clone()),
    )
    .await?;
    ensure!(
        ok(
            &mut browser,
            router,
            Method::PUT,
            &saved_path,
            Some(put.clone())
        )
        .await?
            == receipt
    );
    ensure!(
        ok(
            &mut browser,
            router,
            Method::POST,
            &format!("{saved_path}/execute"),
            Some(json!({}))
        )
        .await?["asset"]["summary"]["matched"]
            == 1
    );

    let second_saved = Uuid::new_v4();
    ok(&mut browser,router,Method::PUT,&format!("/api/v1/saved-queries/{second_saved}"),Some(request(0,json!({"action":"put","definition":{"name":"Floor 3","query":{"filter":"custom.office_floor==3"}}})))).await?;
    let mut ids = [saved, second_saved];
    ids.sort();
    let base = "/api/v1/saved-queries?filter=name==%22Floor%203%22&sort=name&fields=id&limit=1";
    let page = ok(&mut browser, router, Method::GET, base, None).await?;
    ensure!(page["asset"]["items"] == json!([{"id":ids[0]}]));
    let cursor = page["asset"]["nextCursor"].as_str().unwrap();
    let last = ok(
        &mut browser,
        router,
        Method::GET,
        &format!("{base}&cursor={cursor}"),
        None,
    )
    .await?;
    ensure!(
        last["asset"]["items"] == json!([{"id":ids[1]}]) && last["asset"]["nextCursor"].is_null()
    );
    let mut other = crate::test_support::authority::Authority::prepared_browser("admin")?;
    let other_subject = prepared_subject(&other)?;
    identity::seed_grants(case_tenant(), &other_subject, permissions(None, true)?).await?;
    ensure!(
        other
            .call(
                router,
                Method::GET,
                &format!("{base}&cursor={cursor}"),
                None
            )
            .await?
            .0
            == StatusCode::CONFLICT
    );

    ensure!(other.call(router, Method::GET, &saved_path, None).await?.0 == StatusCode::NOT_FOUND);
    ensure!(
        other
            .call(
                router,
                Method::POST,
                &format!("{saved_path}/execute"),
                Some(request(1, json!({})))
            )
            .await?
            .0
            == StatusCode::NOT_FOUND
    );
    ensure!(
        ok(
            &mut other,
            router,
            Method::GET,
            "/api/v1/saved-queries",
            None
        )
        .await?["asset"]["items"]
            == json!([])
    );
    ensure!(other.call(router, Method::GET, &second, None).await?.0 == StatusCode::FORBIDDEN);
    identity::change_grants(case_tenant(), subject, permissions(Some("asset-a"), false)?).await?;
    let effective = browser
        .call(router, Method::GET, "/api/v1/authorization", None)
        .await?;
    ensure!(effective.0 == StatusCode::OK);
    let reads = effective.1["grants"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|g| g["operation"] == "inventory_read")
        .collect::<Vec<_>>();
    ensure!(
        reads.len() == 1 && reads[0]["scope"] == json!({"kind":"device","id":"asset-a"}),
        "asset reader retained broad grants: {effective:?}"
    );
    ensure!(browser.call(router, Method::GET, &second, None).await?.0 == StatusCode::FORBIDDEN);
    ensure!(
        browser
            .call(
                router,
                Method::GET,
                "/api/v1/devices/asset-b/inventory",
                None
            )
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    ensure!(
        browser
            .call(
                router,
                Method::PUT,
                floor,
                Some(request(1, json!({"action":"delete"})))
            )
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    ensure!(
        ok(
            &mut browser,
            router,
            Method::POST,
            "/api/v1/device-queries",
            Some(json!({}))
        )
        .await?["asset"]["summary"]["total"]
            == 1
    );
    identity::change_grants(case_tenant(), subject, permissions(None, true)?).await?;
    ok(
        &mut browser,
        router,
        Method::PUT,
        floor,
        Some(request(
            1,
            json!({"action":"set","value":{"kind":"integer","value":4}}),
        )),
    )
    .await?;
    let old = ok(
        &mut browser,
        router,
        Method::GET,
        &format!("{items_path}?limit=1"),
        None,
    )
    .await?;
    ensure!(old["asset"]["items"] == frozen);
    let fresh = ok(
        &mut browser,
        router,
        Method::POST,
        "/api/v1/device-queries",
        Some(json!({"filter":"custom.office_floor==4","fields":["custom.office_floor"]})),
    )
    .await?;
    ensure!(fresh["asset"]["items"].as_array().unwrap().len() == 1);
    ensure!(fresh["asset"]["items"][0]["device"] == "asset-a");
    ensure!(
        fresh["asset"]["items"][0]["fields"]["custom.office_floor"]["state"]["value"]
            == json!({"kind":"integer","value":4})
    );

    let deletion = request(1, json!({"action":"delete"}));
    ok(
        &mut browser,
        router,
        Method::PUT,
        &saved_path,
        Some(deletion),
    )
    .await?;
    ensure!(ok(&mut browser, router, Method::PUT, &saved_path, Some(put)).await? == receipt);
    ensure!(
        browser
            .call(
                router,
                Method::POST,
                &format!("{saved_path}/execute"),
                Some(request(2, json!({})))
            )
            .await?
            .0
            == StatusCode::NOT_FOUND
    );
    identity::change_grants(case_tenant(), subject, permissions(None, true)?).await?;
    pg(&format!(
        "INSERT INTO mdm_access.devices VALUES('{TENANT}','tie-c'),('{TENANT}','tie-a'),('{TENANT}','tie-b')",
        TENANT = case_tenant()
    ))?;
    for device in ["tie-c", "tie-a", "tie-b"] {
        ok(
            &mut browser,
            router,
            Method::PUT,
            &format!("/api/v1/devices/{device}/manual-fields/custom.office_floor"),
            Some(request(
                0,
                json!({"action":"set","value":{"kind":"integer","value":99}}),
            )),
        )
        .await?;
    }
    for descending in [false, true] {
        let query = json!({"filter":"custom.office_floor==99","sort":[{"field":"custom.office_floor","descending":descending}]});
        let result = ok(
            &mut browser,
            router,
            Method::POST,
            "/api/v1/device-queries",
            Some(query),
        )
        .await?;
        let base = format!(
            "/api/v1/device-queries/{}/items?limit=1",
            result["asset"]["snapshot"].as_str().unwrap()
        );
        let mut path = base.clone();
        let mut seen = Vec::new();
        loop {
            let page = ok(&mut browser, router, Method::GET, &path, None).await?;
            for item in page["asset"]["items"].as_array().unwrap() {
                seen.push(item["device"].as_str().unwrap().to_owned());
            }
            let Some(cursor) = page["asset"]["nextCursor"].as_str() else {
                break;
            };
            path = format!("{base}&cursor={cursor}");
            ensure!(seen.len() <= 3);
        }
        ensure!(seen == ["tie-a", "tie-b", "tie-c"]);
    }
    fixture.resources.finish(async { Ok(()) }).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=assets.queries: maximum stored sort keys remain pageable"]
async fn maximum_sort_keys_page_through_the_same_immutable_result() -> Result<()> {
    use crate::authorization::{Grant, Permission, Scope};
    let fixture = AssetHttp::open().await?;
    pg(&format!(
        "INSERT INTO mdm_access.devices(tenant_id,id) VALUES('{tenant}','asset-a'),('{tenant}','asset-b')",
        tenant = case_tenant()
    ))?;
    let router = &fixture.router;
    let mut browser = fixture.author.clone();
    let mut grants = crate::test_support::identity::device_grants(
        None,
        &["inventory_read", "inventory_assign"],
    )?;
    grants.push(Grant {
        operation: Permission::InventoryFieldsWrite,
        scope: Scope::Tenant,
    });
    crate::test_support::identity::seed_grants(case_tenant(), &fixture.author_id, grants).await?;
    let field = "custom.cursor_sort";
    let definition = json!({"key":field,"version":1,"valueType":{"kind":"string","maxLength":1024,"allowEmpty":false},"nullable":true,"manual":true,"sources":{"manual":0},"platforms":["macos","windows"],"sensitivity":"standard","unit":null,"searchable":true,"itemKey":null});
    ok(
        &mut browser,
        router,
        Method::PUT,
        &format!("/api/v1/asset-fields/{field}"),
        Some(request(0, json!({"action":"put","definition":definition}))),
    )
    .await?;
    let mut devices = [Uuid::new_v4().to_string(), Uuid::new_v4().to_string()];
    devices.sort();
    for device in &devices {
        pg(&format!(
            "INSERT INTO mdm_access.devices VALUES('{}','{device}')",
            case_tenant()
        ))?;
        ok(
            &mut browser,
            router,
            Method::PUT,
            &format!("/api/v1/devices/{device}/manual-fields/custom.office_floor"),
            Some(request(
                0,
                json!({"action":"set","value":{"kind":"integer","value":1}}),
            )),
        )
        .await?;
    }
    // The old JSON byte array exceeds PageCursor already at 1000 bytes. Also
    // exercise the exact 1024-byte storage limit for single and composite sorts.
    for (revision, (length, composite)) in [(497, false), (509, false), (500, true)]
        .into_iter()
        .enumerate()
    {
        for (device, letter) in devices.iter().zip(["y", "z"]) {
            ok(
                &mut browser,
                router,
                Method::PUT,
                &format!("/api/v1/devices/{device}/manual-fields/{field}"),
                Some(request(
                    revision as u64,
                    json!({"action":"set","value":{"kind":"string","value":letter.repeat(length)}}),
                )),
            )
            .await?;
        }
        for descending in [false, true] {
            let mut sort = vec![json!({"field":field,"descending":descending})];
            if composite {
                sort.push(json!({"field":"custom.office_floor"}));
            }
            let created = ok(&mut browser, router, Method::POST, "/api/v1/device-queries", Some(json!({"filter":format!("{field}=isnotnull=true"),"sort":sort,"fields":[field]}))).await?;
            let task = created["asset"]["snapshot"]
                .as_str()
                .context("query task")?;
            let bytes = pg(&format!(
                "SELECT max(octet_length(sort_key)) FROM mdm_assets.asset_query_results WHERE tenant_id='{}' AND run='{task}'",
                case_tenant()
            ))?;
            ensure!(
                bytes.trim() == if length == 497 { "1000" } else { "1024" },
                "stored key bytes: {bytes}"
            );
            let base = format!("/api/v1/device-queries/{task}/items?limit=1");
            let first = ok(&mut browser, router, Method::GET, &base, None).await?;
            let cursor = first["asset"]["nextCursor"]
                .as_str()
                .context("bounded continuation")?;
            ensure!(cursor.len() <= 4096);
            let last = ok(
                &mut browser,
                router,
                Method::GET,
                &format!("{base}&cursor={cursor}"),
                None,
            )
            .await?;
            let index = usize::from(descending);
            ensure!(first["asset"]["items"][0]["device"] == devices[index]);
            ensure!(
                last["asset"]["items"][0]["device"] == devices[1 - index]
                    && last["asset"]["nextCursor"].is_null()
            );
            println!(
                "QUERY-05 stored_sort_bytes={} cursor_bytes={} composite={composite} descending={descending}",
                bytes.trim(),
                cursor.len()
            );
        }
    }
    fixture.resources.finish(async { Ok(()) }).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=assets.queries: saved definitions roundtrip at the parser boundary"]
async fn maximum_saved_filter_reads_executes_and_saves_again() -> Result<()> {
    let fixture = AssetHttp::open().await?;
    pg(&format!(
        "INSERT INTO mdm_access.devices(tenant_id,id) VALUES('{tenant}','asset-a'),('{tenant}','asset-b')",
        tenant = case_tenant()
    ))?;
    let router = &fixture.router;
    let mut browser = fixture.author.clone();
    let text = vec![format!("device.name=={}", "z".repeat(1010)); 8].join(";");
    ensure!(text.len() == 8191);
    for suffix in ["", "z"] {
        let filter = format!("{text}{suffix}");
        let path = format!("/api/v1/saved-queries/{}", Uuid::new_v4());
        let written = ok(
            &mut browser,
            router,
            Method::PUT,
            &path,
            Some(request(
                0,
                json!({"action":"put","definition":{"name":"boundary","query":{"filter":filter}}}),
            )),
        )
        .await?;
        let read = ok(&mut browser, router, Method::GET, &path, None).await?;
        ensure!(written["asset"]["query"] == read["asset"]["query"]);
        let definition = read["asset"]["query"]["definition"].clone();
        ensure!(definition["query"]["filter"] == filter);
        let direct = ok(
            &mut browser,
            router,
            Method::POST,
            "/api/v1/device-queries",
            Some(definition["query"].clone()),
        )
        .await?;
        let saved = ok(
            &mut browser,
            router,
            Method::POST,
            &format!("{path}/execute"),
            Some(json!({})),
        )
        .await?;
        ensure!(direct["asset"]["summary"] == saved["asset"]["summary"]);
        let again = ok(
            &mut browser,
            router,
            Method::PUT,
            &path,
            Some(request(1, json!({"action":"put","definition":definition}))),
        )
        .await?;
        ensure!(
            again["asset"]["query"]["definition"] == definition
                && again["asset"]["query"]["revision"] == 2
        );
    }
    let path = format!("/api/v1/saved-queries/{}", Uuid::new_v4());
    let filter = format!("{text}zz");
    let denied = browser
        .call(
            router,
            Method::PUT,
            &path,
            Some(request(
                0,
                json!({"action":"put","definition":{"name":"expansion","query":{"filter":filter}}}),
            )),
        )
        .await?;
    ensure!(
        denied.0 == StatusCode::BAD_REQUEST,
        "unreplayable saved definition: {denied:?}"
    );
    ensure!(browser.call(router, Method::GET, &path, None).await?.0 == StatusCode::NOT_FOUND);
    fixture.resources.finish(async { Ok(()) }).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=assets.queries: native record metadata, RSQL and frozen array reads"]
async fn native_record_properties_preserve_unknown_booleans_in_queries_and_pages() -> Result<()> {
    use crate::authorization::{Grant, Permission, Scope};
    use rss_mdm_inventory::{FieldKey, Source, builtin};
    let fixture = Fixture::open().await?;
    let mut browser = fixture.browser.clone();
    let router = &fixture.router;
    let mut grants = crate::test_support::identity::device_grants(
        None,
        &["inventory_read", "inventory_assign"],
    )?;
    grants.push(Grant {
        operation: Permission::InventoryFieldsWrite,
        scope: Scope::Tenant,
    });
    crate::test_support::identity::seed_grants(
        case_tenant(),
        &crate::test_support::http::prepared_subject(&fixture.browser)?,
        grants.clone(),
    )
    .await?;
    // Exercise query/storage through a normal writable field with the exact native Record type.
    // The Windows protocol-to-Inventory seam is owned by windows.management.
    let key = "custom.native_packages";
    let mut field = builtin::fields()
        .into_iter()
        .find(|f| f.key.as_str() == "device.software.windows.system")
        .unwrap();
    field.key = FieldKey::parse(key)?;
    field.manual = true;
    field.sources = [(Source::Manual, 0)].into();
    let definition = rss_mdm_inventory_service::collection::wire::to_wire_field(&field)?;
    ok(
        &mut browser,
        router,
        Method::PUT,
        &format!("/api/v1/asset-fields/{key}"),
        Some(request(0, json!({"action":"put","definition":definition}))),
    )
    .await?;
    let original = json!({
        "id":"package", "origin":"./Device/Vendor/MSFT/EnterpriseModernAppManagement/AppManagement/System",
        "name":"System package", "publisher":"CN=Vendor", "version":"1.0.0.0", "architecture":"arm64",
        "is_bundle":false, "is_framework":false, "is_provisioned_native":2, "package_status":0,
        "registered_users_native":"", "collection_scope":"device"
    });
    let mut first = original.clone();
    first["id"] = json!("package-a");
    let mut second = original.clone();
    second["id"] = json!("package-b");
    let unknown = field.value_type.decode_json(&json!([first, second]))?;
    let mut known = original.clone();
    known["id"] = json!("package-c");
    known["is_provisioned_native"] = json!(1);
    known["is_provisioned"] = json!(true);
    let known = field.value_type.decode_json(&json!([known]))?;
    for (device, value) in [("asset-a", unknown), ("asset-b", known)] {
        ok(
            &mut browser,
            router,
            Method::PUT,
            &format!("/api/v1/devices/{device}/manual-fields/{key}"),
            Some(request(0, json!({"action":"set","value":value}))),
        )
        .await?;
    }
    let query = json!({"filter":format!("{key}.is_provisioned_native=containsany=(2)"),"fields":[key],"sort":[]});
    ensure!(
        browser
            .call(
                router,
                Method::POST,
                "/api/v1/device-queries",
                Some(request(0, query.clone()))
            )
            .await?
            .0
            == StatusCode::FORBIDDEN,
        "field metadata does not grant sensitive value access"
    );
    grants.push(Grant {
        operation: Permission::InventorySensitiveRead,
        scope: Scope::Tenant,
    });
    crate::test_support::identity::change_grants(
        case_tenant(),
        &crate::test_support::http::prepared_subject(&fixture.browser)?,
        grants.clone(),
    )
    .await?;
    let selected = ok(
        &mut browser,
        router,
        Method::POST,
        "/api/v1/device-queries",
        Some(query.clone()),
    )
    .await?;
    ensure!(
        selected["asset"]["summary"]["matched"] == 1
            && selected["asset"]["items"][0]["device"] == "asset-a",
        "raw integer predicate: {selected}"
    );
    ensure!(
        selected["asset"]["items"][0]["lists"][key]["state"]["count"] == 2,
        "record projection: {selected}"
    );
    let false_query =
        json!({"filter":format!("{key}.is_provisioned=containsany=(false)"),"fields":[key]});
    let absent = ok(
        &mut browser,
        router,
        Method::POST,
        "/api/v1/device-queries",
        Some(false_query),
    )
    .await?;
    ensure!(
        absent["asset"]["summary"]["matched"] == 0,
        "unknown provisioning must not become false: {absent}"
    );
    let true_query =
        json!({"filter":format!("{key}.is_provisioned=containsany=(true)"),"fields":[key]});
    let present = ok(
        &mut browser,
        router,
        Method::POST,
        "/api/v1/device-queries",
        Some(true_query),
    )
    .await?;
    ensure!(
        present["asset"]["summary"]["matched"] == 1
            && present["asset"]["items"][0]["device"] == "asset-b"
    );
    let list = format!("/api/v1/devices/asset-a/inventory-lists/{key}");
    let first = ok(
        &mut browser,
        router,
        Method::GET,
        &format!("{list}?limit=1"),
        None,
    )
    .await?;
    let cursor = first["asset"]["nextCursor"].as_str().unwrap();
    ok(
        &mut browser,
        router,
        Method::PUT,
        &format!("/api/v1/devices/asset-a/manual-fields/{key}"),
        Some(request(
            1,
            json!({"action":"set","value":{"kind":"array","value":[]}}),
        )),
    )
    .await?;
    let second = ok(
        &mut browser,
        router,
        Method::GET,
        &format!("{list}?limit=1&cursor={cursor}"),
        None,
    )
    .await?;
    ensure!(
        second["asset"]["watermark"] == first["asset"]["watermark"]
            && second["asset"]["total"] == 2
            && second["asset"]["nextCursor"].is_null()
    );
    for page in [&first, &second] {
        let properties = page["asset"]["items"][0]["value"].as_object().unwrap();
        ensure!(
            properties["is_provisioned_native"] == json!({"kind":"integer","value":2})
                && !properties.contains_key("is_provisioned")
        );
    }
    ensure!(
        first["asset"]["items"][0]["value"]["id"] != second["asset"]["items"][0]["value"]["id"]
    );
    let current = ok(&mut browser, router, Method::GET, &list, None).await?;
    ensure!(current["asset"]["total"] == 0);
    let after = ok(
        &mut browser,
        router,
        Method::POST,
        "/api/v1/device-queries",
        Some(query.clone()),
    )
    .await?;
    ensure!(after["asset"]["summary"]["matched"] == 0);
    let denied_legacy = request(0, json!({"criteria":null,"select":[key]}));
    ensure!(
        browser
            .call(
                router,
                Method::POST,
                "/api/v1/device-queries",
                Some(denied_legacy)
            )
            .await?
            .0
            == StatusCode::BAD_REQUEST
    );
    grants.pop();
    crate::test_support::identity::change_grants(
        case_tenant(),
        &crate::test_support::http::prepared_subject(&fixture.browser)?,
        grants,
    )
    .await?;
    ensure!(browser.call(router, Method::GET, &list, None).await?.0 == StatusCode::FORBIDDEN);
    ensure!(
        browser
            .call(
                router,
                Method::GET,
                &format!("{list}?limit=1&cursor={cursor}"),
                None
            )
            .await?
            .0
            == StatusCode::CONFLICT
    );
    fixture.close().await
}
