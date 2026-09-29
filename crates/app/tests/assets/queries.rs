use super::*;
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=assets.queries: real Router and persisted assets"]
async fn query_snapshots_saved_ownership_and_stable_pagination() -> Result<()> {
    let fixture = Fixture::open().await?;
    let router = &fixture.router;
    let subject = &fixture.subject;
    let mut browser = fixture.browser.clone();
    let floor = "/api/v2/devices/asset-a/manual-fields/custom.office_floor";
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
    let query = json!({"sort":{"field":"custom.office_floor"}});
    let result = ok(
        &mut browser,
        router,
        Method::POST,
        "/api/v2/device-queries",
        Some(query),
    )
    .await?;
    let items_path = format!(
        "/api/v2/device-queries/{}/items",
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
    let second = format!(
        "{items_path}?limit=1&cursor={}",
        first["asset"]["nextCursor"].as_str().unwrap()
    );
    ensure!(
        ok(&mut browser, router, Method::GET, &second, None).await?["asset"]["items"][0]["device"]
            == "asset-b"
    );
    let saved = Uuid::new_v4();
    let saved_path = format!("/api/v2/saved-queries/{saved}");
    let put = request(
        0,
        json!({"action":"put","definition":{"name":"Floor 3","query":{"criteria":predicate("custom.office_floor","integer",json!(3))}}}),
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
    let mut other = Browser::default();
    ensure!(other.login(router, "other").await? == StatusCode::OK);
    let other_subject = browser_subject(&other, router).await?;
    permissions(&other_subject, None, true).await?;
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
            "/api/v2/saved-queries",
            None
        )
        .await?["asset"]["items"]
            == json!([])
    );
    ensure!(other.call(router, Method::GET, &second, None).await?.0 == StatusCode::FORBIDDEN);
    permissions(subject, Some("asset-a"), false).await?;
    ensure!(browser.call(router, Method::GET, &second, None).await?.0 == StatusCode::FORBIDDEN);
    ensure!(
        browser
            .call(
                router,
                Method::GET,
                "/api/v2/devices/asset-b/inventory",
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
            "/api/v2/device-queries",
            Some(json!({}))
        )
        .await?["asset"]["summary"]["total"]
            == 1
    );
    permissions(subject, None, true).await?;
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
    ensure!(browser.call(router, Method::GET, &second, None).await?.0 == StatusCode::OK);
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
    permissions(subject, None, true).await?;
    pg(&format!(
        "INSERT INTO mdm_access.devices VALUES('{TENANT}','tie-c'),('{TENANT}','tie-a'),('{TENANT}','tie-b')",
        TENANT = case_tenant()
    ))?;
    for device in ["tie-c", "tie-a", "tie-b"] {
        ok(
            &mut browser,
            router,
            Method::PUT,
            &format!("/api/v2/devices/{device}/manual-fields/custom.office_floor"),
            Some(request(
                0,
                json!({"action":"set","value":{"kind":"integer","value":99}}),
            )),
        )
        .await?;
    }
    for descending in [false, true] {
        let query = json!({"criteria":predicate("custom.office_floor","integer",json!(99)),"sort":{"field":"custom.office_floor","descending":descending}});
        let result = ok(
            &mut browser,
            router,
            Method::POST,
            "/api/v2/device-queries",
            Some(query),
        )
        .await?;
        let base = format!(
            "/api/v2/device-queries/{}/items?limit=1",
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
    fixture.close().await
}
