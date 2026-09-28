use crate::assets::t2::*;
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=assets.http: real Router and persisted assets"]
async fn manual_types_replay_cas_and_rollback() -> Result<()> {
    let fixture = Fixture::open().await?;
    let router = &fixture.router;
    let mut browser = fixture.browser.clone();
    let catalog = ok(
        &mut browser,
        router,
        Method::GET,
        "/api/v2/asset-fields",
        None,
    )
    .await?;
    ensure!(
        catalog["asset"]["fields"].as_array().unwrap().len()
            == rss_mdm_inventory::FieldKey::ALL.len()
    );
    let cases = [
        ("custom.asset_tag", "string", json!("A-2463")),
        ("custom.office_floor", "integer", json!(3)),
        ("custom.is_loaner", "boolean", json!(false)),
        ("custom.purchase_date", "time", json!(1_700_000_000)),
    ];
    for (field, kind, value) in cases {
        let path = format!("/api/v2/devices/asset-a/manual-fields/{field}");
        let write = request(
            0,
            json!({"action":"set","value":{"kind":kind,"value":value}}),
        );
        let first = ok(
            &mut browser,
            router,
            Method::PUT,
            &path,
            Some(write.clone()),
        )
        .await?;
        ensure!(first["asset"]["revision"] == 1);
        ensure!(
            ok(
                &mut browser,
                router,
                Method::PUT,
                &path,
                Some(write.clone())
            )
            .await?
                == first
        );
        let mut changed = write.clone();
        changed["input"] = json!({"action":"delete"});
        ensure!(
            browser
                .call(router, Method::PUT, &path, Some(changed))
                .await?
                .0
                == StatusCode::CONFLICT
        );
        let detail = ok(
            &mut browser,
            router,
            Method::GET,
            "/api/v2/devices/asset-a/inventory",
            None,
        )
        .await?;
        ensure!(
            detail["asset"]["device"]["fields"][field]["state"]["value"]
                == json!({"kind":kind,"value":value})
        );
        let criteria = predicate(field, kind, value);
        let result = ok(
            &mut browser,
            router,
            Method::POST,
            "/api/v2/device-queries",
            Some(json!({"criteria":criteria})),
        )
        .await?;
        ensure!(
            result["asset"]["summary"]["matched"] == 1
                && result["asset"]["items"][0]["device"] == "asset-a"
        );
    }
    let floor = "/api/v2/devices/asset-a/manual-fields/custom.office_floor";
    for input in [
        json!({"action":"set","value":{"kind":"string","value":"3"}}),
        json!({"action":"set","value":{"kind":"integer","value":3},"validUntil":1}),
        json!({"action":"delete","ttl":1}),
    ] {
        ensure!(
            browser
                .call(router, Method::PUT, floor, Some(request(1, input)))
                .await?
                .0
                .is_client_error()
        );
    }
    ensure!(
        browser
            .call(
                router,
                Method::PUT,
                "/api/v2/devices/asset-a/manual-fields/device.model",
                Some(request(
                    0,
                    json!({"action":"set","value":{"kind":"string","value":"spoof"}})
                ))
            )
            .await?
            .0
            == StatusCode::BAD_REQUEST
    );
    ensure!(
        browser
            .call(
                router,
                Method::GET,
                "/api/v2/devices/asset-a/inventory?source=mdm.windows",
                None
            )
            .await?
            .0
            .is_client_error()
    );
    let mut a = browser.clone();
    let mut b = browser.clone();
    let (a, b) = tokio::join!(
        a.call(
            router,
            Method::PUT,
            floor,
            Some(request(
                1,
                json!({"action":"set","value":{"kind":"integer","value":4}})
            ))
        ),
        b.call(
            router,
            Method::PUT,
            floor,
            Some(request(
                1,
                json!({"action":"set","value":{"kind":"integer","value":5}})
            ))
        )
    );
    let (a, b) = (a?, b?);
    ensure!(
        (a.0 == StatusCode::OK) ^ (b.0 == StatusCode::OK),
        "CAS admitted both/neither: {a:?} {b:?}"
    );
    ok(
        &mut browser,
        router,
        Method::PUT,
        floor,
        Some(request(2, json!({"action":"null"}))),
    )
    .await?;
    let null = ok(
        &mut browser,
        router,
        Method::GET,
        "/api/v2/devices/asset-a/inventory",
        None,
    )
    .await?;
    ensure!(null["asset"]["device"]["fields"]["custom.office_floor"]["state"]["kind"] == "null");
    ok(
        &mut browser,
        router,
        Method::PUT,
        floor,
        Some(request(3, json!({"action":"delete"}))),
    )
    .await?;
    let removed = ok(
        &mut browser,
        router,
        Method::GET,
        "/api/v2/devices/asset-a/inventory",
        None,
    )
    .await?;
    ensure!(
        removed["asset"]["device"]["fields"]["custom.office_floor"]["state"]["kind"] == "deleted"
    );
    ensure!(
        removed["asset"]["device"]["fields"]["custom.office_floor"]["sources"][0]["lastKnown"]["value"]
            ["kind"]
            == "integer"
    );
    // A deferred business write failure rolls back the assignment, receipt and staged audit.
    pg(
        "CREATE FUNCTION public.reject_asset_write() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture'; END $$; CREATE CONSTRAINT TRIGGER reject_asset_write AFTER UPDATE ON mdm.manual_assignments DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.reject_asset_write();",
    )?;
    let rejected = browser
        .call(
            router,
            Method::PUT,
            floor,
            Some(request(
                4,
                json!({"action":"set","value":{"kind":"integer","value":7}}),
            )),
        )
        .await?;
    pg(
        "DROP TRIGGER reject_asset_write ON mdm.manual_assignments; DROP FUNCTION public.reject_asset_write();",
    )?;
    ensure!(rejected.0 == StatusCode::SERVICE_UNAVAILABLE);
    ensure!(pg(&format!("SELECT revision FROM mdm.manual_assignments WHERE tenant_id='{TENANT}' AND device='asset-a' AND field='custom.office_floor'"))?.trim()=="4");
    fixture.close().await
}
