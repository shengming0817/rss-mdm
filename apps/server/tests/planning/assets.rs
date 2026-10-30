use crate::planning::test_support::*;

#[tokio::test]
#[ignore = "MODULE=planning.assets: real capability storage and transactions"]
async fn asset_history_rollback_replay_and_frozen_cut() {
    let t = tenant();
    let service = planning(t).await;
    let device = format!("history-{}", Uuid::new_v4());
    let read = || {
        sql(&format!(
            "SELECT count(*) FROM mdm.asset_changes WHERE tenant_id='{t}'"
        ))
        .parse::<i64>()
        .unwrap()
    };
    let before = read();
    sql(&format!(
        "BEGIN; SET LOCAL rss.tenant_id='{t}'; INSERT INTO mdm_access.devices VALUES('{t}','{device}'); ROLLBACK;"
    ));
    assert_eq!(read(), before, "rollback cannot leave a durable trigger");
    sql(&format!(
        "BEGIN; SET LOCAL rss.tenant_id='{t}'; INSERT INTO mdm_access.devices VALUES('{t}','{device}'); COMMIT;"
    ));
    let created = read();
    let created_cut = asset_cut();
    assert!(created > before);
    sql(&format!(
        "BEGIN; SET LOCAL rss.tenant_id='{t}'; INSERT INTO mdm_access.devices VALUES('{t}','{device}') ON CONFLICT DO NOTHING; COMMIT;"
    ));
    assert_eq!(
        read(),
        created,
        "idempotent writes cannot manufacture a new input version"
    );
    sql(&format!(
        "BEGIN; SET LOCAL rss.tenant_id='{t}'; DELETE FROM mdm_access.devices WHERE tenant_id='{t}' AND id='{device}'; COMMIT;"
    ));
    assert!(read() > created);
    assert_eq!(
        sql(&format!(
            "SELECT document->>'id' FROM mdm_access.asset_authority_history WHERE tenant_id='{t}' AND kind='device' AND identity='{device}' AND mdm.asset_visible('{cut}'::jsonb,revision) ORDER BY revision DESC LIMIT 1",
            cut = created_cut.to_json()
        )),
        device
    );
    assert_eq!(
        sql(&format!(
            "SELECT document IS NULL FROM mdm_access.asset_authority_history WHERE tenant_id='{t}' AND kind='device' AND identity='{device}' ORDER BY revision DESC LIMIT 1"
        )),
        "t"
    );
    let scope_device = device.clone();
    let frozen = service
        .policy
        .runtime
        .local_tx_with_context(t, deadline(), &service, move |s, tx| {
            Box::pin(async move {
                rss_mdm_inventory_service::assets::planning::SnapshotReader { tenant: s.tenant }
                    .asset_page_in(
                        tx,
                        &created_cut,
                        None,
                        1,
                        &assets::ReadScope {
                            authority: "internal".into(),
                            collection_scope: rss_mdm_inventory::CollectionScope::Device,

                            subject: "history".into(),
                            devices: Some([scope_device.clone()].into()),
                        },
                    )
                    .await
                    .map_err(|_| sqlx::Error::Protocol("frozen page rejected".into()).into())
            })
        })
        .await
        .fold(
            |p| p,
            |e| panic!("{e:?}"),
            |e| panic!("{e:?}"),
            |e| panic!("{e:?}"),
            |e| panic!("{e:?}"),
            |e| panic!("{e:?}"),
        );
    assert_eq!(frozen.devices.len(), 1);
    assert_eq!(frozen.devices[0].scalars.device, device);
    assert!(frozen.next.is_none());
    service.close().await;
}

#[tokio::test]
#[ignore = "MODULE=planning.assets: real capability storage and transactions"]
async fn frozen_fields_manual_and_quality_survive_updates_deletes_and_rollback() {
    let t = tenant();
    let device = "all-histories";
    let registration = seed_device(device);
    let epoch = sql(&format!(
        "SELECT epoch FROM mdm_access.report_sources WHERE registration='{registration}'"
    ));
    let scope = crate::device::scope(
        t,
        Uuid::parse_str(&registration).unwrap(),
        "mdm.windows",
        Uuid::parse_str(&epoch).unwrap(),
    )
    .unwrap()
    .encode()
    .unwrap();
    let coverage = serde_json::to_string(
        &crate::test_support::inventory::definition(
            "inventory",
            "mdm.windows",
            &[
                rss_mdm_inventory::builtin::MODEL,
                rss_mdm_inventory::builtin::OS_VERSION,
            ],
        )
        .coverage()
        .unwrap(),
    )
    .unwrap();
    sql(&crate::test_support::inventory::definition_sql(
        &t.to_string(),
        &crate::test_support::inventory::definition(
            "inventory",
            "mdm.windows",
            &[
                rss_mdm_inventory::builtin::MODEL,
                rss_mdm_inventory::builtin::OS_VERSION,
            ],
        ),
    )
    .unwrap());
    let old_value =
        serde_json::to_string(&rss_mdm_inventory::Scalar::String("Old".into())).unwrap();
    let new_value =
        serde_json::to_string(&rss_mdm_inventory::Scalar::String("New".into())).unwrap();
    let collection = Uuid::new_v4();
    let attempts = serde_json::to_string(&crate::collection::Attempts::new(
        crate::test_support::inventory::definition(
            "inventory",
            "mdm.windows",
            &[
                rss_mdm_inventory::builtin::MODEL,
                rss_mdm_inventory::builtin::OS_VERSION,
            ],
        ),
    ))
    .unwrap();
    sql(&format!(
        "INSERT INTO mdm.inventory(field_scope,tenant_id,journal,generation,scope,coverage,field,value,batch_id,observed_at,received_at,state,registration,source,epoch,collection_sequence) VALUES(replace(jsonb_build_object('kind','device')::text,' ',''),'{t}','mdm.observation.v1','inventory-projection-v1','{scope}','{coverage}','device.model','{old_value}','old-batch',1,2,'known','{registration}','mdm.windows','{epoch}',0); INSERT INTO mdm_access.collection_runs(tenant_id,id,registration,source,epoch,scope,sequence,started_at,attempts,result) VALUES('{t}','{collection}','{registration}','mdm.windows','{epoch}','{scope}',1,1,'{attempts}','pending')"
    ));
    let service = planning(t).await;
    let manual = |revision, input| assets::Command::Manual {
        device: device.into(),
        field: rss_mdm_inventory::builtin::IS_LOANER,
        owner: assets::Owner {
            instance: "history".into(),
            principal: "operator".into(),
        },
        change: inventory_operation(revision, input),
    };
    execute_asset(
        &service,
        &manual(
            0,
            assets::ManualChange::Set {
                value: rss_mdm_inventory::Scalar::Boolean(true),
            },
        ),
    )
    .await
    .unwrap();
    let old_cut = asset_cut();
    let before = frozen_device(&service, device, &old_cut).await;
    assert_eq!(
        before["fields"]["device.model"]["state"]["value"]["value"],
        "Old"
    );
    assert_eq!(
        before["fields"]["custom.is_loaner"]["state"]["value"]["value"],
        true
    );
    assert_eq!(before["quality"][0]["result"], "pending");
    let mut failed = crate::collection::Attempts::new(crate::test_support::inventory::definition(
        "inventory",
        "mdm.windows",
        &[
            rss_mdm_inventory::builtin::MODEL,
            rss_mdm_inventory::builtin::OS_VERSION,
        ],
    ));
    failed
        .observe_status(rss_mdm_inventory::builtin::MODEL, 500, 4)
        .unwrap();
    failed.finish();
    let failed = serde_json::to_string(&failed).unwrap();
    let changes = format!(
        "UPDATE mdm.inventory SET value='{new_value}',batch_id='new-batch',observed_at=3,received_at=4 WHERE registration='{registration}'; UPDATE mdm.manual_assignments SET revision=revision+1,fact=jsonb_set(fact,'{{state}}','{{\"kind\":\"null\"}}') WHERE device='{device}'; UPDATE mdm_access.collection_runs SET attempts='{failed}',result='failed',reason='timeout',sealed_at=4 WHERE id='{collection}';"
    );
    sql(&format!("BEGIN; {changes} ROLLBACK;"));
    assert_eq!(frozen_device(&service, device, &asset_cut()).await, before);
    sql(&changes);
    let new_cut = asset_cut();
    let changed = frozen_device(&service, device, &new_cut).await;
    assert_eq!(
        changed["fields"]["device.model"]["state"]["value"]["value"],
        "New"
    );
    assert_eq!(
        changed["fields"]["custom.is_loaner"]["state"]["kind"],
        "null"
    );
    assert_eq!(changed["quality"][0]["result"], "failed");
    assert_eq!(changed["quality"][0]["fields"][0]["quality"], "failed");
    assert_eq!(changed["quality"][0]["fields"][0]["status"], 500);
    assert_eq!(frozen_device(&service, device, &old_cut).await, before);
    // A Group snapshot must omit Secret before resolving stored values, even with internal scope.
    let mut secret = rss_mdm_inventory::builtin::fields()
        .into_iter()
        .find(|f| f.key == rss_mdm_inventory::builtin::MODEL)
        .unwrap();
    secret.sensitivity = rss_mdm_inventory::Sensitivity::Secret;
    secret.searchable = false;
    secret.manual = false;
    secret.sources.remove(&rss_mdm_inventory::Source::Manual);
    let catalog = rss_mdm_inventory::Catalog::new(vec![secret]).unwrap();
    let secret_cut = new_cut.clone();
    let snapshot = service
        .policy
        .runtime
        .local_tx(t, deadline(), move |tx| {
            Box::pin(async move {
                tx.with_connection(move |c| {
                    Box::pin(async move {
                        assets::planning::SnapshotReader { tenant: t }
                            .scalar_devices_on(c, &secret_cut, &[device.into()], &catalog)
                            .await
                            .map_err(|e| sqlx::Error::Protocol(format!("secret input: {e:?}")))
                    })
                })
                .await
            })
        })
        .await
        .fold(
            |v| v,
            |e| panic!("{e:?}"),
            |e| panic!("{e:?}"),
            |_| panic!("commit unknown"),
            |_| panic!("rollback unknown"),
            |e| panic!("{e:?}"),
        );
    assert_eq!(snapshot.len(), 1);
    assert!(snapshot[0].fields.is_empty());
    execute_asset(&service, &manual(2, assets::ManualChange::Delete {}))
        .await
        .unwrap();
    sql(&format!(
        "DELETE FROM mdm.inventory WHERE registration='{registration}'; DELETE FROM mdm_access.collection_runs WHERE id='{collection}'"
    ));
    let deleted = frozen_device(&service, device, &asset_cut()).await;
    assert_eq!(
        deleted["fields"]["device.model"]["state"]["kind"],
        "missing"
    );
    assert_eq!(
        deleted["fields"]["custom.is_loaner"]["state"]["kind"],
        "deleted"
    );
    assert_eq!(deleted["quality"], json!([]));
    assert_eq!(frozen_device(&service, device, &new_cut).await, changed);
    assert_eq!(frozen_device(&service, device, &old_cut).await, before);
    service.close().await;
}
