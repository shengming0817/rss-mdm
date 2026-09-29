use crate::planning::test_support::*;

#[tokio::test]
#[ignore = "MODULE=planning.assets: real capability storage and transactions"]
async fn asset_history_rollback_replay_and_frozen_watermark() {
    let t = tenant();
    let device = format!("history-{}", Uuid::new_v4());
    let read = || {
        sql(&format!(
            "SELECT coalesce(max(revision),0) FROM mdm.asset_changes WHERE tenant_id='{t}'"
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
            "SELECT document->>'id' FROM mdm_access.asset_authority_history WHERE tenant_id='{t}' AND kind='device' AND identity='{device}' AND revision<={created} ORDER BY revision DESC LIMIT 1"
        )),
        device
    );
    assert_eq!(
        sql(&format!(
            "SELECT document IS NULL FROM mdm_access.asset_authority_history WHERE tenant_id='{t}' AND kind='device' AND identity='{device}' ORDER BY revision DESC LIMIT 1"
        )),
        "t"
    );
    let service = planning(t).await;
    let scope_device = device.clone();
    let frozen = service
        .runtime
        .local_tx_with_context(t, deadline(), &service, move |s, tx| {
            Box::pin(async move {
                s.asset_reader
                    .asset_page_in(
                        tx,
                        created,
                        None,
                        1,
                        &assets::ReadScope {
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
    assert_eq!(frozen.devices[0].device, device);
    assert!(frozen.next.is_none());
    assert_eq!(service.forward_asset_changes().await.unwrap(), 2);
    assert_eq!(service.forward_asset_changes().await.unwrap(), 0);
    assert_eq!(
        sql(&format!(
            "SELECT count(*) FROM rss_reconcile.targets WHERE tenant_id='{t}' AND reconciler='mdm.assets' AND entity='changes'"
        )),
        "1"
    );
    assert_eq!(
        sql(&format!(
            "SELECT count(*) FROM mdm.asset_changes WHERE tenant_id='{t}' AND revision>{before}"
        )),
        "2",
        "forwarding must retain the durable input"
    );
    service.runtime.close().await;
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
    let coverage = serde_json::to_string(&rss_mdm_inventory::coverage()).unwrap();
    let collection = Uuid::new_v4();
    let attempts = serde_json::to_string(&crate::collection::Attempts::default()).unwrap();
    sql(&format!(
        "INSERT INTO mdm.inventory(tenant_id,journal,generation,scope,coverage,field,value,batch_id,observed_at,received_at,state,registration,source,epoch) VALUES('{t}','mdm.observation.v1','inventory-v3','{scope}','{coverage}','device.model','Old','old-batch',1,2,'known','{registration}','mdm.windows','{epoch}'); INSERT INTO mdm_access.collection_runs(tenant_id,id,registration,source,epoch,scope,sequence,session_id,request_message,first_command,request,started_at,attempts,result) VALUES('{t}','{collection}','{registration}','mdm.windows','{epoch}','{scope}',1,'history',1,1024,decode('01','hex'),1,'{attempts}','pending')"
    ));
    let service = planning(t).await;
    let manual = |revision, input| assets::Command::Manual {
        device: device.into(),
        field: assets::FieldKey::IsLoaner,
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
    let watermark = || {
        sql(&format!(
            "SELECT revision FROM mdm.asset_clock WHERE tenant_id='{t}'"
        ))
        .parse::<i64>()
        .unwrap()
    };
    let old_watermark = watermark();
    let before = frozen_device(&service, device, old_watermark).await;
    assert_eq!(
        before["fields"]["device.model"]["state"]["value"]["value"],
        "Old"
    );
    assert_eq!(
        before["fields"]["custom.is_loaner"]["state"]["value"]["value"],
        true
    );
    assert_eq!(before["quality"][0]["result"], "pending");
    let mut failed = crate::collection::Attempts::default();
    failed.fields[0].quality = crate::collection::Quality::Failed;
    failed.fields[0].status = Some(500);
    failed.fields[0].received_at = Some(4);
    let failed = serde_json::to_string(&failed).unwrap();
    let changes = format!(
        "UPDATE mdm.inventory SET value='New',batch_id='new-batch',observed_at=3,received_at=4 WHERE registration='{registration}'; UPDATE mdm.manual_assignments SET revision=revision+1,fact=jsonb_set(fact,'{{state}}','{{\"kind\":\"null\"}}') WHERE device='{device}'; UPDATE mdm_access.collection_runs SET attempts='{failed}',result='failed',reason='timeout',sealed_at=4 WHERE id='{collection}';"
    );
    sql(&format!("BEGIN; {changes} ROLLBACK;"));
    assert_eq!(
        watermark(),
        old_watermark,
        "rollback advanced committed watermarks"
    );
    assert_eq!(frozen_device(&service, device, watermark()).await, before);
    sql(&changes);
    let new_watermark = watermark();
    let changed = frozen_device(&service, device, new_watermark).await;
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
    assert_eq!(frozen_device(&service, device, old_watermark).await, before);
    execute_asset(&service, &manual(2, assets::ManualChange::Delete {}))
        .await
        .unwrap();
    sql(&format!(
        "DELETE FROM mdm.inventory WHERE registration='{registration}'; DELETE FROM mdm_access.collection_runs WHERE id='{collection}'"
    ));
    let deleted = frozen_device(&service, device, watermark()).await;
    assert_eq!(
        deleted["fields"]["device.model"]["state"]["kind"],
        "missing"
    );
    assert_eq!(
        deleted["fields"]["custom.is_loaner"]["state"]["kind"],
        "deleted"
    );
    assert_eq!(deleted["quality"], json!([]));
    assert_eq!(
        frozen_device(&service, device, new_watermark).await,
        changed
    );
    assert_eq!(frozen_device(&service, device, old_watermark).await, before);
    service.runtime.close().await;
}
