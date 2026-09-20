//! Real Router and PostgreSQL rules, membership, CAS, receipts and one-time initialization.
use super::*;
use uuid::Uuid;

async fn put(
    browser: &mut Browser,
    router: &Router,
    path: &str,
    operation: Uuid,
    revision: u64,
    value: Value,
) -> Result<(StatusCode, Value)> {
    browser
        .call(
            router,
            Method::PUT,
            path,
            Some(json!({"operationId":operation,"expectedRevision":revision,"value":value})),
        )
        .await
}
fn user(subject: &str) -> Value {
    json!({"kind":"user","user":{"instanceId":INSTANCE,"tenantId":TENANT,"principalId":subject}})
}
fn grant(operation: &str, scope: Value) -> Value {
    json!({"operation":operation,"scope":scope})
}

#[tokio::test]
#[ignore = "make t2-identity: persistent authorization through real PG and HTTP"]
async fn persistent_rules_membership_cas_replay_and_restart() -> Result<()> {
    let base: Value = serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
    let config: Config = serde_json::from_value(base.clone())?;
    let reader = Arc::new(InventoryReader::connect(config.database.options()?).await?);
    let router = app(&base, reader.clone()).await?;
    let mut admin = Browser::default();
    let mut member = Browser::default();
    ensure!(admin.login(&router, "admin").await? == StatusCode::OK);
    ensure!(
        admin
            .call(
                &router,
                Method::POST,
                &format!("/api/v2/tenants/{TENANT}/accounts"),
                Some(json!({"login":"authorization-member","password":PASSWORD}))
            )
            .await?
            .0
            == StatusCode::CREATED
    );
    ensure!(member.login(&router, "authorization-member").await? == StatusCode::OK);
    let subject = browser_subject(&member, &router).await?;
    let store = access_store(&base).await?;
    ensure!(matches!(
        store
            .initialize_authorization(crate::identity_fixture::user(TENANT, ADMIN), Uuid::new_v4())
            .await,
        Err(crate::Error::Conflict)
    ));
    ensure!(
        member
            .call(&router, Method::GET, "/api/v1/authorization/rules", None)
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    let rule_id = Uuid::new_v4();
    let key = Uuid::new_v4();
    let path = format!("/api/v1/authorization/rules/{rule_id}");
    let value = json!({"subject":user(&subject),"grants":[grant("inventory_read",json!({"kind":"device","id":"a"})),grant("device_wipe",json!({"kind":"device","id":"b"}))]});
    let created = put(&mut admin, &router, &path, key, 0, value.clone()).await?;
    ensure!(created.0 == StatusCode::OK && created.1["revision"] == 1);
    ensure!(
        put(&mut admin, &router, &path, key, 0, value.clone())
            .await?
            .1
            == created.1
    );
    ensure!(
        put(&mut admin, &router, &path, key, 0, Value::Null)
            .await?
            .0
            == StatusCode::CONFLICT
    );
    for (device, expected) in [("a", StatusCode::NOT_FOUND), ("b", StatusCode::FORBIDDEN)] {
        ensure!(
            member
                .call(
                    &router,
                    Method::GET,
                    &format!("/api/v1/devices/{device}/inventory?source=mdm.windows"),
                    None
                )
                .await?
                .0
                == expected
        );
    }
    for (device, expected) in [
        ("a", StatusCode::FORBIDDEN),
        ("b", StatusCode::NOT_IMPLEMENTED),
    ] {
        ensure!(
            member
                .call(
                    &router,
                    Method::POST,
                    &format!("/api/v1/devices/{device}/actions"),
                    Some(json!({"action":"wipe"}))
                )
                .await?
                .0
                == expected
        );
    }
    let mut a = admin.clone();
    let mut b = admin.clone();
    let (first, second) = tokio::join!(
        put(&mut a, &router, &path, Uuid::new_v4(), 1, value.clone()),
        put(&mut b, &router, &path, Uuid::new_v4(), 1, value.clone())
    );
    let mut statuses = [first?.0.as_u16(), second?.0.as_u16()];
    statuses.sort();
    ensure!(statuses == [200, 409]);
    ensure!(
        put(&mut admin, &router, &path, Uuid::new_v4(), 2, Value::Null)
            .await?
            .0
            == StatusCode::OK
    );
    // Returning an old receipt never restores a revoked document.
    ensure!(
        put(&mut admin, &router, &path, key, 0, value.clone())
            .await?
            .1
            == created.1
    );
    ensure!(
        put(&mut admin, &router, &path, Uuid::new_v4(), 3, value)
            .await?
            .0
            == StatusCode::CONFLICT
    );
    let restarted = app(&base, reader.clone()).await?;
    ensure!(
        member
            .call(
                &restarted,
                Method::POST,
                "/api/v1/devices/b/actions",
                Some(json!({"action":"wipe"}))
            )
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    let group_id = Uuid::new_v4();
    let group_path = format!("/api/v1/authorization/user-groups/{group_id}");
    let group_key = Uuid::new_v4();
    let group = json!({"name":"explicit users","members":[user(&subject)["user"].clone()]});
    let created_group = put(
        &mut admin,
        &router,
        &group_path,
        group_key,
        0,
        group.clone(),
    )
    .await?;
    ensure!(created_group.0 == StatusCode::OK);
    let group_rule_path = format!("/api/v1/authorization/rules/{}", Uuid::new_v4());
    ensure!(put(&mut admin, &router, &group_rule_path, Uuid::new_v4(), 0, json!({"subject":{"kind":"user_group","id":group_id},"grants":[grant("group_read",json!({"kind":"tenant"}))]})).await?.0 == StatusCode::OK);
    let target = format!("/api/v1/groups/{}", Uuid::new_v4());
    ensure!(member.call(&router, Method::GET, &target, None).await?.0 == StatusCode::NOT_FOUND);
    let members_path = format!("{group_path}/members");
    ensure!(
        admin
            .call(&router, Method::GET, &members_path, None)
            .await?
            .1["items"]
            .as_array()
            .unwrap()
            .len()
            == 1
    );
    ensure!(
        put(
            &mut admin,
            &router,
            &group_path,
            Uuid::new_v4(),
            1,
            json!({"name":"explicit users","members":[]})
        )
        .await?
        .0 == StatusCode::OK
    );
    ensure!(member.call(&router, Method::GET, &target, None).await?.0 == StatusCode::FORBIDDEN);
    ensure!(
        put(&mut admin, &router, &group_path, group_key, 0, group)
            .await?
            .1
            == created_group.1
    );
    ensure!(member.call(&router, Method::GET, &target, None).await?.0 == StatusCode::FORBIDDEN);
    ensure!(
        put(
            &mut admin,
            &router,
            &group_path,
            Uuid::new_v4(),
            2,
            Value::Null
        )
        .await?
        .0 == StatusCode::OK
    );
    ensure!(
        put(
            &mut admin,
            &router,
            &group_rule_path,
            Uuid::new_v4(),
            1,
            Value::Null
        )
        .await?
        .0 == StatusCode::OK
    );
    // The initializer marker, grant, receipt and audit must all roll back together.
    let mut isolated = crate::identity_fixture::user(TENANT, ADMIN);
    isolated.instance_id = Uuid::new_v4().to_string();
    let init_key = Uuid::new_v4();
    pg("REVOKE INSERT ON mdm_access.audit FROM mdm_access")?;
    let failed = store
        .initialize_authorization(isolated.clone(), init_key)
        .await;
    pg("GRANT INSERT ON mdm_access.audit TO mdm_access")?;
    ensure!(failed.is_err());
    for table in [
        "authorization_initializations",
        "authorization_rules",
        "operations",
    ] {
        ensure!(pg(&format!("SELECT count(*) FROM mdm_access.{table} WHERE tenant_id='{TENANT}' AND instance='{}'", isolated.instance_id))?.trim() == "0");
    }
    let initial = store
        .initialize_authorization(isolated.clone(), init_key)
        .await?;
    // Simulate the persisted result of deleting the seed, without changing its marker/receipt.
    pg(&format!(
        "UPDATE mdm_access.authorization_rules SET revision=2,document=NULL WHERE tenant_id='{TENANT}' AND instance='{}' AND id='{}'",
        isolated.instance_id, initial.id
    ))?;
    let reopened = access_store(&base).await?;
    let replayed = reopened
        .initialize_authorization(isolated.clone(), init_key)
        .await?;
    ensure!(replayed.id == initial.id && replayed.revision == initial.revision);
    ensure!(matches!(
        reopened
            .initialize_authorization(isolated.clone(), Uuid::new_v4())
            .await,
        Err(crate::Error::Conflict)
    ));
    ensure!(pg(&format!("SELECT document IS NULL FROM mdm_access.authorization_rules WHERE tenant_id='{TENANT}' AND instance='{}' AND id='{}'", isolated.instance_id, initial.id))?.trim() == "t");
    reopened.close().await;
    // Corrupt stored policy is an unavailable authorization authority, never an ignored rule.
    pg(&format!(
        "UPDATE mdm_access.authorization_rules SET document='{{\"broken\":true}}' WHERE tenant_id='{TENANT}' AND id='{rule_id}'"
    ))?;
    let corrupt = member
        .call(&router, Method::GET, "/api/v1/authorization", None)
        .await?;
    pg(&format!(
        "UPDATE mdm_access.authorization_rules SET document=NULL WHERE tenant_id='{TENANT}' AND id='{rule_id}'"
    ))?;
    ensure!(corrupt.0 == StatusCode::SERVICE_UNAVAILABLE && corrupt.1.get("grants").is_none());
    // Runtime admission and data access both fail closed on PG permission drift.
    pg("REVOKE SELECT ON mdm_access.authorization_rules FROM mdm_access")?;
    let denied = member
        .call(&router, Method::GET, "/api/v1/authorization", None)
        .await?;
    let reconnect = crate::AccessStore::connect(config.access_database.options()?).await;
    pg("GRANT SELECT ON mdm_access.authorization_rules TO mdm_access")?;
    ensure!(
        denied.0 == StatusCode::SERVICE_UNAVAILABLE
            && denied.1.get("grants").is_none()
            && reconnect.is_err()
    );
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_access.audit WHERE operation_id='{key}' AND result='success'"
        ))?
        .trim()
            == "1"
    );
    store.close().await;
    println!("MDM_DYNAMIC_AUTHORIZATION_PG_HTTP_PASSED");
    Ok(())
}
