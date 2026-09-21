//! Real Router and PostgreSQL rules, membership, CAS, receipts and one-time initialization.
use super::*;
use uuid::Uuid;
mod boundaries;

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
    let reader = Arc::new(
        InventoryReader::connect(
            config
                .access_database
                .options()?
                .username("mdm_api")
                .password("api-fixture"),
        )
        .await?,
    );
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
    for (suffix, action, allowed) in [
        ("", "authorization_effective_read", true),
        ("/rules", "authorization_rules_read", false),
        ("/user-groups", "authorization_groups_read", false),
        ("/departments", "authorization_departments_read", false),
    ] {
        let path = format!("/api/v1/authorization{suffix}");
        for (browser, expected) in [
            (&mut admin, 200),
            (&mut member, if allowed { 200 } else { 403 }),
        ] {
            let before = pg(&format!("SELECT count(*) FROM mdm_access.audit WHERE action='{action}' AND status={expected}"))?.trim().parse::<i64>()?;
            ensure!(
                browser
                    .call(&router, Method::GET, &path, None)
                    .await?
                    .0
                    .as_u16()
                    == expected
            );
            let after = pg(&format!("SELECT count(*) FROM mdm_access.audit WHERE action='{action}' AND status={expected}"))?.trim().parse::<i64>()?;
            ensure!(
                after == before + 1,
                "authorization read audit action missing: {action}"
            );
        }
    }
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
                    &format!("/api/v1/devices/{device}/inventory"),
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
    let group =
        json!({"name":"explicit users","enabled":true,"members":[user(&subject)["user"].clone()]});
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
    let mut disabled = group.clone();
    disabled["enabled"] = json!(false);
    ensure!(
        put(
            &mut admin,
            &router,
            &group_path,
            Uuid::new_v4(),
            1,
            disabled
        )
        .await?
        .0 == StatusCode::OK
    );
    ensure!(member.call(&router, Method::GET, &target, None).await?.0 == StatusCode::FORBIDDEN);
    let listed = admin
        .call(
            &router,
            Method::GET,
            "/api/v1/authorization/user-groups",
            None,
        )
        .await?
        .1;
    let listed = listed["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["id"] == group_id.to_string())
        .unwrap();
    ensure!(listed["value"]["enabled"] == false && listed["value"]["memberCount"] == 1);
    // Replaying the enabled creation returns its receipt without changing the disabled document.
    ensure!(
        put(
            &mut admin,
            &router,
            &group_path,
            group_key,
            0,
            group.clone()
        )
        .await?
        .1 == created_group.1
    );
    ensure!(member.call(&router, Method::GET, &target, None).await?.0 == StatusCode::FORBIDDEN);
    ensure!(
        put(
            &mut admin,
            &router,
            &group_path,
            Uuid::new_v4(),
            2,
            group.clone()
        )
        .await?
        .0 == StatusCode::OK
    );
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
            3,
            json!({"name":"explicit users","enabled":true,"members":[]})
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
            4,
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
    boundaries::verify(&router, &mut admin, &mut member, &store).await?;
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
    store.fail_next(2);
    ensure!(matches!(
        store
            .initialize_authorization(isolated.clone(), init_key)
            .await,
        Err(crate::Error::CommitUnknown)
    ));
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
    let context = admin
        .call(
            &router,
            Method::GET,
            &format!("/api/identity-host/v1/tenants/{TENANT}/context"),
            None,
        )
        .await?;
    let reconnect = crate::AccessStore::connect(config.access_database.options()?).await;
    pg("GRANT SELECT ON mdm_access.authorization_rules TO mdm_access")?;
    ensure!(
        denied.0 == StatusCode::SERVICE_UNAVAILABLE
            && denied.1.get("grants").is_none()
            && reconnect.is_err()
            && context.0 == StatusCode::OK
            && context.1["navigation"]["manageAccounts"] == true
    );
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_access.audit WHERE operation_id='{key}' AND result='success'"
        ))?
        .trim()
            == "1"
    );
    // A valid-looking but absent target never acquires the irreversible bootstrap marker.
    let wrong_key = Uuid::new_v4();
    let mut init = json!({"database":base["access_database"],"identityDatabase":base["identity"]["database"],
        "installation":{"instance_id":INSTANCE,"target":base["management"]["target"],"lineage":base["management"]["lineage"],"epoch":base["management"]["epoch"],"tenants":[TENANT]},
        "login":"authorization-member","passwordFile":std::path::Path::new(&std::env::var("MDM_TEST_CONFIG")?).parent().unwrap().join("account-password"),
        "operationId":wrong_key,"user":{"instanceId":INSTANCE,"tenantId":TENANT,"principalId":Uuid::new_v4()}});
    ensure!(matches!(
        crate::authorization::initialize(serde_json::from_value(init.clone())?).await,
        Err(crate::Error::Forbidden)
    ));
    init["user"]["principalId"] = subject.clone().into();
    init["user"]["instanceId"] = Uuid::new_v4().to_string().into();
    ensure!(matches!(
        crate::authorization::initialize(serde_json::from_value(init)?).await,
        Err(crate::Error::Configuration(_))
    ));
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_access.operations WHERE operation_id='{wrong_key}'"
        ))?
        .trim()
            == "0"
    );
    // A proof loaded before revocation cannot later mutate authorization state.
    let writer_id = Uuid::new_v4();
    let writer_path = format!("/api/v1/authorization/rules/{writer_id}");
    let writer_rule = json!({"subject":user(&subject),"grants":[grant("authorization_write",json!({"kind":"tenant"}))]});
    ensure!(
        put(
            &mut admin,
            &router,
            &writer_path,
            Uuid::new_v4(),
            0,
            writer_rule
        )
        .await?
        .0 == StatusCode::OK
    );
    let identity = crate::identity_fixture::identity(TENANT).await?;
    let stale = crate::identity::Principal::new(
        identity
            .authority
            .inspect_session(
                identity.tenant,
                rss_identity_core::session::SessionSecret::parse(
                    member.cookies["__Host-identity-session"].clone(),
                )?,
                crate::identity::deadline(),
            )
            .await?,
    )?
    .load_authorization(&store)
    .await?;
    ensure!(
        put(
            &mut admin,
            &router,
            &writer_path,
            Uuid::new_v4(),
            1,
            Value::Null
        )
        .await?
        .0 == StatusCode::OK
    );
    let audit = crate::audit::Audit::new(TENANT.into(), "authorization_write");
    audit.identify(&stale);
    let rejected = store.change_rule(&stale, Uuid::new_v4(), crate::authorization::Change {
        operation_id:Uuid::new_v4(), expected_revision:0, value:Some(serde_json::from_value(json!({"subject":user(&subject),"grants":[grant("group_read",json!({"kind":"tenant"}))]}))?)
    }, &audit).await;
    audit.finalize(None);
    let stale_denied = matches!(rejected, Err(crate::Error::Forbidden));
    // Membership administration cannot confer a group's unrelated authority.
    let privilege_group = Uuid::new_v4();
    let privilege_group_path = format!("/api/v1/authorization/user-groups/{privilege_group}");
    ensure!(
        put(
            &mut admin,
            &router,
            &privilege_group_path,
            Uuid::new_v4(),
            0,
            json!({"name":"privileged","enabled":true,"members":[]})
        )
        .await?
        .0 == StatusCode::OK
    );
    let group_rule = format!("/api/v1/authorization/rules/{}", Uuid::new_v4());
    ensure!(put(&mut admin, &router, &group_rule, Uuid::new_v4(), 0, json!({"subject":{"kind":"user_group","id":privilege_group},"grants":[grant("authorization_write",json!({"kind":"tenant"}))]})).await?.0 == StatusCode::OK);
    let member_rule = format!("/api/v1/authorization/rules/{}", Uuid::new_v4());
    ensure!(put(&mut admin, &router, &member_rule, Uuid::new_v4(), 0, json!({"subject":user(&subject),"grants":[grant("user_group_write",json!({"kind":"tenant"}))]})).await?.0 == StatusCode::OK);
    let escalation = put(
        &mut member,
        &router,
        &privilege_group_path,
        Uuid::new_v4(),
        1,
        json!({"name":"privileged","enabled":true,"members":[user(&subject)["user"].clone()]}),
    )
    .await?;
    let escalation_denied = escalation.0 == StatusCode::FORBIDDEN;
    ensure!(
        stale_denied && escalation_denied,
        "stale writer denied={stale_denied}; group escalation denied={escalation_denied}"
    );
    // Stop protocol replies after BEGIN/query, beyond the pool acquire timeout.
    use sqlx::Connection;
    let mut holder =
        sqlx::PgConnection::connect_with(&crate::device::tests::options("postgres")?).await?;
    sqlx::raw_sql("BEGIN; LOCK TABLE mdm_access.authorization_rules IN ACCESS EXCLUSIVE MODE")
        .execute(&mut holder)
        .await?;
    let container = std::env::var("MDM_TEST_PG_CONTAINER")?;
    let freeze = async {
        let deadline = rss_request_context::Clock::now(&crate::lifecycle::RuntimeTimer)
            + Duration::from_millis(750);
        loop {
            sqlx::query("SELECT pg_stat_clear_snapshot()")
                .execute(&mut holder)
                .await?;
            let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='mdm_access' AND wait_event_type='Lock' AND query LIKE 'WITH rules AS MATERIALIZED%')").fetch_one(&mut holder).await?;
            if waiting {
                break;
            }
            ensure!(
                rss_request_context::Clock::now(&crate::lifecycle::RuntimeTimer) < deadline,
                "snapshot did not enter SQL"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        command(&["pause", &container], None)?;
        tokio::time::sleep(Duration::from_millis(3200)).await;
        command(&["unpause", &container], None)?;
        sqlx::query("ROLLBACK").execute(&mut holder).await?;
        anyhow::Ok(())
    };
    let (stalled, frozen) = tokio::join!(
        tokio::time::timeout(Duration::from_secs(4), store.authorization_snapshot(&stale)),
        freeze
    );
    frozen?;
    holder.close().await?;
    ensure!(matches!(
        stalled,
        Ok(Err(crate::Error::Unavailable(
            crate::Failure::RequestDeadline
        )))
    ));
    ensure!(
        member
            .call(&router, Method::GET, "/api/v1/authorization", None)
            .await?
            .0
            == StatusCode::OK
    );
    tokio::time::timeout(Duration::from_secs(8), store.close()).await?;
    println!("MDM_DYNAMIC_AUTHORIZATION_PG_HTTP_PASSED");
    Ok(())
}
