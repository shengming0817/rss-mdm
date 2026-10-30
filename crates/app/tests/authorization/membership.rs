use super::*;

#[tokio::test]
#[ignore = "MODULE=authorization.membership: real authorization contract"]
async fn membership_activation_removal_and_replay() -> Result<()> {
    let mut authority = authority::Authority::open().await?;
    let tenant = authority.identity.tenant;
    let runtime = crate::planning::test_support::policy_runtime(tenant).await;
    authority
        .resources
        .resource(SourceResource(runtime.clone()));
    let key = crate::planning::test_support::cursor_key(tenant).await;
    let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5));
    let audit = Arc::new(
        authority
            .audit
            .on_runtime(runtime.clone(), tenant, &budget.control())
            .await?,
    );
    let planning = Arc::new(
        crate::planning::test_support::OwnerFixture::new(
            audit.clone(),
            runtime,
            tenant,
            Arc::new(crate::clock::SystemClock),
            &key,
            Arc::new(rss_mdm_device_service::planning::PlanningObjects),
        )
        .await?,
    );
    authority
        .resources
        .resource(crate::planning::test_support::OwnerResource(
            planning.clone(),
        ));
    let groups = Arc::new(crate::planning::test_support::groups(&planning).await);
    let routes = {
        rss_mdm_http_contract::route_module! { struct MembershipActivationRemovalAndReplayModule1 for [Browser] { api_v1 at "/api/v1" } }
        MembershipActivationRemovalAndReplayModule1 {
            api_v1: rss_mdm_management_http::planning::http::routes().with_state(Arc::new(
                rss_mdm_management_http::planning::http::HttpState {
                    scopes: crate::planning::test_support::scopes(&planning).await,
                    groups,
                },
            )),
        }
        .assemble()
    };
    let router = authority.router({
 rss_mdm_http_contract::route_module! { struct MembershipActivationRemovalAndReplayModule301 for [Browser] { base, routes } }
 MembershipActivationRemovalAndReplayModule301 { base: authority.authorization(),
routes }.assemble()
})?;
    let mut admin = authority.browser("admin")?;
    let mut member = authority.browser("other")?;
    let subject = prepared_subject(&member)?;
    let resources = authority.resources;
    resources.finish(async {
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
    let rule_id = Uuid::new_v4();
    let group_rule_path = format!("/api/v1/authorization/rules/{rule_id}");
    let rule: crate::authorization::Rule = serde_json::from_value(json!({"subject":{"kind":"user_group","id":group_id},"grants":[grant("group_read",json!({"kind":"tenant"})),grant("inventory_read",json!({"kind":"all_devices"}))]}))?;
    rule.validate(case_tenant(), INSTANCE)?;
    let mut tx = authority.pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)").bind(case_tenant()).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_access.authorization_rules(tenant_id,instance,id,revision,document) VALUES($1::uuid,$2::uuid,$3,1,$4)")
        .bind(case_tenant()).bind(INSTANCE).bind(rule_id).bind(serde_json::to_value(rule)?).execute(&mut *tx).await?;
    tx.commit().await?;
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

    Ok(())
    }).await
}
