use super::*;

#[tokio::test]
#[ignore = "MODULE=authorization.membership: real authorization contract"]
async fn membership_activation_removal_and_replay() -> Result<()> {
    let Fixture {
        router,
        mut admin,
        mut member,
        subject,
        ..
    } = fixture().await?;
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
    ensure!(put(&mut admin, &router, &group_rule_path, Uuid::new_v4(), 0, json!({"subject":{"kind":"user_group","id":group_id},"grants":[grant("group_read",json!({"kind":"tenant"})),grant("inventory_read",json!({"kind":"all_devices"}))]})).await?.0 == StatusCode::OK);
    let target = format!("/api/v2/groups/{}", Uuid::new_v4());
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
}
