use super::*;

fn members(count: u128) -> Vec<Value> {
    (1..=count)
        .map(
            |id| json!({"instanceId":INSTANCE,"tenantId":TENANT,"principalId":Uuid::from_u128(id)}),
        )
        .collect()
}
fn no_write(id: Uuid, operation: Uuid, table: &str) -> Result<()> {
    ensure!(pg(&format!("SELECT count(*) FROM mdm_access.{table} WHERE tenant_id='{TENANT}' AND instance='{INSTANCE}' AND id='{id}'"))?.trim() == "0");
    ensure!(pg(&format!("SELECT count(*) FROM mdm_access.operations WHERE tenant_id='{TENANT}' AND operation_id='{operation}'"))?.trim() == "0");
    ensure!(pg(&format!("SELECT count(*) FROM mdm_access.audit WHERE tenant_id='{TENANT}' AND operation_id='{operation}' AND result='success'"))?.trim() == "0");
    Ok(())
}
pub(super) async fn verify(
    router: &Router,
    admin: &mut Browser,
    member: &mut Browser,
    store: &crate::AccessStore,
) -> Result<()> {
    let id = Uuid::new_v4();
    let path = format!("/api/v1/authorization/user-groups/{id}");
    let page = format!("{path}/members");
    let group = json!({"name":"pagination","enabled":true,"members":members(101)});
    ensure!(
        put(admin, router, &path, Uuid::new_v4(), 0, group.clone())
            .await?
            .0
            == StatusCode::OK
    );
    let first = admin.call(router, Method::GET, &page, None).await?;
    ensure!(
        first.0 == StatusCode::OK
            && first.1["items"].as_array().unwrap().len() == 100
            && first.1["nextOffset"] == 100
    );
    let second = admin
        .call(
            router,
            Method::GET,
            &format!("{page}?offset=100&expectedRevision=1"),
            None,
        )
        .await?;
    ensure!(
        second.0 == StatusCode::OK
            && second.1["items"].as_array().unwrap().len() == 1
            && second.1["nextOffset"].is_null()
    );
    ensure!(
        admin
            .call(router, Method::GET, &format!("{page}?offset=100"), None)
            .await?
            .0
            == StatusCode::CONFLICT
    );
    ensure!(member.call(router, Method::GET, &page, None).await?.0 == StatusCode::FORBIDDEN);
    for status in [200, 403] {
        ensure!(pg(&format!("SELECT count(*)>0 FROM mdm_access.audit WHERE action='authorization_members_read' AND target='{id}' AND status={status}"))?.trim()=="t");
    }
    ensure!(
        put(
            admin,
            router,
            &path,
            Uuid::new_v4(),
            1,
            json!({"name":"pagination","enabled":true,"members":members(100)})
        )
        .await?
        .0 == StatusCode::OK
    );
    ensure!(
        admin
            .call(
                router,
                Method::GET,
                &format!("{page}?offset=100&expectedRevision=1"),
                None
            )
            .await?
            .0
            == StatusCode::CONFLICT
    );
    let empty = admin
        .call(
            router,
            Method::GET,
            &format!("{page}?offset=10000&expectedRevision=2"),
            None,
        )
        .await?;
    ensure!(
        empty.0 == StatusCode::OK
            && empty.1["items"] == json!([])
            && empty.1["nextOffset"].is_null()
    );
    ensure!(
        admin
            .call(
                router,
                Method::GET,
                &format!("{page}?offset=10001&expectedRevision=2"),
                None
            )
            .await?
            .0
            == StatusCode::BAD_REQUEST
    );
    pg(&format!(
        "DELETE FROM mdm_access.user_groups WHERE tenant_id='{TENANT}' AND id='{id}'"
    ))?;

    for (table, path, value) in [
        (
            "user_groups",
            "user-groups",
            json!({"name":"capacity","enabled":true,"members":[]}),
        ),
        (
            "authorization_rules",
            "rules",
            json!({"subject":user(ADMIN),"grants":[grant("group_read",json!({"kind":"tenant"}))]}),
        ),
    ] {
        // Fill with valid tombstones: they count toward capacity and must not disappear from checks.
        pg(&format!(
            "INSERT INTO mdm_access.{table}(tenant_id,instance,id,revision,document) SELECT '{TENANT}','{INSTANCE}',('2363f500-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,1,NULL FROM generate_series(1,9999-(SELECT count(*)::integer FROM mdm_access.{table} WHERE tenant_id='{TENANT}' AND instance='{INSTANCE}')) n"
        ))?;
        let last = Uuid::new_v4();
        ensure!(
            put(
                admin,
                router,
                &format!("/api/v1/authorization/{path}/{last}"),
                Uuid::new_v4(),
                0,
                value.clone()
            )
            .await?
            .0 == StatusCode::OK
        );
        let over = Uuid::new_v4();
        let operation = Uuid::new_v4();
        ensure!(
            put(
                admin,
                router,
                &format!("/api/v1/authorization/{path}/{over}"),
                operation,
                0,
                value
            )
            .await?
            .0 == StatusCode::CONFLICT
        );
        no_write(over, operation, table)?;
        pg(&format!(
            "INSERT INTO mdm_access.{table}(tenant_id,instance,id,revision,document) VALUES('{TENANT}','{INSTANCE}','{over}',1,NULL)"
        ))?;
        ensure!(
            admin
                .call(router, Method::GET, "/api/v1/authorization", None)
                .await?
                .0
                == StatusCode::SERVICE_UNAVAILABLE
        );
        pg(&format!(
            "DELETE FROM mdm_access.{table} WHERE tenant_id='{TENANT}' AND instance='{INSTANCE}' AND (id::text LIKE '2363f500-0000-4000-8000-%' OR id IN ('{last}','{over}'))"
        ))?;
    }
    let large = json!({"name":"capacity","enabled":true,"members":members(10000)});
    let mut ids = Vec::new();
    loop {
        let id = Uuid::new_v4();
        let operation = Uuid::new_v4();
        let response = put(
            admin,
            router,
            &format!("/api/v1/authorization/user-groups/{id}"),
            operation,
            0,
            large.clone(),
        )
        .await?;
        if response.0 == StatusCode::CONFLICT {
            no_write(id, operation, "user_groups")?;
            break;
        }
        ensure!(
            response.0 == StatusCode::OK,
            "large group boundary failed: {}",
            response.0
        );
        ids.push(id);
        ensure!(ids.len() < 10, "aggregate limit not enforced");
    }
    ensure!(ids.len() >= 4, "near-limit success not reached");
    let oversized = Uuid::new_v4();
    pg(&format!(
        "INSERT INTO mdm_access.user_groups SELECT tenant_id,instance,'{oversized}',1,document FROM mdm_access.user_groups WHERE id='{}'",
        ids[0]
    ))?;
    ensure!(
        admin
            .call(router, Method::GET, "/api/v1/authorization", None)
            .await?
            .0
            == StatusCode::SERVICE_UNAVAILABLE
    );
    ids.push(oversized);
    for id in ids {
        pg(&format!(
            "DELETE FROM mdm_access.user_groups WHERE tenant_id='{TENANT}' AND id='{id}'"
        ))?;
    }
    // The database independently rejects a single over-size document, even if application checks are bypassed.
    pg(&format!(
        "DO $$ BEGIN BEGIN INSERT INTO mdm_access.user_groups VALUES('{TENANT}','{INSTANCE}','{oversized}',1,jsonb_build_object('oversized',repeat('x',2097152))); EXCEPTION WHEN check_violation THEN RETURN; END; RAISE EXCEPTION 'document limit absent'; END $$"
    ))?;
    let operation = Uuid::new_v4();
    let id = Uuid::new_v4();
    let too_large = json!({"name":"x".repeat(2*1024*1024),"enabled":true,"members":[]});
    ensure!(
        put(
            admin,
            router,
            &format!("/api/v1/authorization/user-groups/{id}"),
            operation,
            0,
            too_large
        )
        .await?
        .0 == StatusCode::PAYLOAD_TOO_LARGE
    );
    no_write(id, operation, "user_groups")?;

    // The same command deadline projection is used before COMMIT and after a durable but unacknowledged COMMIT.
    for fault in [3, 4] {
        let mut user = crate::identity_fixture::user(TENANT, ADMIN);
        user.instance_id = Uuid::new_v4().to_string();
        let key = Uuid::new_v4();
        let audit = crate::audit::Audit::new(TENANT.into(), "authorization_initialize");
        store.fail_next(fault);
        let deadline = rss_request_context::Deadline::from_timeout(
            &crate::lifecycle::RuntimeTimer,
            std::time::Duration::from_millis(100),
        )?;
        let outcome = crate::authorization::bounded_initialization(
            &audit,
            deadline,
            store.initialize_authorization_audited(user.clone(), key, &audit),
        )
        .await;
        audit.finalize(Some(crate::audit::FailureReason::Transaction));
        ensure!(matches!(outcome, Err(crate::Error::CommitUnknown)));
        let durable = pg(&format!(
            "SELECT count(*) FROM mdm_access.authorization_initializations WHERE tenant_id='{TENANT}' AND instance='{}'",
            user.instance_id
        ))?;
        ensure!(durable.trim() == if fault == 4 { "1" } else { "0" });
        let receipt = store.initialize_authorization(user.clone(), key).await?;
        ensure!(store.initialize_authorization(user, key).await?.id == receipt.id);
    }
    let audit = crate::audit::Audit::new(TENANT.into(), "authorization_initialize");
    let deadline = rss_request_context::Deadline::from_timeout(
        &crate::lifecycle::RuntimeTimer,
        std::time::Duration::from_millis(10),
    )?;
    let before: Result<(), crate::Error> =
        crate::authorization::bounded_initialization(&audit, deadline, std::future::pending())
            .await;
    audit.finalize(Some(crate::audit::FailureReason::Transaction));
    ensure!(matches!(
        before,
        Err(crate::Error::Unavailable(crate::Failure::RequestDeadline))
    ));
    Ok(())
}
