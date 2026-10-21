#![allow(
    clippy::cognitive_complexity,
    reason = "test scenarios retain distinct authorization, failure and recovery assertions"
)]
use super::*;
use crate::audit_test_support::audit_count;

fn members(count: u128) -> Vec<Value> {
    (1..=count)
        .map(
            |id| json!({"instanceId":INSTANCE,"tenantId":case_tenant(),"principalId":Uuid::from_u128(id)}),
        )
        .collect()
}
fn no_write(id: Uuid, operation: Uuid, table: &str) -> Result<()> {
    ensure!(pg(&format!("SELECT count(*) FROM mdm_access.{table} WHERE tenant_id='{TENANT}' AND instance='{INSTANCE}' AND id='{id}'", TENANT = case_tenant()))?.trim() == "0");
    ensure!(pg(&format!("SELECT count(*) FROM mdm_access.authorization_operations WHERE tenant_id='{TENANT}' AND operation_id='{operation}'", TENANT = case_tenant()))?.trim() == "0");
    ensure!(
        audit_count(|r| r.source() == "mdm.business"
            && r.operation() == Some(operation.to_string().as_str())
            && r.result() == "success")?
            == 0
    );
    Ok(())
}
async fn verify(router: &Router, admin: &mut Browser, member: &mut Browser) -> Result<()> {
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
            && first.1["items"] == json!(members(100))
            && first.1["revision"] == 1
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
            && second.1["items"] == json!([members(101).pop().unwrap()])
            && second.1["revision"] == 1
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
        ensure!(
            audit_count(|r| r.action() == "authorization_members_read"
                && r.target() == id.to_string()
                && r.status() == status)?
                > 0
        );
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
        "DELETE FROM mdm_access.user_groups WHERE tenant_id='{TENANT}' AND id='{id}'",
        TENANT = case_tenant()
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
            json!({"subject":user(case_admin()),"grants":[grant("group_read",json!({"kind":"tenant"}))]}),
        ),
    ] {
        // Fill with valid tombstones: they count toward capacity and must not disappear from checks.
        pg(&format!(
            "INSERT INTO mdm_access.{table}(tenant_id,instance,id,revision,document) SELECT '{TENANT}','{INSTANCE}',('2363f500-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,1,NULL FROM generate_series(1,9999-(SELECT count(*)::integer FROM mdm_access.{table} WHERE tenant_id='{TENANT}' AND instance='{INSTANCE}')) n",
            TENANT = case_tenant()
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
            "INSERT INTO mdm_access.{table}(tenant_id,instance,id,revision,document) VALUES('{TENANT}','{INSTANCE}','{over}',1,NULL)",
            TENANT = case_tenant()
        ))?;
        ensure!(
            admin
                .call(router, Method::GET, "/api/v1/authorization", None)
                .await?
                .0
                == StatusCode::SERVICE_UNAVAILABLE
        );
        pg(&format!(
            "DELETE FROM mdm_access.{table} WHERE tenant_id='{TENANT}' AND instance='{INSTANCE}' AND (id::text LIKE '2363f500-0000-4000-8000-%' OR id IN ('{last}','{over}'))",
            TENANT = case_tenant()
        ))?;
    }
    let large = json!({"name":"capacity","enabled":true,"members":members(10000)});
    let document = serde_json::to_string(&large)?.replace('\'', "''");
    let sizes: Value = serde_json::from_str(&pg(&format!(
        "SELECT jsonb_build_array(octet_length('{document}'::jsonb::text),(SELECT coalesce(sum(octet_length(document::text)),0) FROM mdm_access.authorization_rules WHERE tenant_id='{tenant}' AND instance='{INSTANCE}')+(SELECT coalesce(sum(octet_length(document::text)),0) FROM mdm_access.user_groups WHERE tenant_id='{tenant}' AND instance='{INSTANCE}'))::text",
        tenant = case_tenant()
    ))?)?;
    let size = sizes[0].as_u64().unwrap();
    let existing = sizes[1].as_u64().unwrap();
    let count = (8_388_608 - existing) / size - 1;
    ensure!(count > 0 && size <= 2_097_152);
    let mut ids: Vec<_> = (0..count).map(|_| Uuid::new_v4()).collect();
    let values = ids
        .iter()
        .map(|id| {
            format!(
                "('{tenant}','{INSTANCE}','{id}',1,'{document}'::jsonb)",
                tenant = case_tenant()
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    pg(&format!(
        "INSERT INTO mdm_access.user_groups(tenant_id,instance,id,revision,document) VALUES {values}"
    ))?;
    ensure!(
        admin
            .call(router, Method::GET, "/api/v1/authorization", None)
            .await?
            .0
            == StatusCode::OK
    );
    let last = Uuid::new_v4();
    ensure!(
        put(
            admin,
            router,
            &format!("/api/v1/authorization/user-groups/{last}"),
            Uuid::new_v4(),
            0,
            large.clone()
        )
        .await?
        .0 == StatusCode::OK
    );
    ids.push(last);
    let over = Uuid::new_v4();
    let operation = Uuid::new_v4();
    let rejected = put(
        admin,
        router,
        &format!("/api/v1/authorization/user-groups/{over}"),
        operation,
        0,
        large,
    )
    .await?;
    ensure!(rejected.0 == StatusCode::CONFLICT && rejected.1["code"] == "operation_conflict");
    no_write(over, operation, "user_groups")?;
    let oversized = Uuid::new_v4();
    pg(&format!(
        "INSERT INTO mdm_access.user_groups SELECT tenant_id,instance,'{oversized}',1,document FROM mdm_access.user_groups WHERE tenant_id='{}' AND instance='{INSTANCE}' AND id='{}'",
        case_tenant(),
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
            "DELETE FROM mdm_access.user_groups WHERE tenant_id='{TENANT}' AND id='{id}'",
            TENANT = case_tenant()
        ))?;
    }
    // The database independently rejects a single over-size document, even if application checks are bypassed.
    pg(&format!(
        "DO $$ BEGIN BEGIN INSERT INTO mdm_access.user_groups VALUES('{TENANT}','{INSTANCE}','{oversized}',1,jsonb_build_object('oversized',repeat('x',2097152))); EXCEPTION WHEN check_violation THEN RETURN; END; RAISE EXCEPTION 'document limit absent'; END $$",
        TENANT = case_tenant()
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

    Ok(())
}

#[tokio::test]
#[ignore = "MODULE=authorization.capacity: real authorization contract"]
async fn sql_capacity_membership_pagination_and_atomicity() -> Result<()> {
    let Fixture {
        resources,
        router,
        mut admin,
        mut member,
        ..
    } = fixture().await?;
    resources
        .finish(async {
            verify(&router, &mut admin, &mut member).await?;
            Ok(())
        })
        .await
}
