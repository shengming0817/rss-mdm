use crate::audit_test_support::audit_count;
use crate::test_support::planning_http::*;
use crate::test_support::{http::*, process::*, runtime::*, *};
#[tokio::test]
#[ignore = "make t2 MODULE=authorization.rules"]
async fn each_route_requires_its_exact_capability() -> Result<()> {
    let mut fixture = authority::Authority::open().await?;
    let fixture_resources = std::mem::take(&mut fixture.resources);
    fixture_resources.finish(async {
    let server = publication_support::Server::new().await;
    let cfg = publication_http::configuration(&fixture.base, &server);
    let base = &cfg;

    let session = &fixture.browser("other")?;
    let id = uuid::Uuid::new_v4();
    let source = base["flow"]["publication"]["sources"][0]["name"]
        .as_str()
        .unwrap();
    let release = format!("/api/v1/software/publications/{id}");
    let op = |input: Value| {
        Some(json!({"operationId":uuid::Uuid::new_v4(),"expectedRevision":999,"input":input}))
    };
    let mut cases = vec![
        (
            "group_read",
            Method::GET,
            format!("/api/v1/groups/{id}"),
            None,
        ),
        (
            "group_write",
            Method::POST,
            format!("/api/v1/groups/{id}"),
            op(json!({"action":"edit","presentation":{"name":"denied","description":""}})),
        ),
        (
            "group_recompute",
            Method::POST,
            format!("/api/v1/groups/{id}"),
            op(json!({"action":"recompute"})),
        ),
        (
            "scope_read",
            Method::GET,
            format!("/api/v1/scopes/{id}"),
            None,
        ),
        (
            "scope_write",
            Method::POST,
            format!("/api/v1/scopes/{id}"),
            op(json!({"action":"delete"})),
        ),
        (
            "policy_read",
            Method::GET,
            format!("/api/v1/policies/{id}"),
            None,
        ),
        (
            "policy_write",
            Method::POST,
            format!("/api/v1/policies/{id}"),
            op(json!({"action":"disable"})),
        ),
        (
            "resource_read",
            Method::GET,
            format!("/api/v1/resources/{id}"),
            None,
        ),
        (
            "resource_write",
            Method::POST,
            format!("/api/v1/resources/{id}"),
            op(json!({"action":"activate","version":"missing"})),
        ),
        ("release_read", Method::GET, release.clone(), None),
        ("release_publish",Method::POST,"/api/v1/software/publications".into(),Some(json!({"operationId":id,"expectedRevision":0,"input":{"action":"publish","resource":"missing","version":"v1","expectedResourceRevision":1,"resourceDigest":vec![1;32],"target":source,"targetDigest":vec![2;32]}}))),
        (
            "release_withdraw",
            Method::POST,
            release.clone(),
            op(json!({"action":"withdraw"})),
        ),
        (
            "release_recover",
            Method::POST,
            release,
            op(json!({"action":"retry"})),
        ),
    ];
    cases.extend([
        (
            "group_read",
            Method::POST,
            format!("/api/v1/groups/{id}/previews"),
            op(json!({})),
        ),
        (
            "release_recover",
            Method::POST,
            format!("/api/v1/software/publications/{id}"),
            op(json!({"action":"recover"})),
        ),
    ]);
    let expected_denied = cases.len();
    let counts = || {
        pg(&format!(
            "SELECT jsonb_build_array((SELECT count(*) FROM mdm_group.groups WHERE tenant_id='{tenant}'),(SELECT count(*) FROM mdm_planning.operations WHERE tenant_id='{tenant}')+(SELECT count(*) FROM mdm_assets.operations WHERE tenant_id='{tenant}')+(SELECT count(*) FROM mdm_resource_catalog.operations WHERE tenant_id='{tenant}')+(SELECT count(*) FROM mdm_publication.operations WHERE tenant_id='{tenant}'),(SELECT count(*) FROM mdm_planning.scope_versions WHERE tenant_id='{tenant}'),(SELECT count(*) FROM mdm_automation.automation_jobs WHERE tenant_id='{tenant}'),(SELECT count(*) FROM mdm_policy.policies WHERE tenant_id='{tenant}'),(SELECT count(*) FROM mdm_software_composition.subjects WHERE tenant_id='{tenant}'))::text",
            tenant = case_tenant()
        ))
    };
    // Exercise every permission change against the same running service. Rebuilding
    // full applications per grant needlessly multiplies component connection pools.
    let (router, app_resources) = app(base).await?;
    app_resources.finish(async {
    let member = browser_subject(session, &router).await?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let hosted = router.clone();
    let _server = Server(tokio::spawn(
        async move { axum::serve(listener, hosted).await },
    ));
    let mut browser = Browser {
        network: Some((
            Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            format!("http://{address}"),
        )),
        ..session.clone()
    };
    for (needed, method, path, body) in &cases {
        let wrong = match *needed {
            "group_read" => "group_write",
            "group_write" | "group_recompute" => "group_read",
            "scope_read" => "scope_write",
            "scope_write" => "scope_read",
            "policy_read" => "policy_write",
            "policy_write" => "policy_read",
            "resource_read" => "resource_write",
            "resource_write" => "resource_read",
            "release_read" => "release_publish",
            "release_publish" | "release_withdraw" | "release_recover" => "release_read",
            _ => unreachable!(),
        };
        seed_management_grants(&member, json!([wrong])).await?;
        let before = counts()?;
        let denied = browser.call(&router, method.clone(), path, body.clone()).await?;
        ensure!(denied.0 == StatusCode::FORBIDDEN && denied.1["code"] == "permission_denied", "{wrong} allowed {needed}: {denied:?}");
        ensure!(before == counts()?, "denied capability mutated product state");
        change_management_grants(&member, json!([needed])).await?;
        let accepted = browser.call(&router, method.clone(), path, body.clone()).await?;
        let (status, code) = match (*needed, method == Method::GET) {
            ("group_read" | "group_recompute", _) => (StatusCode::NOT_FOUND, "group_not_found"),
            ("scope_read" | "scope_write", _) => (StatusCode::NOT_FOUND, "scope_not_found"),
            ("policy_read", _) => (StatusCode::NOT_FOUND, "policy_not_found"),
            ("resource_read", _) => (StatusCode::NOT_FOUND, "resource_not_found"),
            ("release_read" | "release_withdraw" | "release_recover", _) => (StatusCode::NOT_FOUND, "software_publication_not_found"),
            _ => (StatusCode::CONFLICT, "operation_conflict"),
        };
        ensure!(accepted.0 == status && accepted.1["code"] == code, "{needed} wrong domain result: {accepted:?}");
    }
    ensure!(
        audit_count(|r| r.target() == id.to_string()
            && r.result() == "denied"
            && matches!(r.action(), "management_read" | "management_write")
            && r.actor().is_some()
            && r.payload["instance"] == INSTANCE).await?
        .to_string()
            == expected_denied.to_string(),
        "denied action/target/actor audit incomplete"
    );

    Ok(())
    }).await

    }).await
}
