use crate::test_support::planning_http::*;
use crate::test_support::*;
#[tokio::test]
#[ignore = "make t2 MODULE=authorization.rules"]
async fn each_route_requires_its_exact_capability() -> Result<()> {
    let fixture = authority::Authority::open().await?;
    let server = publication_support::Server::new().await;
    let cfg = publication_http::configuration(&fixture.base, &server);
    let base = &cfg;
    let reader = authority::reader(base).await?;
    let session = &fixture.browser("other")?;
    let id = uuid::Uuid::new_v4();
    let source = base["flow"]["publication"]["sources"][0]["name"]
        .as_str()
        .unwrap();
    let release = format!("/api/v1/software-sources/{source}/candidates/{id}");
    let op = |input: Value| {
        Some(json!({"operationId":uuid::Uuid::new_v4(),"expectedRevision":999,"input":input}))
    };
    let mut cases = vec![
        (
            "group_read",
            Method::GET,
            format!("/api/v2/groups/{id}"),
            None,
        ),
        (
            "group_write",
            Method::POST,
            format!("/api/v2/groups/{id}"),
            op(json!({"action":"edit","name":"denied","description":""})),
        ),
        (
            "group_recompute",
            Method::POST,
            format!("/api/v2/groups/{id}"),
            op(json!({"action":"recompute"})),
        ),
        (
            "scope_read",
            Method::GET,
            format!("/api/v2/scopes/{id}"),
            None,
        ),
        (
            "scope_write",
            Method::POST,
            format!("/api/v2/scopes/{id}"),
            op(json!({"action":"delete"})),
        ),
        (
            "policy_read",
            Method::GET,
            format!("/api/v2/policies/{id}"),
            None,
        ),
        (
            "policy_write",
            Method::POST,
            format!("/api/v2/policies/{id}"),
            op(json!({"action":"disable"})),
        ),
        (
            "resource_read",
            Method::GET,
            format!("/api/v3/resources/{id}"),
            None,
        ),
        (
            "resource_write",
            Method::POST,
            format!("/api/v3/resources/{id}"),
            op(json!({"action":"activate","version":"missing"})),
        ),
        ("release_read", Method::GET, release.clone(), None),
        (
            "release_write",
            Method::POST,
            release.clone(),
            Some(
                json!({"operationId":uuid::Uuid::new_v4(),"expectedRevision":0,"input":{"action":"candidate","resource":"missing","version":"v1","expectedResourceRevision":1,"submission":{"kind":"Winget","manifest":{}}}}),
            ),
        ),
        (
            "release_validate",
            Method::POST,
            release.clone(),
            op(json!({"action":"validate","ring":"test"})),
        ),
        (
            "release_approve",
            Method::POST,
            release.clone(),
            op(json!({"action":"approve","ring":"test","publisherSubject":ADMIN})),
        ),
        (
            "release_publish",
            Method::POST,
            release.clone(),
            op(json!({"action":"authorize","ring":"test"})),
        ),
        (
            "release_withdraw",
            Method::POST,
            release.clone(),
            op(json!({"action":"withdraw","ring":"test"})),
        ),
        (
            "release_recover",
            Method::POST,
            release,
            op(json!({"action":"retry","ring":"test","attempt":1})),
        ),
    ];
    cases.extend([
        (
            "group_read",
            Method::POST,
            format!("/api/v2/groups/{id}/previews"),
            op(json!({})),
        ),
        (
            "release_publish",
            Method::POST,
            format!("/api/v1/software-sources/{source}/candidates/{id}"),
            op(json!({"action":"publish","ring":"test","publication":vec![0;32],"attempt":1})),
        ),
        (
            "release_recover",
            Method::POST,
            format!("/api/v1/software-sources/{source}/candidates/{id}"),
            op(json!({"action":"recover","ring":"test","publication":vec![0;32],"attempt":1})),
        ),
    ]);
    let grants = cases
        .iter()
        .map(|c| c.0)
        .collect::<std::collections::BTreeSet<_>>();
    let expected_denied = cases.len() * (grants.len() - 1);
    let counts = || {
        pg(
            "SELECT jsonb_build_array((SELECT count(*) FROM mdm_group.groups),(SELECT count(*) FROM mdm_planning.operations)+(SELECT count(*) FROM mdm_assets.operations)+(SELECT count(*) FROM mdm_resource_catalog.operations)+(SELECT count(*) FROM mdm_publication.operations),(SELECT count(*) FROM mdm_planning.scope_versions),(SELECT count(*) FROM mdm_automation.automation_jobs),(SELECT count(*) FROM mdm_policy.policies),(SELECT count(*) FROM mdm_software_composition.subjects))::text",
        )
    };
    // Exercise every permission change against the same running service. Rebuilding
    // full applications per grant needlessly multiplies component connection pools.
    let router = app(base, reader.clone()).await?;
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
    for grant in &grants {
        set_management_grants(&member, json!([grant])).await?;
        set_management_grants(ADMIN, json!(["release_publish"])).await?;
        let before = counts()?;
        for (needed, method, path, body) in &cases {
            if grant == needed {
                continue;
            }
            let (status, _) = browser
                .call(&router, method.clone(), path, body.clone())
                .await?;
            ensure!(
                status == StatusCode::FORBIDDEN,
                "grant {grant} allowed {needed}: {status}"
            );
        }
        ensure!(
            before == counts()?,
            "denied capability mutated product state"
        );
        for (_, method, path, body) in cases.iter().filter(|c| c.0 == *grant) {
            let (status, result) = browser
                .call(&router, method.clone(), path, body.clone())
                .await?;
            ensure!(
                matches!(
                    status,
                    StatusCode::NOT_FOUND | StatusCode::CONFLICT | StatusCode::BAD_REQUEST
                ),
                "grant {grant} failed to reach domain validation: {status} {result}"
            );
            if *method == Method::GET {
                let code = match *grant {
                    "group_read" => "group_not_found",
                    "scope_read" => "scope_not_found",
                    "policy_read" => "policy_not_found",
                    "resource_read" => "resource_not_found",
                    "release_read" => "software_candidate_not_found",
                    _ => unreachable!(),
                };
                ensure!(
                    status == StatusCode::NOT_FOUND && result["code"] == code,
                    "wrong missing-object contract: {result}"
                );
            }
        }
    }
    ensure!(
        audit_count(|r| r.target() == id.to_string()
            && r.result() == "denied"
            && matches!(r.action(), "management_read" | "management_write")
            && r.actor().is_some()
            && r.payload["instance"] == INSTANCE)?
        .to_string()
            == expected_denied.to_string(),
        "denied action/target/actor audit incomplete"
    );
    reader.close().await;
    Ok(())
}
