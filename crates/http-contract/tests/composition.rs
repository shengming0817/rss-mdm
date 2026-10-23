use rss_mdm_http_contract::{
    Operation, Router, Violation, catalog::RESOURCE, routing::get, validate,
};
#[test]
fn mount_propagates_and_missing_list_or_get_cannot_disappear() {
    let routes = Router::<()>::new()
        .route(
            "/resources",
            get(|| async {}).owned(&RESOURCE, &[Operation::List]),
        )
        .route(
            "/resources/{id}",
            get(|| async {})
                .owned(&RESOURCE, &[Operation::Get])
                .post(|| async {})
                .owned(
                    &RESOURCE,
                    &[Operation::Create, Operation::Update, Operation::Lifecycle],
                ),
        );
    let mounted = Router::new().nest("/api/v1", routes);
    assert!(validate(mounted.endpoints(), &[&RESOURCE], &[]).is_empty());
    assert_eq!(mounted.endpoints()[0].path, "/api/v1/resources");
    for missing in [Operation::List, Operation::Get] {
        let endpoints = mounted
            .endpoints()
            .iter()
            .filter(|e| !e.operations.contains(&missing))
            .cloned()
            .collect::<Vec<_>>();
        assert!(
            validate(&endpoints, &[&RESOURCE], &[])
                .contains(&Violation::Missing("resource".into(), missing))
        );
    }
    assert!(validate(&[], &[&RESOURCE], &[]).contains(&Violation::Orphan("resource".into())));
}
#[test]
fn duplicate_unexpected_and_stale_exemptions_are_rejected() {
    let routes = Router::<()>::new().route(
        "/resources",
        get(|| async {}).owned(&RESOURCE, &[Operation::List]),
    );
    let mut endpoints = routes.endpoints().to_vec();
    endpoints.extend_from_slice(routes.endpoints());
    assert!(
        validate(&endpoints, &[&RESOURCE], &[])
            .iter()
            .any(|v| matches!(v, Violation::Duplicate(..)))
    );
    assert!(
        validate(routes.endpoints(), &[], &[])
            .iter()
            .any(|v| matches!(v, Violation::Unknown(..)))
    );
    let gaps = [rss_mdm_http_contract::Gap {
        resource: "resource",
        operation: Operation::List,
        issue: 2900,
        reason: "synthetic",
    }];
    assert!(
        validate(routes.endpoints(), &[&RESOURCE], &gaps)
            .iter()
            .any(|v| matches!(v, Violation::StaleGap(..)))
    );
}
