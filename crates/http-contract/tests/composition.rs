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

#[test]
fn native_listener_cannot_drop_a_registered_subtree() {
    use rss_mdm_http_contract::catalog::{
        APPLE_LISTENER, DOWNLOAD_APPLE_CHANNEL, PROTOCOL_APPLE_CHANNEL,
    };
    let protocol = Router::<()>::new().route(
        "/mdm",
        rss_mdm_http_contract::routing::put(|| async {})
            .owned(&PROTOCOL_APPLE_CHANNEL, &[Operation::Action]),
    );
    let download = Router::<()>::new().route(
        "/assets/{id}",
        get(|| async {}).owned(&DOWNLOAD_APPLE_CHANNEL, &[Operation::Action]),
    );
    assert!(
        validate(protocol.endpoints(), APPLE_LISTENER, &[])
            .contains(&Violation::Orphan("download_apple_channel".into()))
    );
    let mounted = protocol.merge(download);
    assert!(validate(mounted.endpoints(), APPLE_LISTENER, &[]).is_empty());
    let _ = mounted.into_checked_axum(APPLE_LISTENER);
}

#[test]
fn changing_migration_status_cannot_replace_missing_query_description() {
    use rss_mdm_http_contract::{QueryPolicy, collections};
    let mut departments = rss_mdm_http_contract::catalog::AUTHORIZATION_DEPARTMENTS;
    assert!(collections::valid(&departments, &[]));
    departments.query = QueryPolicy::FixedWindow;
    assert!(
        !collections::valid(&departments, &[]),
        "unbounded snapshot was relabeled as a bounded window"
    );
    departments.collection = None;
    assert!(
        !collections::valid(&departments, &[]),
        "window has no budget/order/fields"
    );
    let mut resource = RESOURCE;
    resource.id = "new-resource";
    assert!(
        !collections::valid(&resource, &[]),
        "another resource borrowed the Resource field contract"
    );
}
