use rss_mdm_http_contract::{
    Operation, Router, Violation, catalog::RESOURCE, routing::get, validate,
};
#[test]
fn mount_propagates_and_missing_list_or_get_cannot_disappear() {
    let routes = Router::<()>::new()
        .route(
            "/resources",
            get(|| async { rss_mdm_http_contract::CollectionResponse(()) })
                .owned(&RESOURCE, &[Operation::List]),
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
    assert!(validate(mounted.endpoints(), &[&RESOURCE]).is_empty());
    assert_eq!(mounted.endpoints()[0].path, "/api/v1/resources");
    for missing in [Operation::List, Operation::Get] {
        let endpoints = mounted
            .endpoints()
            .iter()
            .filter(|e| !e.operations.contains(&missing))
            .cloned()
            .collect::<Vec<_>>();
        assert!(
            validate(&endpoints, &[&RESOURCE])
                .contains(&Violation::Missing("resource".into(), missing))
        );
    }
    assert!(validate(&[], &[&RESOURCE]).contains(&Violation::Orphan("resource".into())));
}
#[test]
fn duplicate_and_unexpected_resources_are_rejected() {
    let routes = Router::<()>::new().route(
        "/resources",
        get(|| async { rss_mdm_http_contract::CollectionResponse(()) })
            .owned(&RESOURCE, &[Operation::List]),
    );
    let mut endpoints = routes.endpoints().to_vec();
    endpoints.extend_from_slice(routes.endpoints());
    assert!(
        validate(&endpoints, &[&RESOURCE])
            .iter()
            .any(|v| matches!(v, Violation::Duplicate(..)))
    );
    assert!(
        validate(routes.endpoints(), &[])
            .iter()
            .any(|v| matches!(v, Violation::Unknown(..)))
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
        validate(protocol.endpoints(), APPLE_LISTENER)
            .contains(&Violation::Orphan("download_apple_channel".into()))
    );
    let mounted = protocol.merge(download);
    assert!(validate(mounted.endpoints(), APPLE_LISTENER).is_empty());
    let _ = mounted.into_checked_axum(APPLE_LISTENER);
}

#[test]
fn unified_list_requires_an_execution_field_owner() {
    use rss_mdm_http_contract::catalog::SAVED_QUERIES;
    let routes = Router::<()>::new().route(
        "/saved-queries",
        get(|| async { rss_mdm_http_contract::CollectionResponse(()) })
            .owned(&SAVED_QUERIES, &[Operation::List]),
    );
    assert!(
        validate(routes.endpoints(), &[&SAVED_QUERIES])
            .contains(&Violation::MissingQuery("saved_queries".into()))
    );
    static SCHEMA: rss_mdm_query::directory::Schema = rss_mdm_query::directory::Schema {
        id: "saved_queries",
        keys: &["id"],
        default_limit: 1,
        max_limit: 2,
        fields: &[rss_mdm_query::directory::Field::scalar(
            "id",
            rss_mdm_query::directory::Kind::Integer,
        )],
    };
    struct Owner;
    impl rss_mdm_http_contract::query::DirectoryOwner for Owner {
        fn schema() -> &'static rss_mdm_query::directory::Schema {
            &SCHEMA
        }
    }
    let routes = Router::<()>::new().route(
        "/saved-queries",
        get(
            |_: rss_mdm_http_contract::query::OwnedQuery<
                rss_mdm_http_contract::query::Directory<Owner>,
            >| async { rss_mdm_http_contract::CollectionResponse(()) },
        )
        .owned(&SAVED_QUERIES, &[Operation::List]),
    );
    assert!(
        !validate(routes.endpoints(), &[&SAVED_QUERIES])
            .contains(&Violation::MissingQuery("saved_queries".into()))
    );
}
