use rss_mdm_http_contract::{Operation, Violation, catalog::RESOURCE, routing::get, validate};
#[test]
fn mount_propagates_and_missing_list_or_get_cannot_disappear() {
    let routes = {
        rss_mdm_http_contract::route_module! { struct MountPropagatesAndMissingListOrGetCannotDisappearModule1 for [Browser] { get_resources, get_resources_id, post_resources_id } }
        MountPropagatesAndMissingListOrGetCannotDisappearModule1 {
            get_resources: rss_mdm_http_contract::module::Route::new(
                "/resources",
                get(
                    || async { rss_mdm_http_contract::CollectionResponse(()) },
                    &RESOURCE,
                    &[Operation::List],
                ),
            ),
            get_resources_id: rss_mdm_http_contract::module::Route::new(
                "/resources/{id}",
                rss_mdm_http_contract::routing::get(|| async {}, &RESOURCE, &[Operation::Get]),
            ),
            post_resources_id: rss_mdm_http_contract::module::Route::new(
                "/resources/{id}",
                rss_mdm_http_contract::routing::post(
                    || async {},
                    &RESOURCE,
                    &[Operation::Create, Operation::Update, Operation::Lifecycle],
                ),
            ),
        }
        .assemble::<()>()
    };
    let mounted = {
        rss_mdm_http_contract::route_module! { struct MountPropagatesAndMissingListOrGetCannotDisappearModule2 for [Browser] { api_v1 at "/api/v1" } }
        MountPropagatesAndMissingListOrGetCannotDisappearModule2 { api_v1: routes }.assemble()
    };
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
    let routes = {
        rss_mdm_http_contract::route_module! { struct DuplicateAndUnexpectedResourcesAreRejectedModule1 for [Browser] { get_resources } }
        DuplicateAndUnexpectedResourcesAreRejectedModule1 {
            get_resources: rss_mdm_http_contract::module::Route::new(
                "/resources",
                get(
                    || async { rss_mdm_http_contract::CollectionResponse(()) },
                    &RESOURCE,
                    &[Operation::List],
                ),
            ),
        }
        .assemble::<()>()
    };
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
fn native_endpoints_are_distinct_and_cannot_enter_another_listener() {
    use rss_mdm_http_contract::{
        ExternalProtocol,
        catalog::PROTOCOL_APPLE_CHANNEL,
        module::{Listener, Route},
        routing::external_put,
    };
    rss_mdm_http_contract::route_module! { struct Apple for [Apple] { checkin, management } }
    let routes = Apple {
        checkin: Route::new(
            "/checkin",
            external_put(
                || async {},
                ExternalProtocol::AppleMdm,
                &PROTOCOL_APPLE_CHANNEL,
                &[Operation::Action],
            ),
        ),
        management: Route::new(
            "/mdm",
            external_put(
                || async {},
                ExternalProtocol::AppleMdm,
                &PROTOCOL_APPLE_CHANNEL,
                &[Operation::Action],
            ),
        ),
    }
    .assemble::<()>();
    assert!(routes.validate(Listener::Apple).is_empty());
    assert!(!routes.validate(Listener::WindowsEnrollment).is_empty());
    assert_eq!(
        routes
            .endpoints()
            .iter()
            .map(|e| e.path.as_str())
            .collect::<Vec<_>>(),
        ["/checkin", "/mdm"]
    );
    let _ = routes.into_checked_axum(Listener::Apple);
}

#[test]
fn unified_list_requires_an_execution_field_owner() {
    use rss_mdm_http_contract::catalog::SAVED_QUERIES;
    let routes = {
        rss_mdm_http_contract::route_module! { struct UnifiedListRequiresAnExecutionFieldOwnerModule1 for [Browser] { get_saved_queries } }
        UnifiedListRequiresAnExecutionFieldOwnerModule1 {
            get_saved_queries: rss_mdm_http_contract::module::Route::new(
                "/saved-queries",
                get(
                    || async { rss_mdm_http_contract::CollectionResponse(()) },
                    &SAVED_QUERIES,
                    &[Operation::List],
                ),
            ),
        }
        .assemble::<()>()
    };
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
    let routes = {
        rss_mdm_http_contract::route_module! { struct SchemaModule1 for [Browser] { get_saved_queries } }
        SchemaModule1 {
            get_saved_queries: rss_mdm_http_contract::module::Route::new(
                "/saved-queries",
                get(
                    |_: rss_mdm_http_contract::query::OwnedQuery<
                        rss_mdm_http_contract::query::Directory<Owner>,
                    >| async { rss_mdm_http_contract::CollectionResponse(()) },
                    &SAVED_QUERIES,
                    &[Operation::List],
                ),
            ),
        }
        .assemble::<()>()
    };
    assert!(
        !validate(routes.endpoints(), &[&SAVED_QUERIES])
            .contains(&Violation::MissingQuery("saved_queries".into()))
    );
}
