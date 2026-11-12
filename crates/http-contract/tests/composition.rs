struct ResourceOwner;
#[derive(schemars::JsonSchema, serde::Serialize)]
struct ResourceRow {
    #[schemars(length(max = 64))]
    id: String,
}
static RESOURCE_SCHEMA: std::sync::LazyLock<rss_mdm_query::directory::Schema> =
    std::sync::LazyLock::new(|| {
        rss_mdm_query::directory::Schema::derived::<ResourceRow>("resource", &["id"], 1, 2, &[])
            .unwrap()
    });
static RESOURCE_EXECUTION: std::sync::LazyLock<rss_mdm_query::directory::Execution> =
    std::sync::LazyLock::new(|| {
        rss_mdm_query::directory::Execution::bind(&RESOURCE_SCHEMA, ["id"]).unwrap()
    });
impl rss_mdm_http_contract::query::DirectoryOwner for ResourceOwner {
    fn execution() -> &'static rss_mdm_query::directory::Execution {
        &RESOURCE_EXECUTION
    }
}
fn resource_page() -> rss_mdm_http_contract::CollectionResponse<
    axum::Json<rss_mdm_query::Page<rss_mdm_query::directory::Projection<ResourceRow>>>,
> {
    rss_mdm_http_contract::CollectionResponse(axum::Json(rss_mdm_query::Page {
        items: vec![],
        next_cursor: None,
    }))
}
use rss_mdm_http_contract::{Operation, Violation, catalog::RESOURCE, routing::get, validate};
#[test]
fn mount_propagates_and_missing_list_or_get_cannot_disappear() {
    let routes = {
        rss_mdm_http_contract::route_module! { struct MountPropagatesAndMissingListOrGetCannotDisappearModule1 for [Browser] { get_resources, get_resources_id, post_resources_id } }
        MountPropagatesAndMissingListOrGetCannotDisappearModule1 {
            get_resources: rss_mdm_http_contract::module::Route::new(
                "/resources",
                get(
                    |_: rss_mdm_http_contract::query::OwnedQuery<
                        rss_mdm_http_contract::query::Directory<ResourceOwner>,
                    >| async { resource_page() },
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
                    |_: rss_mdm_http_contract::query::OwnedQuery<
                        rss_mdm_http_contract::query::Directory<ResourceOwner>,
                    >| async { resource_page() },
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
    #[derive(schemars::JsonSchema)]
    #[allow(dead_code)]
    struct Saved {
        id: i64,
    }
    static SCHEMA: std::sync::LazyLock<rss_mdm_query::directory::Schema> =
        std::sync::LazyLock::new(|| {
            rss_mdm_query::directory::Schema::derived::<Saved>("saved_queries", &["id"], 1, 2, &[])
                .unwrap()
        });
    static EXECUTION: std::sync::LazyLock<rss_mdm_query::directory::Execution> =
        std::sync::LazyLock::new(|| {
            rss_mdm_query::directory::Execution::bind(&SCHEMA, ["id"]).unwrap()
        });
    struct Owner;
    impl rss_mdm_http_contract::query::DirectoryOwner for Owner {
        fn execution() -> &'static rss_mdm_query::directory::Execution {
            &EXECUTION
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

#[test]
fn directory_requires_the_real_response_row_and_same_statistics_owner() {
    use rss_mdm_http_contract::{
        DirectoryDeclaration, EndpointContract, QueryDeclaration,
        signature::{Response, Schema},
    };
    rss_mdm_http_contract::route_module! { struct DirectoryProof for [Browser] { rows } }
    let routes = DirectoryProof {
        rows: rss_mdm_http_contract::module::Route::new(
            "/resources",
            get(
                |_: rss_mdm_http_contract::query::OwnedQuery<
                    rss_mdm_http_contract::query::Directory<ResourceOwner>,
                >| async { resource_page() },
                &RESOURCE,
                &[Operation::List],
            ),
        ),
    }
    .assemble::<()>();
    let baseline = routes.endpoints().to_vec();
    let invalid = |endpoints: &[rss_mdm_http_contract::Endpoint]| {
        validate(endpoints, &[&RESOURCE])
            .iter()
            .any(|v| matches!(v, Violation::InvalidDirectory(..)))
    };
    assert!(!invalid(&baseline));
    for response in [
        Schema::response::<rss_mdm_query::Page<ResourceRow>>(),
        Schema::response::<rss_mdm_query::Page<rss_mdm_query::directory::Projection<WrongRow>>>(),
    ] {
        let mut endpoints = baseline.clone();
        let EndpointContract::Product(signature) = &mut endpoints[0].contract else {
            panic!("product")
        };
        signature.responses[0].body.as_mut().unwrap().schema = response;
        assert!(invalid(&endpoints));
    }
    // A matching unused definition cannot conceal a different row at the actual items slot.
    let mut endpoints = baseline.clone();
    let EndpointContract::Product(signature) = &mut endpoints[0].contract else {
        panic!("product")
    };
    signature.responses[0].body.as_mut().unwrap().schema.value["properties"]["items"]["items"] =
        serde_json::json!({"type":"string"});
    assert!(invalid(&endpoints));
    let EndpointContract::Product(signature) = &mut endpoints[0].contract else {
        panic!("product")
    };
    let actual = Schema::response::<
        rss_mdm_query::Page<rss_mdm_query::directory::Projection<ResourceRow>>,
    >();
    // Retain the original model definitions while adding an unrelated matching collection.
    signature.responses[0].body.as_mut().unwrap().schema.value["properties"]["metadata"] = serde_json::json!({"type":"object","properties":{"items":actual.value["properties"]["items"].clone()}});
    assert!(invalid(&endpoints));
    let mut stats = baseline[0].clone();
    stats.path = "/statistics".into();
    stats.operation_id = "resource.statistics".into();
    let EndpointContract::Product(signature) = &mut stats.contract else {
        panic!("product")
    };
    signature.request.query_owner = Some(QueryDeclaration::Directory(
        DirectoryDeclaration::statistics(&RESOURCE_EXECUTION),
    ));
    signature.responses = vec![Response::json::<u64>(200)];
    let mut endpoints = baseline.clone();
    endpoints.push(stats.clone());
    assert!(!invalid(&endpoints));
    assert!(invalid(&[stats]));
}
#[derive(schemars::JsonSchema, serde::Serialize)]
struct WrongRow {
    id: i64,
    name: String,
}

#[test]
fn parsing_cannot_switch_directory_owner_and_statistics_keep_list_defaults() {
    use rss_mdm_http_contract::query::{Directory, DirectoryOwner, QueryOwner, Statistics};
    struct DefaultOwner;
    impl DirectoryOwner for DefaultOwner {
        fn execution() -> &'static rss_mdm_query::directory::Execution {
            &RESOURCE_EXECUTION
        }
        fn parse(raw: &str) -> rss_mdm_query::Result<rss_mdm_query::directory::Query> {
            let mut q = RESOURCE_SCHEMA.parse(raw)?;
            q.default_filter("id", "default")?;
            Ok(q)
        }
    }
    assert_eq!(
        Directory::<DefaultOwner>::parse("").unwrap().filter(),
        Statistics::<DefaultOwner>::parse("").unwrap().filter()
    );
    assert!(Statistics::<DefaultOwner>::parse("limit=1").is_err());
    static OTHER: std::sync::LazyLock<rss_mdm_query::directory::Schema> =
        std::sync::LazyLock::new(|| {
            rss_mdm_query::directory::Schema::derived::<ResourceRow>("other", &["id"], 1, 2, &[])
                .unwrap()
        });
    struct WrongOwner;
    impl DirectoryOwner for WrongOwner {
        fn execution() -> &'static rss_mdm_query::directory::Execution {
            &RESOURCE_EXECUTION
        }
        fn parse(raw: &str) -> rss_mdm_query::Result<rss_mdm_query::directory::Query> {
            OTHER.parse(raw)
        }
    }
    assert!(Directory::<WrongOwner>::parse("").is_err());
    assert!(Statistics::<WrongOwner>::parse("").is_err());
}
