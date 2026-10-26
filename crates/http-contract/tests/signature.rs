use axum::{
    Json,
    extract::{Path, State},
    response::IntoResponse,
};
use http_body_util::BodyExt;
use rss_mdm_http_contract::signature::{Direction, Schema, WithStatus, describe};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, JsonSchema)]
struct Document {
    custom_event: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    extension: Option<String>,
}

async fn echo(
    State(()): State<()>,
    Path(_): Path<String>,
    Json(body): Json<Document>,
) -> Json<Document> {
    Json(body)
}

#[test]
fn actual_function_distinguishes_input_absence_and_output_null() {
    let signature = describe::<_, _, ()>(&echo);
    let input = &signature.request.body.as_ref().unwrap().schema;
    let output = &signature
        .responses
        .iter()
        .find(|r| r.status == 200)
        .unwrap()
        .body
        .as_ref()
        .unwrap()
        .schema;
    assert_eq!(input.direction, Direction::Request);
    assert_eq!(output.direction, Direction::Response);
    assert!(
        !input.value["required"]
            .as_array()
            .is_some_and(|r| r.contains(&"custom_event".into()))
    );
    assert!(
        output.value["required"]
            .as_array()
            .unwrap()
            .contains(&"custom_event".into())
    );
    assert!(
        !output.value["required"]
            .as_array()
            .unwrap()
            .contains(&"extension".into())
    );
    assert_eq!(
        output.value["properties"]["custom_event"]["type"],
        serde_json::json!(["string", "null"])
    );
}

async fn missing_receipt() -> Json<Option<Document>> {
    Json(None)
}
#[tokio::test]
async fn nullable_json_is_a_200_body_not_an_absent_response() {
    let signature = describe::<_, _, ()>(&missing_receipt);
    let response = missing_receipt().await.into_response();
    assert_eq!(response.status().as_u16(), signature.responses[0].status);
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["content-type"], "application/json");
    assert_eq!(
        &response.into_body().collect().await.unwrap().to_bytes()[..],
        b"null"
    );
    assert!(
        signature.responses[0]
            .body
            .as_ref()
            .unwrap()
            .schema
            .value
            .to_string()
            .contains("null")
    );
}

async fn accepted() -> WithStatus<202, Json<Document>> {
    WithStatus(Json(Document {
        custom_event: None,
        extension: None,
    }))
}
#[tokio::test]
async fn status_is_shared_by_rendering_and_description() {
    let signature = describe::<_, _, ()>(&accepted);
    let response = accepted().await.into_response();
    assert_eq!(response.status(), 202);
    assert_eq!(response.status().as_u16(), signature.responses[0].status);
}

async fn mapped_rejection(
    _: Result<Json<Document>, axum::extract::rejection::JsonRejection>,
) -> () {
}
#[test]
fn caught_rejections_belong_to_handler_output() {
    let signature = describe::<_, _, ()>(&mapped_rejection);
    assert!(signature.request.rejections.is_empty());
    assert_eq!(signature.responses.len(), 1);
    assert_eq!(signature.responses[0].status, 200);
    assert!(
        describe::<_, _, ()>(&echo)
            .responses
            .iter()
            .any(|r| r.status == 422)
    );
}

#[test]
fn integer_schema_preserves_wire_range_instead_of_javascript_safe_integer_range() {
    let schema = Schema::response::<u64>();
    // Schemars represents the full width with format, not a floating-point maximum.
    assert_eq!(schema.value["format"], "uint64");
    assert_eq!(schema.value["minimum"], 0);
    assert_eq!(
        serde_json::to_string(&u64::MAX).unwrap(),
        "18446744073709551615"
    );
}

struct Window;
static WINDOW: rss_mdm_query::window::Schema = rss_mdm_query::window::Schema {
    id: "test",
    default_limit: 2,
    max_limit: 3,
    order: "id ASC",
    context: &[],
};
impl rss_mdm_http_contract::query::QueryOwner for Window {
    type Parsed = (
        rss_mdm_query::window::Query,
        std::collections::BTreeMap<String, String>,
    );
    type Error = rss_mdm_query::Error;
    fn declaration() -> Option<rss_mdm_http_contract::QueryDeclaration> {
        Some(rss_mdm_http_contract::QueryDeclaration::Window(&WINDOW))
    }
    fn parameters() -> Schema {
        Schema::request::<WindowParameters>()
    }
    fn parse(raw: &str) -> Result<Self::Parsed, Self::Error> {
        WINDOW.parse(raw)
    }
}
#[derive(JsonSchema)]
#[allow(dead_code, reason = "query shape for the owner's description")]
struct WindowParameters {
    limit: Option<u16>,
    cursor: Option<String>,
}

#[tokio::test]
async fn query_capture_preserves_deferred_owner_errors() {
    use axum::extract::FromRequestParts;
    use rss_mdm_http_contract::query::OwnedQuery;
    let request = http::Request::builder()
        .uri("/items?limit=4")
        .body(())
        .unwrap();
    let (mut parts, _) = request.into_parts();
    // Extraction succeeds; the handler can authorize and map the owner's parse failure.
    let query = OwnedQuery::<Window>::from_request_parts(&mut parts, &())
        .await
        .unwrap();
    assert!(query.parse().is_err());
    let request = http::Request::builder()
        .uri("/items?limit=3")
        .body(())
        .unwrap();
    let (mut parts, _) = request.into_parts();
    let query = OwnedQuery::<Window>::from_request_parts(&mut parts, &())
        .await
        .unwrap();
    let (query, _) = query.parse().unwrap();
    assert_eq!(query.limit(), 3);
    query.require_schema(&WINDOW).unwrap();
}

#[test]
fn unresolved_and_unbound_schemas_fail_but_explicit_extensions_remain_open() {
    use rss_mdm_http_contract::validation;
    assert!(!validation::schema(&Schema::response::<serde_json::Value>()).is_empty());
    let mut schema = Schema::response::<Document>();
    schema.value["properties"]["custom_event"] = serde_json::json!({"$ref":"#/$defs/Missing"});
    assert!(!validation::schema(&schema).is_empty());
    schema.value["properties"]["custom_event"] = serde_json::json!({"$dynamicRef":"#missing"});
    assert!(!validation::schema(&schema).is_empty());
    schema.value["properties"]["custom_event"] =
        serde_json::json!({"x-rss-extension":"test presentation metadata"});
    assert!(validation::schema(&schema).is_empty());
    schema.value["properties"]["custom_event"]["$ref"] = "#/$defs/Missing".into();
    assert!(!validation::schema(&schema).is_empty());
}

#[test]
fn mounted_path_must_match_the_real_extractor() {
    use rss_mdm_http_contract::validation;
    let signature = describe::<_, _, ()>(&echo);
    assert!(validation::signature(&signature, "/documents/{id}").is_empty());
    assert!(!validation::signature(&signature, "/documents").is_empty());
    assert!(!validation::signature(&signature, "/documents/{id}/{version}").is_empty());
}

#[test]
fn offline_mounting_never_constructs_state_or_becomes_a_serving_router() {
    use rss_mdm_http_contract::{Operation, Router, catalog, routing::get};
    fn routes() -> Router<()> {
        Router::new().route(
            "/{id}",
            get(echo).owned(&catalog::POLICIES, &[Operation::Get]),
        )
    }
    let offline: Router<()> =
        routes().bind_with(None::<&()>, |_| panic!("must not construct services"));
    let offline = Router::new().nest("/policies", offline);
    assert_eq!(offline.endpoints()[0].path, "/policies/{id}");
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| offline.into_axum())).is_err()
    );
    let live: Router<()> = routes().bind_with(Some(&()), |_| ());
    let _ = live.into_axum();
}

#[test]
fn artifact_uses_final_mounts_interns_schemas_and_preserves_empty_bodies() {
    use rss_mdm_http_contract::{Operation, Router, artifact, catalog, routing::get};
    let routes = Router::<()>::new()
        .route(
            "/first",
            get(missing_receipt).owned(&catalog::POLICIES, &[Operation::Get]),
        )
        .route(
            "/second",
            get(missing_receipt).owned(&catalog::POLICIES, &[Operation::Get]),
        )
        .route(
            "/empty",
            get(|| async {}).owned(&catalog::POLICIES, &[Operation::Get]),
        );
    let endpoints = Router::new().nest("/api", routes).into_endpoints();
    let document = artifact::document([("agent", endpoints.clone())]).unwrap();
    let endpoints = document["endpoints"].as_array().unwrap();
    let empty = endpoints
        .iter()
        .find(|e| e["path"] == "/api/empty")
        .unwrap();
    assert!(empty["request"]["body"].is_null());
    assert!(empty["responses"][0]["body"].is_null());
    assert_eq!(document["schemas"].as_object().unwrap().len(), 1);
    assert!(endpoints.iter().all(|e| {
        e["operationId"]
            .as_str()
            .unwrap()
            .starts_with("agent:GET:/api/")
    }));
    assert!(artifact::document([("agent", endpoints_from_duplicate())]).is_err());
    fn endpoints_from_duplicate() -> Vec<rss_mdm_http_contract::Endpoint> {
        let routes = Router::<()>::new().route(
            "/one",
            get(missing_receipt).owned(&catalog::POLICIES, &[Operation::Get]),
        );
        let mut endpoints = routes.into_endpoints();
        endpoints.push(endpoints[0].clone());
        endpoints
    }
}

#[tokio::test]
async fn binary_framing_preserves_range_status_headers_and_exact_bytes() {
    use rss_mdm_http_contract::download::Download;
    let response = Download::stream(axum::body::Body::from("abc"), "\"digest\"", 3, 6, 10, true)
        .unwrap()
        .into_response();
    assert_eq!(response.status(), 206);
    assert_eq!(response.headers()["content-range"], "bytes 3-5/10");
    assert_eq!(response.headers()["content-length"], "3");
    assert_eq!(response.headers()["cache-control"], "private, no-store");
    assert_eq!(
        &response.into_body().collect().await.unwrap().to_bytes()[..],
        b"abc"
    );
    let rejected = Download::unsatisfied(10).into_response();
    assert_eq!(rejected.status(), 416);
    assert_eq!(rejected.headers()["content-range"], "bytes */10");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(
            &rejected.into_body().collect().await.unwrap().to_bytes()
        )
        .unwrap(),
        serde_json::json!({"code":"range_not_satisfiable"})
    );
    assert!(Download::stream(axum::body::Body::empty(), "\"digest\"", 6, 3, 10, true).is_err());
}

#[test]
fn documented_enum_variants_are_still_a_closed_vocabulary() {
    #[derive(JsonSchema)]
    #[serde(rename_all = "snake_case")]
    #[allow(dead_code)]
    enum Code {
        /// First real code.
        First,
        /// Second real code.
        Second,
    }
    assert_eq!(
        Schema::response::<Code>().string_values(),
        vec![serde_json::json!("first"), serde_json::json!("second")]
    );
}

#[tokio::test]
async fn configured_static_path_keeps_runtime_precedence_without_exporting_a_fake_uuid() {
    use rss_mdm_http_contract::{ConfiguredSegment, Operation, Router, catalog, routing::get};
    use tower::ServiceExt;
    fn routes(value: Option<&str>) -> Router {
        Router::new()
            .route(
                "/tenants/{tenant}/context",
                get(|Path(_): Path<String>| async { "ordinary" })
                    .owned(&catalog::IDENTITY_CONTEXT, &[Operation::Get]),
            )
            .configured_route(
                "/tenants/{management_tenant}/context",
                ConfiguredSegment {
                    name: "management_tenant",
                    source: "installation.management_tenant",
                },
                value,
                get(|| async { "management" }).owned(&catalog::IDENTITY_CONTEXT, &[Operation::Get]),
            )
    }
    let id = "fb894f90-b569-4d4c-9bdb-20ad7f5ac677";
    let offline =
        rss_mdm_http_contract::artifact::document([("browser", routes(None).into_endpoints())])
            .unwrap();
    let live = routes(Some(id));
    let described =
        rss_mdm_http_contract::artifact::document([("browser", live.endpoints().to_vec())])
            .unwrap();
    assert_eq!(offline, described);
    assert!(!offline.to_string().contains(id));
    let special = offline["endpoints"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["configuredPath"].is_object())
        .unwrap();
    assert!(special["request"]["path"].is_null());
    assert_eq!(
        special["configuredPath"]["overrides"],
        "browser:GET:/tenants/{tenant}/context"
    );
    let app = live.into_axum();
    for (tenant, expected) in [(id, "management"), ("another-tenant", "ordinary")] {
        let response = app
            .clone()
            .oneshot(
                http::Request::builder()
                    .uri(format!("/tenants/{tenant}/context"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            expected
        );
    }
    assert!(std::panic::catch_unwind(|| routes(Some("not-a-uuid"))).is_err());
    assert!(std::panic::catch_unwind(|| routes(None).into_axum()).is_err());
}

#[tokio::test]
async fn response_header_layer_describes_and_applies_success_and_extractor_failure() {
    use rss_mdm_http_contract::{EndpointContract, Router, routing::post};
    use tower::ServiceExt;
    async fn body(Json(value): Json<Document>) -> Json<Document> {
        Json(value)
    }
    let router = Router::new()
        .route(
            "/header",
            post(body).owned(
                &rss_mdm_http_contract::catalog::POLICIES,
                &[rss_mdm_http_contract::Operation::Create],
            ),
        )
        .fixed_response_headers(&[
            ("cache-control", "no-store"),
            ("referrer-policy", "no-referrer"),
        ]);
    let EndpointContract::Product(signature) = &router.endpoints()[0].contract else {
        panic!("product route")
    };
    for response in &signature.responses {
        assert_eq!(response.headers["cache-control"].value["const"], "no-store");
        assert_eq!(
            response.headers["referrer-policy"].value["const"],
            "no-referrer"
        );
    }
    for (body, status) in [("{}", 200), ("{", 400)] {
        let response = router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/header")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), status);
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(response.headers()["referrer-policy"], "no-referrer");
    }
}
