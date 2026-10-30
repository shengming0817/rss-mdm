use crate::{Error, authorization::context::RequestAuth};
use axum::{
    Extension, Json,
    extract::{Path, State},
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use rss_mdm_http_contract::{
    Router,
    routing::{get, post},
};
use rss_mdm_webhook_service::management::{Command, Reply, Service, response::*};
use rss_mdm_webhook_service::storage::Mutation;
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;
pub fn routes(
    source: Arc<Service>,
) -> Router<(), impl rss_mdm_http_contract::module::Declaration + use<>> {
    register().with_state(source)
}
pub(crate) fn register()
-> Router<Arc<Service>, impl rss_mdm_http_contract::module::Declaration + use<>> {
    {
        rss_mdm_http_contract::route_module! { struct RegisterModule1 for [Browser] { get_materials, post_prepare_material, post_transition_material, get_material_operation, get_health, get_types, get_subscriptions, get_subscription, put_change, post_test, get_deliveries, get_delivery, post_replay, post_redrive } }
        RegisterModule1 {
            get_materials: rss_mdm_http_contract::module::Route::new(
                "/webhooks/materials",
                rss_mdm_http_contract::routing::get(
                    materials,
                    &contracts::WEBHOOK_MATERIALS,
                    &[RouteOperation::Get],
                ),
            ),
            post_prepare_material: rss_mdm_http_contract::module::Route::new(
                "/webhooks/materials",
                rss_mdm_http_contract::routing::post(
                    prepare_material,
                    &contracts::WEBHOOK_MATERIALS,
                    &[RouteOperation::Update],
                ),
            ),
            post_transition_material: rss_mdm_http_contract::module::Route::new(
                "/webhooks/materials/transitions",
                post(
                    transition_material,
                    &contracts::WEBHOOK_MATERIALS,
                    &[RouteOperation::Update],
                ),
            ),
            get_material_operation: rss_mdm_http_contract::module::Route::new(
                "/webhooks/materials/operations/{id}",
                get(
                    material_operation,
                    &contracts::WEBHOOK_MATERIALS,
                    &[RouteOperation::Get],
                ),
            ),
            get_health: rss_mdm_http_contract::module::Route::new(
                "/webhooks/health",
                get(health, &contracts::WEBHOOK_HEALTH, &[RouteOperation::Get]),
            ),
            get_types: rss_mdm_http_contract::module::Route::new(
                "/webhooks/event-types",
                get(types, &contracts::WEBHOOK_TYPES, &[RouteOperation::List]),
            ),
            get_subscriptions: rss_mdm_http_contract::module::Route::new(
                "/webhooks/subscriptions",
                get(
                    subscriptions,
                    &contracts::WEBHOOK_SUBSCRIPTIONS,
                    &[RouteOperation::List],
                ),
            ),
            get_subscription: rss_mdm_http_contract::module::Route::new(
                "/webhooks/subscriptions/{id}",
                rss_mdm_http_contract::routing::get(
                    subscription,
                    &contracts::WEBHOOK_SUBSCRIPTIONS,
                    &[RouteOperation::Get],
                ),
            ),
            put_change: rss_mdm_http_contract::module::Route::new(
                "/webhooks/subscriptions/{id}",
                rss_mdm_http_contract::routing::put(
                    change,
                    &contracts::WEBHOOK_SUBSCRIPTIONS,
                    &[
                        RouteOperation::Create,
                        RouteOperation::Update,
                        RouteOperation::Delete,
                    ],
                ),
            ),
            post_test: rss_mdm_http_contract::module::Route::new(
                "/webhooks/subscriptions/{id}/test",
                post(
                    test,
                    &contracts::WEBHOOK_SUBSCRIPTIONS,
                    &[RouteOperation::Action, RouteOperation::Create],
                ),
            ),
            get_deliveries: rss_mdm_http_contract::module::Route::new(
                "/webhooks/deliveries",
                get(
                    deliveries,
                    &contracts::WEBHOOK_DELIVERIES,
                    &[RouteOperation::List],
                ),
            ),
            get_delivery: rss_mdm_http_contract::module::Route::new(
                "/webhooks/deliveries/{id}",
                get(
                    delivery,
                    &contracts::WEBHOOK_DELIVERIES,
                    &[RouteOperation::Get],
                ),
            ),
            post_replay: rss_mdm_http_contract::module::Route::new(
                "/webhooks/deliveries/{id}/replay",
                post(
                    replay,
                    &contracts::WEBHOOK_DELIVERIES,
                    &[RouteOperation::Action, RouteOperation::Lifecycle],
                ),
            ),
            post_redrive: rss_mdm_http_contract::module::Route::new(
                "/webhooks/deliveries/{id}/redrive",
                post(
                    redrive,
                    &contracts::WEBHOOK_DELIVERIES,
                    &[RouteOperation::Action, RouteOperation::Lifecycle],
                ),
            ),
        }
        .assemble()
    }
}
type Response = Result<Reply, Error>;
#[derive(schemars::JsonSchema, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Test {
    operation_id: Uuid,
    device_id: String,
}
#[derive(schemars::JsonSchema, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Replay {
    operation_id: Uuid,
}
#[derive(schemars::JsonSchema, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Redrive {
    operation_id: Uuid,
    expected_version: u64,
}
async fn call(s: Arc<Service>, a: RequestAuth, audit: RequestAudit, c: Command) -> Response {
    s.execute(a.proof, audit, c).await.map_err(Error::from)
}

async fn materials(
    State(s): State<Arc<Service>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
) -> Result<Json<rss_mdm_webhook_service::materials::PublicDirectory>, Error> {
    call(s, a, audit, Command::Materials)
        .await
        .and_then(|reply| reply.materials().map_err(Error::from))
        .map(Json)
}
async fn material_operation(
    State(s): State<Arc<Service>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    path: Result<Path<Uuid>, axum::extract::rejection::PathRejection>,
) -> Result<Json<MaterialOperation>, Error> {
    call(
        s,
        a,
        audit,
        Command::MaterialOperation(path.map_err(|_| Error::Malformed)?.0),
    )
    .await
    .and_then(|reply| reply.material_operation().map_err(Error::from))
    .map(Json)
}
async fn prepare_material(
    State(s): State<Arc<Service>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    headers: crate::api::WriteHeaders,
    body: Result<
        Json<rss_mdm_webhook_service::materials::Prepare>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Result<Json<rss_mdm_webhook_service::materials::Material>, Error> {
    call(
        s,
        a,
        audit,
        Command::PrepareMaterial(
            headers.operation_key()?,
            body.map_err(|_| Error::Malformed)?.0,
        ),
    )
    .await
    .and_then(|reply| reply.material().map_err(Error::from))
    .map(Json)
}
async fn transition_material(
    State(s): State<Arc<Service>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    headers: crate::api::WriteHeaders,
    body: Result<
        Json<rss_mdm_webhook_service::materials::Transition>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Result<Json<rss_mdm_webhook_service::materials::Receipt>, Error> {
    call(
        s,
        a,
        audit,
        Command::TransitionMaterial(
            headers.operation_key()?,
            body.map_err(|_| Error::Malformed)?.0,
        ),
    )
    .await
    .and_then(|reply| reply.material_receipt().map_err(Error::from))
    .map(Json)
}
async fn types(
    State(s): State<Arc<Service>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
) -> Result<rss_mdm_http_contract::CollectionResponse<Json<EventTypes>>, Error> {
    (async {
        call(s, a, audit, Command::Types)
            .await
            .and_then(|reply| reply.types().map_err(Error::from))
            .map(Json)
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}
async fn subscriptions(
    State(s): State<Arc<Service>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    q: rss_mdm_http_contract::query::OwnedQuery<SubscriptionsQuery>,
) -> Result<rss_mdm_http_contract::CollectionResponse<Json<Subscriptions>>, Error> {
    (async {
        call(
            s,
            a,
            audit,
            Command::Subscriptions(q.parse().unwrap_or_else(|never| match never {})),
        )
        .await
        .and_then(|reply| reply.subscriptions().map_err(Error::from))
        .map(Json)
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}
async fn subscription(
    State(s): State<Arc<Service>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
) -> Result<Json<rss_mdm_webhook_service::model::Subscription>, Error> {
    call(s, a, audit, Command::Subscription(id))
        .await
        .and_then(|reply| reply.subscription().map_err(Error::from))
        .map(Json)
}
async fn change(
    State(s): State<Arc<Service>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    body: Result<Json<Mutation>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<rss_mdm_webhook_service::model::Subscription>, Error> {
    call(
        s,
        a,
        audit,
        Command::Change(id, body.map_err(Error::from)?.0),
    )
    .await
    .and_then(|reply| reply.subscription().map_err(Error::from))
    .map(Json)
}
async fn test(
    State(s): State<Arc<Service>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    body: Result<Json<Test>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<DeliveryReceipt>, Error> {
    let v = body.map_err(Error::from)?.0;
    call(
        s,
        a,
        audit,
        Command::Test {
            subscription: id,
            operation: v.operation_id,
            device: v.device_id,
        },
    )
    .await
    .and_then(|reply| reply.delivery_receipt().map_err(Error::from))
    .map(Json)
}
async fn deliveries(
    State(s): State<Arc<Service>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    q: rss_mdm_http_contract::query::OwnedQuery<DeliveriesQuery>,
) -> Result<rss_mdm_http_contract::CollectionResponse<Json<Deliveries>>, Error> {
    (async {
        call(
            s,
            a,
            audit,
            Command::Deliveries(q.parse().unwrap_or_else(|never| match never {})),
        )
        .await
        .and_then(|reply| reply.deliveries().map_err(Error::from))
        .map(Json)
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}
async fn delivery(
    State(s): State<Arc<Service>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
) -> Result<Json<Deliveries>, Error> {
    call(s, a, audit, Command::Delivery(id))
        .await
        .and_then(|reply| reply.deliveries().map_err(Error::from))
        .map(Json)
}
async fn replay(
    State(s): State<Arc<Service>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    body: Result<Json<Replay>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<ReplayReceipt>, Error> {
    call(
        s,
        a,
        audit,
        Command::Replay {
            delivery: id,
            operation: body.map_err(Error::from)?.operation_id,
        },
    )
    .await
    .and_then(|reply| reply.replay().map_err(Error::from))
    .map(Json)
}
async fn redrive(
    State(s): State<Arc<Service>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    body: Result<Json<Redrive>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<RedriveReceipt>, Error> {
    let v = body.map_err(Error::from)?.0;
    call(
        s,
        a,
        audit,
        Command::Redrive {
            delivery: id,
            operation: v.operation_id,
            version: v.expected_version,
        },
    )
    .await
    .and_then(|reply| reply.redrive().map_err(Error::from))
    .map(Json)
}

async fn health(
    State(s): State<Arc<Service>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
) -> Result<Json<Health>, Error> {
    call(s, a, audit, Command::Health)
        .await
        .and_then(|reply| reply.health().map_err(Error::from))
        .map(Json)
}

struct SubscriptionsQuery;
impl rss_mdm_http_contract::query::QueryOwner for SubscriptionsQuery {
    type Parsed = rss_mdm_webhook_service::directory::SubscriptionInput;
    type Error = std::convert::Infallible;
    fn declaration() -> Option<rss_mdm_http_contract::QueryDeclaration> {
        Some(rss_mdm_http_contract::QueryDeclaration::Directory(
            Self::Parsed::schema(),
        ))
    }
    fn parameters() -> rss_mdm_http_contract::signature::Schema {
        let schema = Self::Parsed::schema();
        rss_mdm_http_contract::query::directory_parameters(schema.default_limit, schema.max_limit)
    }
    fn parse(raw: &str) -> Result<Self::Parsed, Self::Error> {
        Ok(Self::Parsed::capture(raw))
    }
}

struct DeliveriesQuery;
impl rss_mdm_http_contract::query::QueryOwner for DeliveriesQuery {
    type Parsed = rss_mdm_webhook_service::directory::DeliveryInput;
    type Error = std::convert::Infallible;
    fn declaration() -> Option<rss_mdm_http_contract::QueryDeclaration> {
        Some(rss_mdm_http_contract::QueryDeclaration::Directory(
            Self::Parsed::schema(),
        ))
    }
    fn parameters() -> rss_mdm_http_contract::signature::Schema {
        let schema = Self::Parsed::schema();
        rss_mdm_http_contract::query::directory_parameters(schema.default_limit, schema.max_limit)
    }
    fn parse(raw: &str) -> Result<Self::Parsed, Self::Error> {
        Ok(Self::Parsed::capture(raw))
    }
}
