use crate::{
    Error,
    authorization::context::{AuthorizedPrincipal, RequestAuth},
};
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
use rss_mdm_webhook_service::storage::Mutation;
use serde::Deserialize;
mod response;
pub use response::*;
use std::sync::Arc;
use uuid::Uuid;
#[derive(Clone, serde::Serialize)]
pub enum Command {
    Materials,
    MaterialOperation(Uuid),
    PrepareMaterial(Uuid, rss_mdm_webhook_service::materials::Prepare),
    TransitionMaterial(Uuid, rss_mdm_webhook_service::materials::Transition),
    Types,
    Health,
    Subscriptions(rss_mdm_webhook_service::directory::SubscriptionInput),
    Subscription(Uuid),
    Change(Uuid, Mutation),
    Test {
        subscription: Uuid,
        operation: Uuid,
        device: String,
    },
    Deliveries(rss_mdm_webhook_service::directory::DeliveryInput),
    Delivery(Uuid),
    Replay {
        delivery: Uuid,
        operation: Uuid,
    },
    Redrive {
        delivery: Uuid,
        operation: Uuid,
        version: u64,
    },
}
pub trait Source: Send + Sync {
    fn execute<'a>(
        &'a self,
        proof: Arc<AuthorizedPrincipal>,
        audit: RequestAudit,
        command: Command,
    ) -> futures::future::BoxFuture<'a, Result<Reply, Error>>;
}
pub fn routes(source: Arc<dyn Source>) -> Router {
    register().with_state(source)
}
pub(crate) fn register() -> Router<Arc<dyn Source>> {
    Router::new()
        .route(
            "/webhooks/materials",
            get(materials)
                .owned(&contracts::WEBHOOK_MATERIALS, &[RouteOperation::Get])
                .post(prepare_material)
                .owned(&contracts::WEBHOOK_MATERIALS, &[RouteOperation::Update]),
        )
        .route(
            "/webhooks/materials/transitions",
            post(transition_material)
                .owned(&contracts::WEBHOOK_MATERIALS, &[RouteOperation::Update]),
        )
        .route(
            "/webhooks/materials/operations/{id}",
            get(material_operation).owned(&contracts::WEBHOOK_MATERIALS, &[RouteOperation::Get]),
        )
        .route(
            "/webhooks/health",
            get(health).owned(&contracts::WEBHOOK_HEALTH, &[RouteOperation::Get]),
        )
        .route(
            "/webhooks/event-types",
            get(types).owned(&contracts::WEBHOOK_TYPES, &[RouteOperation::List]),
        )
        .route(
            "/webhooks/subscriptions",
            get(subscriptions).owned(&contracts::WEBHOOK_SUBSCRIPTIONS, &[RouteOperation::List]),
        )
        .route(
            "/webhooks/subscriptions/{id}",
            get(subscription)
                .owned(&contracts::WEBHOOK_SUBSCRIPTIONS, &[RouteOperation::Get])
                .put(change)
                .owned(
                    &contracts::WEBHOOK_SUBSCRIPTIONS,
                    &[
                        RouteOperation::Create,
                        RouteOperation::Update,
                        RouteOperation::Delete,
                    ],
                ),
        )
        .route(
            "/webhooks/subscriptions/{id}/test",
            post(test).owned(
                &contracts::WEBHOOK_SUBSCRIPTIONS,
                &[RouteOperation::Action, RouteOperation::Create],
            ),
        )
        .route(
            "/webhooks/deliveries",
            get(deliveries).owned(&contracts::WEBHOOK_DELIVERIES, &[RouteOperation::List]),
        )
        .route(
            "/webhooks/deliveries/{id}",
            get(delivery).owned(&contracts::WEBHOOK_DELIVERIES, &[RouteOperation::Get]),
        )
        .route(
            "/webhooks/deliveries/{id}/replay",
            post(replay).owned(
                &contracts::WEBHOOK_DELIVERIES,
                &[RouteOperation::Action, RouteOperation::Lifecycle],
            ),
        )
        .route(
            "/webhooks/deliveries/{id}/redrive",
            post(redrive).owned(
                &contracts::WEBHOOK_DELIVERIES,
                &[RouteOperation::Action, RouteOperation::Lifecycle],
            ),
        )
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
async fn call(s: Arc<dyn Source>, a: RequestAuth, audit: RequestAudit, c: Command) -> Response {
    match &c {
        Command::Test {
            subscription,
            operation,
            ..
        } => {
            audit.operation(
                *operation,
                "webhook_write",
                rss_mdm_audit_integration::AuditIntent::Management,
            );
            audit.target(&subscription.to_string());
        }
        Command::Replay {
            delivery,
            operation,
        }
        | Command::Redrive {
            delivery,
            operation,
            ..
        } => {
            audit.operation(
                *operation,
                if matches!(&c, Command::Redrive { .. }) {
                    "webhook_redrive"
                } else {
                    "webhook_write"
                },
                rss_mdm_audit_integration::AuditIntent::Management,
            );
            audit.target(&delivery.to_string());
        }
        _ => {}
    }
    s.execute(a.proof, audit, c).await
}

async fn materials(
    State(s): State<Arc<dyn Source>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
) -> Result<Json<rss_mdm_webhook_service::materials::PublicDirectory>, Error> {
    call(s, a, audit, Command::Materials)
        .await
        .and_then(Reply::materials)
        .map(Json)
}
async fn material_operation(
    State(s): State<Arc<dyn Source>>,
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
    .and_then(Reply::material_operation)
    .map(Json)
}
async fn prepare_material(
    State(s): State<Arc<dyn Source>>,
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
    .and_then(Reply::material)
    .map(Json)
}
async fn transition_material(
    State(s): State<Arc<dyn Source>>,
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
    .and_then(Reply::material_receipt)
    .map(Json)
}
async fn types(
    State(s): State<Arc<dyn Source>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
) -> Result<rss_mdm_http_contract::CollectionResponse<Json<EventTypes>>, Error> {
    (async {
        call(s, a, audit, Command::Types)
            .await
            .and_then(Reply::types)
            .map(Json)
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}
async fn subscriptions(
    State(s): State<Arc<dyn Source>>,
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
        .and_then(Reply::subscriptions)
        .map(Json)
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}
async fn subscription(
    State(s): State<Arc<dyn Source>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
) -> Result<Json<rss_mdm_webhook_service::model::Subscription>, Error> {
    call(s, a, audit, Command::Subscription(id))
        .await
        .and_then(Reply::subscription)
        .map(Json)
}
async fn change(
    State(s): State<Arc<dyn Source>>,
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
    .and_then(Reply::subscription)
    .map(Json)
}
async fn test(
    State(s): State<Arc<dyn Source>>,
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
    .and_then(Reply::delivery_receipt)
    .map(Json)
}
async fn deliveries(
    State(s): State<Arc<dyn Source>>,
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
        .and_then(Reply::deliveries)
        .map(Json)
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}
async fn delivery(
    State(s): State<Arc<dyn Source>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
) -> Result<Json<Deliveries>, Error> {
    call(s, a, audit, Command::Delivery(id))
        .await
        .and_then(Reply::deliveries)
        .map(Json)
}
async fn replay(
    State(s): State<Arc<dyn Source>>,
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
    .and_then(Reply::replay)
    .map(Json)
}
async fn redrive(
    State(s): State<Arc<dyn Source>>,
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
    .and_then(Reply::redrive)
    .map(Json)
}

async fn health(
    State(s): State<Arc<dyn Source>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
) -> Result<Json<Health>, Error> {
    call(s, a, audit, Command::Health)
        .await
        .and_then(Reply::health)
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
