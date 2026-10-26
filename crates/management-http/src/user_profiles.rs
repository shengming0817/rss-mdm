//! User profile HTTP inputs and the product-owned service port.
use crate::{
    Error,
    authorization::context::{AuthorizedPrincipal, RequestAuth},
};
use axum::{
    Extension, Json,
    extract::{Path, Query, State},
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use rss_mdm_http_contract::{Router, routing::get};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProfileSource {
    IdentityLocal,
    Idp { provider: Uuid },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueType {
    String,
    Boolean,
    Number,
    Integer,
    Array,
    Object,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Visibility {
    #[serde(rename = "self")]
    SelfOnly,
    ProfilesRead,
    Both,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisplayUse {
    Profile,
    Summary,
    Hidden,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DefinitionValue {
    pub key: String,
    pub display_name: String,
    pub source: ProfileSource,
    pub pointer: String,
    pub value_type: ValueType,
    pub max_length: Option<u32>,
    pub max_items: Option<u32>,
    pub minimum: Option<f64>,
    pub maximum: Option<f64>,
    pub enabled: bool,
    pub sensitive: bool,
    pub visibility: Visibility,
    pub display_use: DisplayUse,
    pub required: bool,
    pub use_existing_observation: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Change {
    pub operation_id: Uuid,
    pub expected_revision: i64,
    #[serde(deserialize_with = "Option::deserialize")]
    pub value: Option<DefinitionValue>,
}
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum View {
    #[default]
    Current,
    Latest,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileQuery {
    #[serde(default)]
    pub view: View,
    #[serde(default)]
    pub preview: bool,
}
#[derive(Clone)]
pub enum Command {
    Definitions(rss_mdm_query::directory::Query),
    Definition(Uuid),
    Change(Uuid, Change),
    Operation(Uuid),
    Me(ProfileQuery),
    Person(Uuid, ProfileQuery),
}
pub trait Source: Send + Sync {
    fn directory_schema(&self) -> &'static rss_mdm_query::directory::Schema;
    fn execute<'a>(
        &'a self,
        proof: Arc<AuthorizedPrincipal>,
        audit: RequestAudit,
        command: Command,
    ) -> futures::future::BoxFuture<'a, Result<Value, Error>>;
}
pub fn routes(source: Arc<dyn Source>) -> Router {
    Router::new()
        .route(
            "/user-attribute-definitions",
            get(definitions)
                .owned(&contracts::USER_ATTRIBUTES, &[RouteOperation::List])
                .queried(source.directory_schema()),
        )
        .route(
            "/user-attribute-definitions/{id}",
            get(definition)
                .owned(&contracts::USER_ATTRIBUTES, &[RouteOperation::Get])
                .put(change)
                .owned(
                    &contracts::USER_ATTRIBUTES,
                    &[
                        RouteOperation::Create,
                        RouteOperation::Update,
                        RouteOperation::Delete,
                    ],
                ),
        )
        .route(
            "/user-attribute-operations/{id}",
            get(operation).owned(
                &contracts::USER_ATTRIBUTE_OPERATIONS,
                &[RouteOperation::Get],
            ),
        )
        .route(
            "/user-profiles/me",
            get(me).owned(&contracts::USER_PROFILES, &[RouteOperation::Action]),
        )
        .route(
            "/user-profiles/{id}",
            get(person).owned(&contracts::USER_PROFILES, &[RouteOperation::Get]),
        )
        .with_state(source)
}
type Response = Result<Json<Value>, Error>;
async fn call(s: Arc<dyn Source>, a: RequestAuth, audit: RequestAudit, c: Command) -> Response {
    s.execute(a.proof, audit, c).await.map(Json)
}
async fn definitions(
    State(s): State<Arc<dyn Source>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    axum::extract::RawQuery(raw): axum::extract::RawQuery,
) -> Result<rss_mdm_http_contract::CollectionResponse<Json<Value>>, Error> {
    (async {
        let query = s
            .directory_schema()
            .parse(raw.as_deref().unwrap_or_default())
            .map_err(|_| Error::Malformed)?;
        call(s, a, audit, Command::Definitions(query)).await
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}
async fn definition(
    State(s): State<Arc<dyn Source>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
) -> Response {
    call(s, a, audit, Command::Definition(id)).await
}
async fn operation(
    State(s): State<Arc<dyn Source>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
) -> Response {
    call(s, a, audit, Command::Operation(id)).await
}
async fn change(
    State(s): State<Arc<dyn Source>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    input: Result<Json<Change>, axum::extract::rejection::JsonRejection>,
) -> Response {
    call(s, a, audit, Command::Change(id, input?.0)).await
}
async fn me(
    State(s): State<Arc<dyn Source>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Query(q): Query<ProfileQuery>,
) -> Response {
    call(s, a, audit, Command::Me(q)).await
}
async fn person(
    State(s): State<Arc<dyn Source>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    Query(mut q): Query<ProfileQuery>,
) -> Response {
    q.view = View::Latest;
    call(s, a, audit, Command::Person(id, q)).await
}
