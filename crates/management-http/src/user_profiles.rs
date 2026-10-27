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

#[derive(schemars::JsonSchema, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProfileSource {
    IdentityLocal,
    Idp { provider: Uuid },
}
#[derive(schemars::JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueType {
    String,
    Boolean,
    Number,
    Integer,
    Array,
    Object,
}
#[derive(schemars::JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Visibility {
    #[serde(rename = "self")]
    SelfOnly,
    ProfilesRead,
    Both,
}
#[derive(schemars::JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisplayUse {
    Profile,
    Summary,
    Hidden,
}
#[derive(schemars::JsonSchema, Clone, Debug, PartialEq, Serialize, Deserialize)]
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
#[derive(schemars::JsonSchema, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Change {
    pub operation_id: Uuid,
    pub expected_revision: i64,
    #[serde(deserialize_with = "Option::deserialize")]
    pub value: Option<DefinitionValue>,
}
#[derive(schemars::JsonSchema, Clone, Copy, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum View {
    #[default]
    Current,
    Latest,
}
#[derive(schemars::JsonSchema, Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileQuery {
    #[serde(default)]
    pub view: View,
    #[serde(default)]
    pub preview: bool,
}

#[derive(schemars::JsonSchema, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Definition {
    pub field_id: Uuid,
    pub revision: i64,
    pub collected_after_micros: i64,
    pub value: Option<DefinitionValue>,
}
#[derive(schemars::JsonSchema, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Receipt {
    pub operation_id: Uuid,
    pub definition: Definition,
}
#[derive(schemars::JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DefinitionRow {
    #[serde(flatten)]
    pub definition: Definition,
    pub key: String,
    pub display_name: String,
    pub source_kind: SourceKind,
    pub provider: Option<Uuid>,
    pub value_type: ValueType,
    pub enabled: bool,
    pub sensitive: bool,
    pub required: bool,
    pub visibility: Visibility,
    pub display_use: DisplayUse,
}
#[derive(schemars::JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    IdentityLocal,
    Idp,
}
#[derive(schemars::JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceView {
    pub source: ProfileSource,
    pub provider_config_version: Option<i64>,
    pub extensions_root: Option<String>,
    pub max_age_seconds: u32,
}
#[derive(schemars::JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Definitions {
    pub items: Vec<rss_mdm_query::directory::Projection<DefinitionRow>>,
    pub next_cursor: Option<String>,
    pub sources: Vec<SourceView>,
}
#[derive(schemars::JsonSchema, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Attribute<T> {
    Available { value: T },
    Missing,
    Invalid,
    NotConfigured,
}
#[derive(schemars::JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Fixed {
    pub display_name: Attribute<String>,
    pub username: Attribute<String>,
    pub email: Attribute<String>,
    pub email_verified: Attribute<bool>,
}
#[derive(schemars::JsonSchema, Clone, Copy, PartialEq, Eq, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileStatus {
    Available,
    Missing,
    Expired,
    Unavailable,
}
#[derive(schemars::JsonSchema, Clone, Copy, PartialEq, Eq, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldStatus {
    Available,
    Missing,
    Expired,
    Unavailable,
    PendingLogin,
    Invalid,
    NotConfigured,
    Redacted,
}
#[derive(schemars::JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ObservedProfile {
    pub source: Option<ProfileSource>,
    pub status: ProfileStatus,
    pub snapshot_id: Option<Uuid>,
    pub provider_config_version: Option<i64>,
    pub source_revision: Option<i64>,
    pub observed_at: Option<i64>,
    pub collected_at_micros: Option<i64>,
    pub expires_at: Option<i64>,
    pub fixed: Option<Fixed>,
}
#[derive(schemars::JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldView {
    pub field_id: Uuid,
    pub revision: i64,
    pub key: String,
    pub display_name: String,
    pub source: ProfileSource,
    pub value_type: ValueType,
    pub sensitive: bool,
    pub display_use: DisplayUse,
    pub required: bool,
    pub status: FieldStatus,
    #[schemars(extend("x-rss-extension"="User-defined attribute admitted by DefinitionValue and model::conforms"))]
    pub value: Option<Value>,
}
#[derive(schemars::JsonSchema, Serialize)]
pub struct Completeness {
    pub required: u32,
    pub complete: u32,
    pub missing: u32,
}
#[derive(schemars::JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    pub principal_id: Uuid,
    pub view: View,
    pub profiles: Vec<ObservedProfile>,
    pub fields: Vec<FieldView>,
    pub completeness: Completeness,
}
pub enum Reply {
    Definitions(Definitions),
    Definition(Definition),
    Receipt(Receipt),
    Profile(Profile),
}
impl Reply {
    pub fn definitions(self) -> Result<Definitions, Error> {
        if let Self::Definitions(v) = self {
            Ok(v)
        } else {
            Err(Error::Unavailable(crate::Failure::Database))
        }
    }
    pub fn definition(self) -> Result<Definition, Error> {
        if let Self::Definition(v) = self {
            Ok(v)
        } else {
            Err(Error::Unavailable(crate::Failure::Database))
        }
    }
    pub fn receipt(self) -> Result<Receipt, Error> {
        if let Self::Receipt(v) = self {
            Ok(v)
        } else {
            Err(Error::Unavailable(crate::Failure::Database))
        }
    }
    pub fn profile(self) -> Result<Profile, Error> {
        if let Self::Profile(v) = self {
            Ok(v)
        } else {
            Err(Error::Unavailable(crate::Failure::Database))
        }
    }
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
            "/user-attribute-definitions",
            get(definitions).owned(&contracts::USER_ATTRIBUTES, &[RouteOperation::List]),
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
}

async fn call(
    s: Arc<dyn Source>,
    a: RequestAuth,
    audit: RequestAudit,
    c: Command,
) -> Result<Reply, Error> {
    s.execute(a.proof, audit, c).await
}
async fn definitions(
    State(s): State<Arc<dyn Source>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Directory<DefinitionDirectory>,
    >,
) -> Result<rss_mdm_http_contract::CollectionResponse<Json<Definitions>>, Error> {
    (async {
        let query = query.parse().map_err(|_| Error::Malformed)?;
        call(s, a, audit, Command::Definitions(query))
            .await
            .and_then(Reply::definitions)
            .map(Json)
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}
async fn definition(
    State(s): State<Arc<dyn Source>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
) -> Result<Json<Definition>, Error> {
    call(s, a, audit, Command::Definition(id))
        .await
        .and_then(Reply::definition)
        .map(Json)
}
async fn operation(
    State(s): State<Arc<dyn Source>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
) -> Result<Json<Receipt>, Error> {
    call(s, a, audit, Command::Operation(id))
        .await
        .and_then(Reply::receipt)
        .map(Json)
}
async fn change(
    State(s): State<Arc<dyn Source>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    input: Result<Json<Change>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Receipt>, Error> {
    call(s, a, audit, Command::Change(id, input?.0))
        .await
        .and_then(Reply::receipt)
        .map(Json)
}
async fn me(
    State(s): State<Arc<dyn Source>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Query(q): Query<ProfileQuery>,
) -> Result<Json<Profile>, Error> {
    call(s, a, audit, Command::Me(q))
        .await
        .and_then(Reply::profile)
        .map(Json)
}
async fn person(
    State(s): State<Arc<dyn Source>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    Query(mut q): Query<ProfileQuery>,
) -> Result<Json<Profile>, Error> {
    q.view = View::Latest;
    call(s, a, audit, Command::Person(id, q))
        .await
        .and_then(Reply::profile)
        .map(Json)
}

use rss_mdm_query::directory::{Field, Kind, Schema};
pub static DIRECTORY: Schema = Schema {
    id: "user_attributes",
    keys: &["fieldId"],
    default_limit: 128,
    max_limit: 128,
    fields: &[
        Field::scalar("fieldId", Kind::Uuid),
        Field::scalar("revision", Kind::Integer),
        Field::scalar("key", Kind::Text),
        Field::scalar("displayName", Kind::Text),
        Field::scalar("sourceKind", Kind::Enum(&["identity_local", "idp"])),
        Field::scalar("provider", Kind::Uuid),
        Field::scalar(
            "valueType",
            Kind::Enum(&["string", "boolean", "number", "integer", "array", "object"]),
        ),
        Field::scalar("enabled", Kind::Boolean),
        Field::scalar("sensitive", Kind::Boolean),
        Field::scalar("required", Kind::Boolean),
        Field::scalar("visibility", Kind::Enum(&["self", "profiles_read", "both"])),
        Field::scalar("displayUse", Kind::Enum(&["profile", "summary", "hidden"])),
        Field::output("collectedAfterMicros"),
        Field::output("value"),
    ],
};
struct DefinitionDirectory;
impl rss_mdm_http_contract::query::DirectoryOwner for DefinitionDirectory {
    fn schema() -> &'static Schema {
        &DIRECTORY
    }
}
