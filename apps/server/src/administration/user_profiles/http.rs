//! User profile HTTP inputs and the product-owned service port.
use rss_mdm_management_http::Error;
use rss_mdm_authorization_service::context::RequestAuth;
use super::{Backend, model::*};
use super::directory::DIRECTORY;
use rss_mdm_query::directory::Schema;
use axum::{
    Extension, Json,
    extract::{Path, Query, State},
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use rss_mdm_http_contract::{Router, routing::get};
use std::sync::Arc;
use uuid::Uuid;

pub fn routes(
    source: Arc<Backend>,
) -> Router<(), impl rss_mdm_http_contract::module::Declaration + use<>> {
    register().with_state(source)
}
pub(crate) fn register()
-> Router<Arc<Backend>, impl rss_mdm_http_contract::module::Declaration + use<>> {
    {
        rss_mdm_http_contract::route_module! { struct RegisterModule1 for [Browser] { get_definitions, get_definition, put_change, get_operation, get_me, get_person } }
        RegisterModule1 {
            get_definitions: rss_mdm_http_contract::module::Route::new(
                "/user-attribute-definitions",
                get(
                    definitions,
                    &contracts::USER_ATTRIBUTES,
                    &[RouteOperation::List],
                ),
            ),
            get_definition: rss_mdm_http_contract::module::Route::new(
                "/user-attribute-definitions/{id}",
                rss_mdm_http_contract::routing::get(
                    definition,
                    &contracts::USER_ATTRIBUTES,
                    &[RouteOperation::Get],
                ),
            ),
            put_change: rss_mdm_http_contract::module::Route::new(
                "/user-attribute-definitions/{id}",
                rss_mdm_http_contract::routing::put(
                    change,
                    &contracts::USER_ATTRIBUTES,
                    &[
                        RouteOperation::Create,
                        RouteOperation::Update,
                        RouteOperation::Delete,
                    ],
                ),
            ),
            get_operation: rss_mdm_http_contract::module::Route::new(
                "/user-attribute-operations/{id}",
                get(
                    operation,
                    &contracts::USER_ATTRIBUTE_OPERATIONS,
                    &[RouteOperation::Get],
                ),
            ),
            get_me: rss_mdm_http_contract::module::Route::new(
                "/user-profiles/me",
                get(me, &contracts::USER_PROFILES, &[RouteOperation::Action]),
            ),
            get_person: rss_mdm_http_contract::module::Route::new(
                "/user-profiles/{id}",
                get(person, &contracts::USER_PROFILES, &[RouteOperation::Get]),
            ),
        }
        .assemble()
    }
}

async fn definitions(
    State(s): State<Arc<Backend>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Directory<DefinitionDirectory>,
    >,
) -> Result<rss_mdm_http_contract::CollectionResponse<Json<Definitions>>, Error> {
    (async {
        let query = query.parse().map_err(|_| Error::Malformed)?;
        s.definitions(&a.proof, &audit, &query)
            .await
            .map_err(Error::from)
            .map(Json)
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}
async fn definition(
    State(s): State<Arc<Backend>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
) -> Result<Json<Definition>, Error> {
    s.definition(&a.proof, &audit, id)
        .await
        .map_err(Error::from)
        .map(Json)
}
async fn operation(
    State(s): State<Arc<Backend>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
) -> Result<Json<Receipt>, Error> {
    s.operation(&a.proof, &audit, id)
        .await
        .map_err(Error::from)
        .map(Json)
}
async fn change(
    State(s): State<Arc<Backend>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    input: Result<Json<Change>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Receipt>, Error> {
    s.change(&a.proof, &audit, id, &input?.0)
        .await
        .map_err(Error::from)
        .map(Json)
}
async fn me(
    State(s): State<Arc<Backend>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Query(q): Query<ProfileQuery>,
) -> Result<Json<Profile>, Error> {
    s.profile(&a.proof, &audit, None, q)
        .await
        .map_err(Error::from)
        .map(Json)
}
async fn person(
    State(s): State<Arc<Backend>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    Query(mut q): Query<ProfileQuery>,
) -> Result<Json<Profile>, Error> {
    q.view = View::Latest;
    s.profile(&a.proof, &audit, Some(id), q)
        .await
        .map_err(Error::from)
        .map(Json)
}

struct DefinitionDirectory;
impl rss_mdm_http_contract::query::DirectoryOwner for DefinitionDirectory {
    fn schema() -> &'static Schema {
        &DIRECTORY
    }
}
