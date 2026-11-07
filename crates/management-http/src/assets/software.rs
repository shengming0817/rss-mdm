//! Independent software contracts on the existing Inventory transaction and query owner.
use super::*;
use rss_mdm_http_contract::{
    CollectionResponse,
    module::Route,
    query::{OwnedQuery, Window, WindowOwner},
};
use rss_mdm_inventory_service::assets::software as model;

pub(super) fn routes()
-> Router<Arc<HttpState>, impl rss_mdm_http_contract::module::Declaration + use<>> {
    rss_mdm_http_contract::route_module! { struct SoftwareRoutes for [Browser] {
        standards, standard, standard_write, mappings, mapping, mapping_write, receipt,
        search, release, status, buckets, breakdowns, devices, evidence, coverage
    } }
    SoftwareRoutes {
        standards: Route::new(
            "/standard-software",
            get(
                standards,
                &contracts::STANDARD_SOFTWARE,
                &[RouteOperation::List],
            ),
        ),
        standard: Route::new(
            "/standard-software/{id}",
            get(
                standard,
                &contracts::STANDARD_SOFTWARE,
                &[RouteOperation::Get],
            ),
        ),
        standard_write: Route::new(
            "/standard-software/{id}",
            put(
                standard_write,
                &contracts::STANDARD_SOFTWARE,
                &[
                    RouteOperation::Create,
                    RouteOperation::Update,
                    RouteOperation::Delete,
                ],
            ),
        ),
        mappings: Route::new(
            "/software-mappings",
            get(
                mappings,
                &contracts::SOFTWARE_MAPPINGS,
                &[RouteOperation::List],
            ),
        ),
        mapping: Route::new(
            "/software-mappings/{id}",
            get(
                mapping,
                &contracts::SOFTWARE_MAPPINGS,
                &[RouteOperation::Get],
            ),
        ),
        mapping_write: Route::new(
            "/software-mappings/{id}",
            put(
                mapping_write,
                &contracts::SOFTWARE_MAPPINGS,
                &[
                    RouteOperation::Create,
                    RouteOperation::Update,
                    RouteOperation::Delete,
                ],
            ),
        ),
        receipt: Route::new(
            "/software-asset-operations/{id}",
            get(
                receipt,
                &contracts::SOFTWARE_ASSET_OPERATIONS,
                &[RouteOperation::Get],
            ),
        ),
        search: Route::new(
            "/software-asset-queries",
            post(
                search,
                &contracts::SOFTWARE_ASSET_QUERIES,
                &[RouteOperation::Create],
            ),
        ),
        release: Route::new(
            "/software-asset-queries/{id}/release",
            post(
                release,
                &contracts::SOFTWARE_ASSET_QUERIES,
                &[RouteOperation::Delete],
            ),
        ),
        status: Route::new(
            "/software-asset-queries/{id}",
            get(
                status,
                &contracts::SOFTWARE_ASSET_QUERIES,
                &[RouteOperation::Get],
            ),
        ),
        coverage: Route::new(
            "/software-asset-queries/{id}/coverage",
            get(
                coverage,
                &contracts::SOFTWARE_ASSET_COVERAGE,
                &[RouteOperation::List],
            ),
        ),
        buckets: Route::new(
            "/software-asset-queries/{id}/software",
            get(
                buckets,
                &contracts::SOFTWARE_ASSET_BUCKETS,
                &[RouteOperation::List],
            ),
        ),
        breakdowns: Route::new(
            "/software-asset-queries/{id}/software/{bucket}/breakdowns/{dimension}",
            get(
                breakdowns,
                &contracts::SOFTWARE_ASSET_BREAKDOWNS,
                &[RouteOperation::List],
            ),
        ),
        devices: Route::new(
            "/software-asset-queries/{id}/software/{bucket}/devices",
            get(
                devices,
                &contracts::SOFTWARE_ASSET_DEVICES,
                &[RouteOperation::List],
            ),
        ),
        evidence: Route::new(
            "/software-asset-queries/{id}/software/{bucket}/devices/{object}/evidence",
            get(
                evidence,
                &contracts::SOFTWARE_ASSET_EVIDENCE,
                &[RouteOperation::List],
            ),
        ),
    }
    .assemble()
}
async fn invoke(
    app: &HttpState,
    auth: &RequestAuth,
    audit: &RequestAudit,
    command: model::Command,
) -> Result<HttpResponse, Error> {
    let access = model::Access::from_proof(&auth.proof)?;
    run(
        app,
        auth,
        audit,
        Command::Software {
            command: Box::new(command),
            access,
        },
    )
    .await
}
macro_rules! window {
    ($name:ident,$schema:ident) => {
        struct $name;
        impl WindowOwner for $name {
            fn schema() -> &'static rss_mdm_query::window::Schema {
                &model::windows::$schema
            }
        }
    };
}
window!(Standards, STANDARDS);
window!(Mappings, MAPPINGS);
window!(Buckets, BUCKETS);
window!(Breakdowns, BREAKDOWNS);
window!(Devices, DEVICES);
window!(Evidence, EVIDENCE);
fn page<Q: WindowOwner>(query: OwnedQuery<Window<Q>>) -> Result<model::Page, Error> {
    let (query, _) = query.parse().map_err(|_| Error::Malformed)?;
    Ok(model::Page {
        limit: query.limit(),
        cursor: query.cursor().clone(),
    })
}
async fn standards(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    query: OwnedQuery<Window<Standards>>,
) -> Result<CollectionResponse<HttpResponse>, Error> {
    invoke(
        &app,
        &auth,
        &audit,
        model::Command::Standards { page: page(query)? },
    )
    .await
    .map(CollectionResponse)
}
async fn standard(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
) -> Result<HttpResponse, Error> {
    invoke(&app, &auth, &audit, model::Command::Standard { id }).await
}
async fn standard_write(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    payload: BodyInput<Operation<model::Change<model::Standard>>>,
) -> Result<HttpResponse, Error> {
    invoke(
        &app,
        &auth,
        &audit,
        model::Command::PutStandard {
            id,
            change: body(payload)?,
        },
    )
    .await
}
async fn mappings(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    query: OwnedQuery<Window<Mappings>>,
) -> Result<CollectionResponse<HttpResponse>, Error> {
    invoke(
        &app,
        &auth,
        &audit,
        model::Command::Mappings { page: page(query)? },
    )
    .await
    .map(CollectionResponse)
}
async fn mapping(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
) -> Result<HttpResponse, Error> {
    invoke(&app, &auth, &audit, model::Command::Mapping { id }).await
}
async fn mapping_write(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    payload: BodyInput<Operation<model::Change<model::Mapping>>>,
) -> Result<HttpResponse, Error> {
    invoke(
        &app,
        &auth,
        &audit,
        model::Command::PutMapping {
            id,
            change: body(payload)?,
        },
    )
    .await
}
async fn receipt(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
) -> Result<HttpResponse, Error> {
    invoke(
        &app,
        &auth,
        &audit,
        model::Command::Receipt {
            id,
            actor: audit.snapshot().actor.ok_or(Error::Malformed)?,
            instance: auth.proof.instance_id().into(),
        },
    )
    .await
}
async fn search(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    payload: BodyInput<Operation<model::Query>>,
) -> Result<HttpResponse, Error> {
    invoke(
        &app,
        &auth,
        &audit,
        model::Command::Search {
            change: Box::new(body(payload)?),
        },
    )
    .await
}
async fn status(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
) -> Result<HttpResponse, Error> {
    invoke(&app, &auth, &audit, model::Command::Status { id }).await
}
async fn buckets(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    query: OwnedQuery<Window<Buckets>>,
) -> Result<CollectionResponse<HttpResponse>, Error> {
    invoke(
        &app,
        &auth,
        &audit,
        model::Command::Buckets {
            id,
            page: page(query)?,
        },
    )
    .await
    .map(CollectionResponse)
}
async fn breakdowns(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((id, bucket, dimension)): Path<(Uuid, String, model::Dimension)>,
    query: OwnedQuery<Window<Breakdowns>>,
) -> Result<CollectionResponse<HttpResponse>, Error> {
    invoke(
        &app,
        &auth,
        &audit,
        model::Command::Breakdowns {
            id,
            bucket,
            dimension,
            page: page(query)?,
        },
    )
    .await
    .map(CollectionResponse)
}
async fn devices(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((id, bucket)): Path<(Uuid, String)>,
    query: OwnedQuery<Window<Devices>>,
) -> Result<CollectionResponse<HttpResponse>, Error> {
    invoke(
        &app,
        &auth,
        &audit,
        model::Command::Devices {
            id,
            bucket,
            page: page(query)?,
        },
    )
    .await
    .map(CollectionResponse)
}
async fn evidence(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((id, bucket, object)): Path<(Uuid, String, String)>,
    query: OwnedQuery<Window<Evidence>>,
) -> Result<CollectionResponse<HttpResponse>, Error> {
    invoke(
        &app,
        &auth,
        &audit,
        model::Command::Evidence {
            id,
            bucket,
            object,
            page: page(query)?,
        },
    )
    .await
    .map(CollectionResponse)
}

window!(Coverage, COVERAGE);
async fn coverage(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    query: OwnedQuery<Window<Coverage>>,
) -> Result<CollectionResponse<HttpResponse>, Error> {
    invoke(
        &app,
        &auth,
        &audit,
        model::Command::Coverage {
            id,
            page: page(query)?,
        },
    )
    .await
    .map(CollectionResponse)
}

async fn release(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    payload: BodyInput<Operation<model::ReleaseInput>>,
) -> Result<HttpResponse, Error> {
    invoke(
        &app,
        &auth,
        &audit,
        model::Command::Release {
            id,
            change: body(payload)?,
        },
    )
    .await
}
