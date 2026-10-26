//! Administrator reads reuse the existing request proof and response boundary.
//! ref: axum axum/src/extract/query.rs@axum-v0.8.9
use crate::{Error, Failure, authorization::context::RequestAuth};
use axum::{
    Extension, Json,
    extract::{Path, State},
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use rss_mdm_http_contract::{Router, routing::get};
use rss_mdm_timeline_service::{Page, Timeline};
use std::sync::Arc;
fn error(error: rss_mdm_timeline_service::Error) -> Error {
    use rss_mdm_timeline_service::Error as E;
    match error {
        E::Malformed => Error::Malformed,
        E::NotFound => Error::NotFound,
        E::Conflict => Error::Conflict,
        E::Forbidden => Error::Forbidden,
        E::Integrity => Error::Unavailable(Failure::AuditIntegrity),
        E::Storage | E::Deadline => Error::Unavailable(Failure::Timeline),
    }
}
pub fn routes() -> Router<Arc<Timeline>> {
    Router::new()
        .route(
            "/devices/{device}/management-activities",
            get(activities).owned(&contracts::MANAGEMENT_ACTIVITIES, &[RouteOperation::List]),
        )
        .route(
            "/devices/{device}/management-activities/{id}",
            get(activity).owned(&contracts::MANAGEMENT_ACTIVITIES, &[RouteOperation::Get]),
        )
        .route(
            "/devices/{device}/timeline",
            get(device).owned(&contracts::DEVICE_TIMELINE, &[RouteOperation::List]),
        )
        .route(
            "/audit-events",
            get(search).owned(&contracts::AUDIT, &[RouteOperation::List]),
        )
}
async fn device(
    State(service): State<Arc<Timeline>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(device): Path<String>,
    params: rss_mdm_http_contract::query::OwnedQuery<DeviceQuery>,
) -> Result<rss_mdm_http_contract::CollectionResponse<Json<Page>>, Error> {
    (async {
        audit.target_device(&device);
        let mut query = params.parse().map_err(error)?;
        if query.device.is_some() {
            return Err(Error::Malformed);
        }
        query.device = Some(device);
        service
            .query(&auth.proof, "device", &query)
            .await
            .map(Json)
            .map_err(error)
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}
async fn search(
    State(service): State<Arc<Timeline>>,
    Extension(audit): Extension<RequestAudit>,
    Extension(auth): Extension<RequestAuth>,
    params: rss_mdm_http_contract::query::OwnedQuery<AuditQuery>,
) -> Result<rss_mdm_http_contract::CollectionResponse<Json<Page>>, Error> {
    (async {
        audit.intent(rss_mdm_audit_integration::AuditIntent::Sensitive(
            rss_mdm_audit_integration::SensitiveAction::AuditHistoryRead,
        ));
        service
            .query(&auth.proof, "audit", &params.parse().map_err(error)?)
            .await
            .map(Json)
            .map_err(error)
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}

async fn activities(
    State(service): State<Arc<Timeline>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(device): Path<String>,
    params: rss_mdm_http_contract::query::OwnedQuery<ActivityQuery>,
) -> Result<
    rss_mdm_http_contract::CollectionResponse<
        Json<rss_mdm_agent_wire::activities::ManagementActivityPage>,
    >,
    Error,
> {
    audit.set_action(
        "management_activity_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    let query = params.parse().map_err(error)?;
    service
        .activities(
            &rss_mdm_timeline_service::activities::Reader::Management {
                proof: &auth.proof,
                device: &device,
            },
            &query,
            false,
        )
        .await
        .map(|v| rss_mdm_http_contract::CollectionResponse(Json(v)))
        .map_err(error)
}
async fn activity(
    State(service): State<Arc<Timeline>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((device, id)): Path<(String, String)>,
) -> Result<Json<rss_mdm_agent_wire::activities::ManagementActivityDetail>, Error> {
    audit.set_action(
        "management_activity_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    service
        .activity_detail(
            &rss_mdm_timeline_service::activities::Reader::Management {
                proof: &auth.proof,
                device: &device,
            },
            &id,
            false,
        )
        .await
        .map(Json)
        .map_err(error)
}

struct DeviceQuery;
impl rss_mdm_http_contract::query::QueryOwner for DeviceQuery {
    type Parsed = rss_mdm_timeline_service::Query;
    type Error = rss_mdm_timeline_service::Error;
    fn declaration() -> Option<rss_mdm_http_contract::QueryDeclaration> {
        Some(rss_mdm_http_contract::QueryDeclaration::Window(
            &rss_mdm_timeline_service::DEVICE_TIMELINE,
        ))
    }
    fn parameters() -> rss_mdm_http_contract::signature::Schema {
        let mut schema = rss_mdm_http_contract::signature::Schema::request::<Self::Parsed>();
        schema.value["properties"]["limit"]["minimum"] = 1.into();
        schema.value["properties"]["limit"]["maximum"] =
            rss_mdm_timeline_service::DEVICE_TIMELINE.max_limit.into();
        schema.value["properties"]["limit"]["default"] = rss_mdm_timeline_service::DEVICE_TIMELINE
            .default_limit
            .into();
        schema.value["properties"]
            .as_object_mut()
            .unwrap()
            .remove("device");
        schema
    }
    fn parse(raw: &str) -> Result<Self::Parsed, Self::Error> {
        rss_mdm_timeline_service::Query::parse(raw, true)
    }
}

struct AuditQuery;
impl rss_mdm_http_contract::query::QueryOwner for AuditQuery {
    type Parsed = rss_mdm_timeline_service::Query;
    type Error = rss_mdm_timeline_service::Error;
    fn declaration() -> Option<rss_mdm_http_contract::QueryDeclaration> {
        Some(rss_mdm_http_contract::QueryDeclaration::Window(
            &rss_mdm_timeline_service::AUDIT,
        ))
    }
    fn parameters() -> rss_mdm_http_contract::signature::Schema {
        let mut schema = rss_mdm_http_contract::signature::Schema::request::<Self::Parsed>();
        schema.value["properties"]["limit"]["minimum"] = 1.into();
        schema.value["properties"]["limit"]["maximum"] =
            rss_mdm_timeline_service::AUDIT.max_limit.into();
        schema.value["properties"]["limit"]["default"] =
            rss_mdm_timeline_service::AUDIT.default_limit.into();

        schema
    }
    fn parse(raw: &str) -> Result<Self::Parsed, Self::Error> {
        rss_mdm_timeline_service::Query::parse(raw, false)
    }
}

struct ActivityQuery;
impl rss_mdm_http_contract::query::QueryOwner for ActivityQuery {
    type Parsed = rss_mdm_timeline_service::activities::Query;
    type Error = rss_mdm_timeline_service::Error;
    fn declaration() -> Option<rss_mdm_http_contract::QueryDeclaration> {
        Some(rss_mdm_http_contract::QueryDeclaration::Window(
            &rss_mdm_timeline_service::activities::ACTIVITIES,
        ))
    }
    fn parameters() -> rss_mdm_http_contract::signature::Schema {
        let mut schema = rss_mdm_http_contract::signature::Schema::request::<Self::Parsed>();
        schema.value["properties"]["limit"]["minimum"] = 1.into();
        schema.value["properties"]["limit"]["maximum"] =
            rss_mdm_timeline_service::activities::ACTIVITIES
                .max_limit
                .into();
        schema.value["properties"]["limit"]["default"] =
            rss_mdm_timeline_service::activities::ACTIVITIES
                .default_limit
                .into();

        schema
    }
    fn parse(raw: &str) -> Result<Self::Parsed, Self::Error> {
        rss_mdm_timeline_service::activities::Query::parse(raw)
    }
}
