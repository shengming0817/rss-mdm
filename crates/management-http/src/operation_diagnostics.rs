//! Read-only product operation diagnostics; receipt owners retain facts and authorization.
//! ref: axum axum/src/extract/query.rs@axum-v0.8.9.
use crate::{Error, Failure, authorization::context::RequestAuth};
use axum::{
    Extension, Json,
    extract::{Path, State},
    http::HeaderMap,
};
use futures::future::BoxFuture;
use rss_mdm_audit_integration::{
    RequestAudit,
    operation::{OperationLocator, OperationOwner, ReceiptSummary},
};
use rss_mdm_http_contract::{Operation as RouteOperation, Router, catalog, routing::get};
use rss_mdm_timeline_service::{DiagnosticPage, Timeline};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone, Debug, Default, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocatorQuery {
    #[serde(default)]
    pub include_audit: bool,
    pub actor: Option<String>,
    pub instance: Option<Uuid>,
    pub device: Option<String>,
    pub target: Option<String>,
    pub registration: Option<Uuid>,
    pub generation: Option<i64>,
}
impl LocatorQuery {
    pub fn validate(&self) -> Result<(), Error> {
        if self.generation.is_some_and(|v| v < 1)
            || self.instance.is_some_and(|v| v.is_nil())
            || self.registration.is_some_and(|v| v.is_nil())
            || [&self.actor, &self.device, &self.target]
                .into_iter()
                .flatten()
                .any(|v| v.is_empty() || v.len() > 256 || v.chars().any(char::is_control))
        {
            return Err(Error::Malformed);
        }
        Ok(())
    }
}
#[derive(Serialize, schemars::JsonSchema)]
#[serde(tag = "availability", content = "value", rename_all = "snake_case")]
pub enum Evidence<T> {
    Available(T),
    NotRequested,
    NotFound,
    NoDurableEvidence,
    Restricted,
    Unavailable,
    Expired,
}
#[derive(Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Detail {
    pub operation: OperationLocator,
    pub original_result: Evidence<ReceiptSummary>,
    pub audit_evidence: Evidence<DiagnosticPage>,
    pub request_evidence: Evidence<DiagnosticPage>,
    pub execution_evidence: Evidence<crate::execution::operations::Evidence>,
    /// An original-result read endpoint; never a write/replay or secret disclosure URL.
    pub original_result_url: Option<String>,
    pub current_resource_url: Option<String>,
}
pub struct Lookup<'a> {
    pub auth: &'a RequestAuth,
    pub audit: &'a RequestAudit,
    pub owner: OperationOwner,
    pub operation: Uuid,
    pub query: &'a LocatorQuery,
    pub headers: &'a HeaderMap,
    pub address: Option<std::net::IpAddr>,
}
pub trait Reads: Send + Sync {
    fn operation<'a>(&'a self, lookup: Lookup<'a>) -> BoxFuture<'a, Result<Detail, Error>>;
}
pub struct Services {
    pub timeline: Arc<Timeline>,
    pub reads: Arc<dyn Reads>,
}
pub fn routes() -> Router<Arc<Services>, impl rss_mdm_http_contract::module::Declaration + use<>> {
    rss_mdm_http_contract::route_module! {struct DiagnosticsRoutes for [Browser]{search,request,operation}}
    DiagnosticsRoutes {
        search: rss_mdm_http_contract::module::Route::new(
            "/operation-diagnostics",
            get(
                search,
                &catalog::OPERATION_DIAGNOSTICS,
                &[RouteOperation::List],
            ),
        ),
        request: rss_mdm_http_contract::module::Route::new(
            "/operation-diagnostics/requests/{requestId}",
            get(
                request,
                &catalog::OPERATION_DIAGNOSTICS,
                &[RouteOperation::List],
            ),
        ),
        operation: rss_mdm_http_contract::module::Route::new(
            "/operation-diagnostics/operations/{owner}/{operationId}",
            get(
                operation,
                &catalog::OPERATION_DIAGNOSTICS,
                &[RouteOperation::Get],
            ),
        ),
    }
    .assemble()
}
fn timeline_error(e: rss_mdm_timeline_service::Error) -> Error {
    use rss_mdm_timeline_service::Error as E;
    match e {
        E::Forbidden => Error::Forbidden,
        E::Malformed => Error::Malformed,
        E::NotFound => Error::NotFound,
        E::Conflict => Error::QueryCursorInvalidated,
        E::Integrity => Error::Unavailable(Failure::AuditIntegrity),
        E::Storage | E::Deadline => Error::Unavailable(Failure::Timeline),
    }
}
fn audit_read(a: &RequestAudit) {
    a.set_action(
        "operation_diagnostics_read",
        rss_mdm_audit_integration::AuditIntent::Sensitive(
            rss_mdm_audit_integration::SensitiveAction::AuditHistoryRead,
        ),
    );
}
async fn search(
    State(s): State<Arc<Services>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    params: rss_mdm_http_contract::query::OwnedQuery<Discovery>,
) -> Result<rss_mdm_http_contract::CollectionResponse<Json<DiagnosticPage>>, Error> {
    audit_read(&audit);
    s.timeline
        .diagnostics(
            &auth.proof,
            "operation_diagnostics",
            &params.parse().map_err(timeline_error)?,
        )
        .await
        .map(Json)
        .map(rss_mdm_http_contract::CollectionResponse)
        .map_err(timeline_error)
}
async fn request(
    State(s): State<Arc<Services>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    params: rss_mdm_http_contract::query::OwnedQuery<Discovery>,
) -> Result<rss_mdm_http_contract::CollectionResponse<Json<DiagnosticPage>>, Error> {
    audit_read(&audit);
    let mut query = params.parse().map_err(timeline_error)?;
    if query.request_id.is_some_and(|value| value != id) {
        return Err(Error::Malformed);
    }
    query.request_id = Some(id);
    s.timeline
        .diagnostics(&auth.proof, "operation_request", &query)
        .await
        .map(Json)
        .map(rss_mdm_http_contract::CollectionResponse)
        .map_err(timeline_error)
}
async fn operation(
    State(s): State<Arc<Services>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((owner, id)): Path<(OperationOwner, Uuid)>,
    PresentedCredentials(headers): PresentedCredentials,
    address: Option<Extension<rss_identity_http_axum::ClientAddress>>,
    params: rss_mdm_http_contract::query::OwnedQuery<LocatorParameters>,
) -> Result<Json<Detail>, Error> {
    if id.is_nil() {
        return Err(Error::Malformed);
    }
    let query = params.parse()?;
    audit.set_action(
        "operation_result_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    s.reads
        .operation(Lookup {
            auth: &auth,
            audit: &audit,
            owner,
            operation: id,
            query: &query,
            headers: &headers,
            address: address.map(|v| v.0.0),
        })
        .await
        .map(Json)
}
struct Discovery;
/// Authentication headers are declared by the existing protection middleware. This borrow lets
/// a separately owned DA authority verify the original credential, without converting proofs.
struct PresentedCredentials(HeaderMap);
impl<S: Send + Sync> axum::extract::FromRequestParts<S> for PresentedCredentials {
    type Rejection = std::convert::Infallible;
    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self(parts.headers.clone()))
    }
}
impl rss_mdm_http_contract::signature::Input for PresentedCredentials {
    fn request() -> rss_mdm_http_contract::signature::Request {
        Default::default()
    }
}
impl rss_mdm_http_contract::query::QueryOwner for Discovery {
    type Parsed = rss_mdm_timeline_service::Query;
    type Error = rss_mdm_timeline_service::Error;
    fn declaration() -> Option<rss_mdm_http_contract::QueryDeclaration> {
        Some(rss_mdm_http_contract::QueryDeclaration::Window(
            &rss_mdm_timeline_service::OPERATION_DIAGNOSTICS,
        ))
    }
    fn parameters() -> rss_mdm_http_contract::signature::Schema {
        rss_mdm_http_contract::signature::Schema::request::<Self::Parsed>()
    }
    fn parse(raw: &str) -> Result<Self::Parsed, Self::Error> {
        rss_mdm_timeline_service::Query::parse(raw, false)
    }
}
struct LocatorParameters;
impl rss_mdm_http_contract::query::QueryOwner for LocatorParameters {
    type Parsed = LocatorQuery;
    type Error = Error;
    fn declaration() -> Option<rss_mdm_http_contract::QueryDeclaration> {
        None
    }
    fn parameters() -> rss_mdm_http_contract::signature::Schema {
        rss_mdm_http_contract::signature::Schema::request::<LocatorQuery>()
    }
    fn parse(raw: &str) -> Result<LocatorQuery, Error> {
        let mut values = serde_json::Map::new();
        for (key, value) in url::form_urlencoded::parse(raw.as_bytes()) {
            let value = if key == "generation" {
                serde_json::Value::from(value.parse::<i64>().map_err(|_| Error::Malformed)?)
            } else if key == "includeAudit" {
                serde_json::Value::Bool(value.parse::<bool>().map_err(|_| Error::Malformed)?)
            } else {
                serde_json::Value::String(value.into_owned())
            };
            if values.insert(key.into_owned(), value).is_some() {
                return Err(Error::Malformed);
            }
        }
        let query: LocatorQuery = serde_json::from_value(serde_json::Value::Object(values))
            .map_err(|_| Error::Malformed)?;
        query.validate()?;
        Ok(query)
    }
}

/// One bounded source query, with request attempts and business history kept distinct.
pub fn split_requests(
    value: Evidence<DiagnosticPage>,
) -> (Evidence<DiagnosticPage>, Evidence<DiagnosticPage>) {
    match value {
        Evidence::Available(page) => {
            let (requests, business) = page.items.into_iter().partition(|v| {
                v.fact.origin == Some(rss_mdm_audit_integration::Origin::Request)
                    && matches!(v.fact.source.as_str(), "mdm.request" | "da.request")
            });
            let requests = DiagnosticPage {
                items: requests,
                next_cursor: page.next_cursor.clone(),
                coverage: page.coverage.clone(),
            };
            let business = DiagnosticPage {
                items: business,
                next_cursor: page.next_cursor,
                coverage: page.coverage,
            };
            (Evidence::Available(business), Evidence::Available(requests))
        }
        Evidence::NotRequested => (Evidence::NotRequested, Evidence::NotRequested),
        Evidence::NotFound => (Evidence::NotFound, Evidence::NotFound),
        Evidence::NoDurableEvidence => (Evidence::NoDurableEvidence, Evidence::NoDurableEvidence),
        Evidence::Restricted => (Evidence::Restricted, Evidence::Restricted),
        Evidence::Unavailable => (Evidence::Unavailable, Evidence::Unavailable),
        Evidence::Expired => (Evidence::Expired, Evidence::Expired),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rss_mdm_http_contract::query::QueryOwner;
    #[test]
    fn locators_reject_ambiguous_dimensions_and_unknown_query_fields() {
        assert!(LocatorParameters::parse("generation=0").is_err());
        assert!(LocatorParameters::parse("device=one&device=two").is_err());
        assert!(LocatorParameters::parse("tenant=another").is_err());
        assert!(LocatorParameters::parse("owner=policy").is_err());
        assert!(
            LocatorParameters::parse("includeAudit=true&generation=2&device=one")
                .unwrap()
                .include_audit
        );
    }
    #[test]
    fn missing_and_unavailable_are_not_expiry_or_success() {
        for (value, expected) in [
            (Evidence::<ReceiptSummary>::NotFound, "not_found"),
            (Evidence::NoDurableEvidence, "no_durable_evidence"),
            (Evidence::Unavailable, "unavailable"),
            (Evidence::Restricted, "restricted"),
        ] {
            let json = serde_json::to_value(value).unwrap();
            assert_eq!(json["availability"], expected);
            assert!(json.get("value").is_none());
        }
    }
}
