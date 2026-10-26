use crate::Error;
use axum::http::HeaderMap;
use rss_mdm_audit_integration::RequestAudit;
/// Capture only; validate at the original write-key call, after the existing auth boundary.
pub struct WriteHeaders(HeaderMap);
impl WriteHeaders {
    pub(crate) fn operation_key(&self) -> Result<uuid::Uuid, Error> {
        operation_key(&self.0)
    }
}
impl<S: Send + Sync> axum::extract::FromRequestParts<S> for WriteHeaders {
    type Rejection = std::convert::Infallible;
    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self(parts.headers.clone()))
    }
}
impl rss_mdm_http_contract::signature::Input for WriteHeaders {
    fn request() -> rss_mdm_http_contract::signature::Request {
        use rss_mdm_http_contract::signature::{Request, Schema};
        let mut key = Schema::request::<uuid::Uuid>();
        key.value["not"] = serde_json::json!({"const":"00000000-0000-0000-0000-000000000000"});
        Request {
            headers: [("idempotency-key".into(), key)].into(),
            required_headers: vec!["idempotency-key"],
            ..Request::default()
        }
    }
}
fn operation_key(headers: &HeaderMap) -> Result<uuid::Uuid, Error> {
    if headers.get_all("idempotency-key").iter().count() != 1 {
        return Err(Error::Malformed);
    }
    let id = uuid::Uuid::parse_str(
        headers
            .get("idempotency-key")
            .and_then(|v| v.to_str().ok())
            .ok_or(Error::Malformed)?,
    )
    .map_err(|_| Error::Malformed)?;
    if id.is_nil() {
        return Err(Error::Malformed);
    }
    Ok(id)
}
pub fn write_key(
    headers: &WriteHeaders,
    audit: &RequestAudit,
    action: &'static str,
) -> Result<uuid::Uuid, Error> {
    let key = headers.operation_key()?;
    audit.operation(
        key,
        action,
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    Ok(key)
}
