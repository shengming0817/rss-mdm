use crate::Error;
use axum::http::HeaderMap;
use rss_mdm_audit_integration::RequestAudit;
fn operation_key(headers: &HeaderMap) -> Result<uuid::Uuid, Error> {
    if headers.get_all("idempotency-key").iter().count() != 1 {
        return Err(Error(rss_mdm_flow_service::Error::Malformed));
    }
    let id = uuid::Uuid::parse_str(
        headers
            .get("idempotency-key")
            .and_then(|v| v.to_str().ok())
            .ok_or(Error(rss_mdm_flow_service::Error::Malformed))?,
    )
    .map_err(|_| Error(rss_mdm_flow_service::Error::Malformed))?;
    if id.is_nil() {
        return Err(Error(rss_mdm_flow_service::Error::Malformed));
    }
    Ok(id)
}
pub fn write_key(
    headers: &HeaderMap,
    audit: &RequestAudit,
    action: &'static str,
) -> Result<uuid::Uuid, Error> {
    let key = operation_key(headers)?;
    audit.operation(key, action);
    Ok(key)
}
