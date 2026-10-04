pub(crate) use rss_mdm_flow_service::planning::policies::*;
pub mod http;
#[path = "preview.rs"]
mod http_preview;
use crate::Error;
use rss_mdm_audit_integration::RequestAudit;
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;
#[cfg(test)]
mod schema_tests {
    #[test]
    fn management_policy_schemas_follow_the_actual_http_envelope_and_aggregate() {
        let actual = serde_json::to_value(schemars::schema_for!(
            rss_mdm_flow_service::operation::Operation<rss_mdm_policy::Change>
        ))
        .unwrap();
        let published: serde_json::Value =
            serde_json::from_str(include_str!("../../../schema/PolicyWrite.json")).unwrap();
        assert_eq!(actual, published);
        let actual = serde_json::to_value(schemars::schema_for!(rss_mdm_policy::View)).unwrap();
        let published: serde_json::Value =
            serde_json::from_str(include_str!("../../../schema/Policy.json")).unwrap();
        assert_eq!(actual, published);
    }
}
