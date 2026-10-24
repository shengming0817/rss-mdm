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
    #[test]
    fn explicit_unpublished_access_null_follows_the_write_contract() {
        let schema: serde_json::Value =
            serde_json::from_str(include_str!("../../../schema/PolicyWrite.json")).unwrap();
        let validator = jsonschema::validator_for(&schema).unwrap();
        let body = serde_json::json!({"operationId":uuid::Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":{"scope":uuid::Uuid::new_v4(),"action":{"kind":"execution","resource":{"id":"repair","version":"v1","platform":"macos","architecture":"aarch64","variant":"default"},"parameters":{},"runLifetimeSeconds":300},"selfService":{"access":null,"published":false,"presentation":{"displayName":"Repair","description":"","prerequisites":"","sideEffects":"","category":"Support","keywords":[]}}}}});
        assert!(validator.is_valid(&body));
        let mut missing = body;
        missing["input"]["definition"]["selfService"]
            .as_object_mut()
            .unwrap()
            .remove("access");
        assert!(!validator.is_valid(&missing));
    }
}
