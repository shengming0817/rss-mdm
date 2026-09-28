use super::*;
pub(crate) fn configuration(base: &Value, server: &crate::publication_support::Server) -> Value {
    let mut cfg = base.clone();
    let source_config = |ring: &str| json!({"Winget":{"base":format!("{}{ring}/",server.base),"addresses":[server.address],"private_ca":server.ca,"credential_reference":"source-key"}});
    cfg["flow"]["publication"]["sources"] = json!([{"name":server.logical,"credentials":{"source-key":server.secret},"rings":{"test":source_config("test"),"pilot":source_config("pilot"),"production":source_config("production")},"artifacts":[{"base":format!("{}artifacts/",server.base),"addresses":[server.address],"private_ca":server.ca}],"max_artifact_bytes":1048576}]);
    cfg
}
