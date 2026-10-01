use super::*;
pub(crate) fn configuration(base: &Value, server: &crate::publication_support::Server) -> Value {
    let mut cfg = base.clone();
    let source_config = |ring: &str| json!({"Winget":{"base":format!("{}/software/native/sources/{}/{ring}/",base["product_origin"].as_str().unwrap(),server.logical),"artifacts_base":format!("{}/software/native/sources/{}/artifacts/",base["product_origin"].as_str().unwrap(),server.logical)}});
    cfg["flow"]["publication"]["sources"] = json!([{"name":server.logical,"credentials":{},"rings":{"test":source_config("test"),"pilot":source_config("pilot"),"production":source_config("production")}}]);
    cfg
}
