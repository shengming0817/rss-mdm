use super::*;
pub(crate) fn configuration(base: &Value, server: &crate::publication_support::Server) -> Value {
    let mut cfg = base.clone();
    let origin = base["product_origin"].as_str().unwrap();
    cfg["publication"]["sources"] = json!([{"name":server.logical,"credentials":{},"target":{"Winget":{"base":format!("{origin}/api/v1/software/native/sources/{}/",server.logical),"artifacts_base":format!("{origin}/api/v1/software/native/sources/{}/artifacts/",server.logical)}}}]);
    cfg
}
