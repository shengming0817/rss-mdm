use super::*;
#[tokio::test(start_paused = true)]
async fn slow_sources_fit_declared_startup_budget_and_remain_bounded() {
    let mut config: serde_json::Value =
        serde_json::from_str(include_str!("../../../../fixtures/mdm-config.example.json")).unwrap();
    let sources=["one","two","three"].map(|name| {
        serde_json::json!({"name":name,"credentials":{"read-key":"/tmp/read-key"},"target":{"Brew":{"tap":format!("a/{name}"),"repository":format!("/tmp/{name}"),"base":format!("https://mdm.example.test/api/v1/software/native/sources/{name}/"),"artifacts_base":format!("https://mdm.example.test/api/v1/software/native/sources/{name}/artifacts/"),"credential_reference":"read-key"}}})
    });
    config["flow"]["publication"]["sources"] = serde_json::json!(sources);
    let c: crate::config::Config = serde_json::from_value(config).unwrap();
    let result = tokio::time::timeout(c.flow.startup_budget(), async {
        tokio::time::sleep(Duration::from_secs(7)).await;
        for _ in 0..3 {
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    })
    .await;
    assert!(
        result.is_ok(),
        "individually bounded sources exhausted the host budget"
    );
    assert!(
        tokio::time::timeout(c.flow.startup_budget(), std::future::pending::<()>())
            .await
            .is_err()
    );
}
