use super::*;
#[tokio::test(start_paused = true)]
async fn slow_sources_fit_declared_startup_budget_and_remain_bounded() {
    let mut config: serde_json::Value =
        serde_json::from_str(include_str!("../../../../fixtures/mdm-config.example.json")).unwrap();
    let source = serde_json::json!({"name":"fixture","credentials":{},"rings":{"test":{"Brew":{"tap":"a/test","repository":"/tmp/test"}},"pilot":{"Brew":{"tap":"a/pilot","repository":"/tmp/pilot"}},"production":{"Brew":{"tap":"a/production","repository":"/tmp/production"}}},"artifacts":[],"max_artifact_bytes":1});
    config["flow"]["publication"]["sources"] =
        serde_json::json!([source.clone(), source.clone(), source]);
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
