//! Device creation rejects native configuration; apple.policy owns the profile lifecycle.
use super::*;
#[tokio::test]
#[ignore = "MODULE=apple.profile: closed device contract over HTTP and PG"]
async fn profile_lifecycle_requires_its_policy_owner() -> Result<()> {
    let mut f = Fixture::start().await?;
    let (_peer, device) = f.ready_local_peer().await?;
    for task in [
        profile_task(Uuid::new_v4(), true),
        ddm::task(vec![ddm::subscription("retired")], vec![]),
    ] {
        let id = Uuid::new_v4();
        let response = f.browser.call(&f.router, Method::POST, &format!("/api/v1/devices/{}/operations", case_device()),
            Some(json!({"operationId":id,"deadline":f.app.clock.unix_seconds()?+300,"inputVersion":"1","target":{"kind":"device"},"task":task}))).await?;
        ensure!(
            response.0 == StatusCode::BAD_REQUEST,
            "retired native input: {response:?}"
        );
        ensure!(
            f.browser
                .call(
                    &f.router,
                    Method::GET,
                    &format!("/api/v1/devices/{}/operations/{id}", case_device()),
                    None
                )
                .await?
                .0
                == StatusCode::NOT_FOUND
        );
    }
    drop(device);
    f.close().await
}
