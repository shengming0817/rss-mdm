//! User channel identity does not reopen generic device execution.
use super::*;
#[tokio::test]
#[ignore = "MODULE=apple.status: closed execution scope and authenticated user channel"]
async fn status_authority_and_user_scope_are_independent() -> Result<()> {
    let mut f = Fixture::start().await?;
    let (peer, device) = f.ready_local_peer().await?;
    let user = Uuid::new_v4();
    peer.user_token(user, 45).await?;
    ensure!(
        peer.user_manage(user, "Idle", None, None)
            .await?
            .1
            .is_empty()
    );
    let response=f.browser.call(&f.router,Method::POST,&format!("/api/v1/devices/{}/operations",case_device()),
        Some(json!({"operationId":Uuid::new_v4(),"deadline":f.app.clock.unix_seconds()?+300,"action":{"kind":"restart"},"target":{"kind":"user","userId":user}}))).await?;
    ensure!(
        response.0 == StatusCode::BAD_REQUEST,
        "user target accepted: {response:?}"
    );
    drop(device);
    f.close().await
}
