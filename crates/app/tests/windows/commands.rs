use crate::execution::test_support::{Client, native};
use crate::windows::test_support::Host;
#[tokio::test]
#[ignore = "make t2 MODULE=windows.commands"]
async fn enrollment_to_native_command_wiring() -> anyhow::Result<()> {
    let mut host = Host::open().await?;
    host.listen().await?;
    let peer = host.peer().await?;
    let mut client = Client::start(host.browser.clone(), host.app.clone()).await?;
    client.accept_approved().await?;
    client.publish_operation(client.operation).await?;
    let opened = native::begin(&peer.mutual, &peer.url, &peer.message, &peer.ack, 1, None).await?;
    let report = native::report(&opened.first, &opened.gets, "10.0.22631.0", 200);
    let response = native::post(&peer.mutual, &peer.url, &report).await?;
    anyhow::ensure!(response.status() == axum::http::StatusCode::OK);
    let message = rss_mdm_windows_mdm::syncml::decode(
        &response.bytes().await?,
        &rss_mdm_windows_mdm::CodecLimits::default(),
    )?;
    let detail = client
        .call(
            axum::http::Method::GET,
            &format!("/{}", client.operation),
            None,
        )
        .await?;
    anyhow::ensure!(
        message.commands.iter().any(|command| matches!(command,
            rss_mdm_windows_mdm::syncml::Command::Get { items, .. }
            if items.iter().any(|item| item.target.as_deref() == Some("./DevInfo/Mod"))
        )),
        "approved command was not delivered after capability discovery: {message:?}, detail: {detail:?}"
    );
    host.close().await?;
    Ok(())
}
