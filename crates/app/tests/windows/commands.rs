use crate::execution::test_support::{Client, native};
use crate::windows::test_support::Host;
#[tokio::test]
#[ignore = "make t2 MODULE=windows.commands"]
async fn current_credential_to_native_command_wiring() -> anyhow::Result<()> {
    let mut host = Host::open().await?;
    host.listen().await?;
    let peer = host.peer().await?;
    let mut client = Client::start(host.browser.clone(), host.app.clone()).await?;
    let warm = native::begin(&peer.mutual, &peer.url, &peer.message, &peer.ack, 1, None).await?;
    anyhow::ensure!(
        native::post(
            &peer.mutual,
            &peer.url,
            &native::report(&warm.first, &warm.gets, "10.0.22631.0", 200)
        )
        .await?
        .status()
            == axum::http::StatusCode::OK
    );
    client.accept_authorized().await?;
    client.publish_operation(client.operation).await?;
    let opened = native::begin(&peer.mutual, &peer.url, &peer.message, &peer.ack, 2, None).await?;
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
        opened.response.commands.iter().chain(message.commands.iter()).filter(|command| matches!(command,
            rss_mdm_windows_mdm::syncml::Command::Exec { items, .. }
            if items.iter().any(|item| item.target.as_deref() == Some("./Device/Vendor/MSFT/Reboot/RebootNow"))
        )).count() == 1,
        "authorized command was not delivered after capability discovery: {message:?}, detail: {detail:?}"
    );
    host.close().await?;
    Ok(())
}
