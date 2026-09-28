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
    native::begin(
        &peer.mutual,
        &peer.url,
        &peer.message,
        &peer.ack,
        1,
        Some("./DevInfo/Mod"),
    )
    .await?;
    host.close().await?;
    Ok(())
}
