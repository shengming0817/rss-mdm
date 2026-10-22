//! Real TCP ingress for protocol fixtures. TLS and authentication remain in the product transport.
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    task::JoinSet,
};

pub(crate) async fn registration(
    listener: TcpListener,
    router: crate::native::TlsRouter,
    audit: Arc<rss_mdm_audit_integration::AuditStore>,
    tenant: String,
    kind: crate::native::NativeListenerKind,
) -> anyhow::Result<rss_runtime::ManagedTaskRegistration> {
    let backend = TcpListener::bind("127.0.0.1:0").await?;
    let target = backend.local_addr()?;
    let native =
        crate::native::tls::registration(backend, router, audit, tenant, kind, target.ip());
    let (task, _) = rss_runtime::ManagedTask::prepare("fixture-ingress", Duration::from_secs(25));
    Ok(task.into_registration(move |cancel| async move {
        let lifecycle: anyhow::Result<()> = async {
            let mut owner = rss_runtime::ShutdownStack::try_new(
                rss_runtime::TotalDrainBudget::new(Duration::from_secs(20))?,
                Arc::new(crate::lifecycle::RuntimeTimer),
            )?;
            owner.startup()?.stage_task_with_token(native);
            let result = forward(listener, target, cancel).await;
            anyhow::ensure!(
                owner.shutdown().join().await?.is_clean(),
                "fixture TLS cleanup failed"
            );
            result
        }
        .await;
        lifecycle.map_err(failed)
    }))
}
pub(crate) fn proxy(
    listener: TcpListener,
    target: SocketAddr,
) -> rss_runtime::ManagedTaskRegistration {
    let (task, _) = rss_runtime::ManagedTask::prepare("fixture-proxy", Duration::from_secs(5));
    task.into_registration(move |cancel| async move {
        forward(listener, target, cancel).await.map_err(failed)
    })
}
fn failed(_: anyhow::Error) -> rss_runtime::ShutdownError {
    rss_runtime::ShutdownError::new(std::io::Error::other("fixture gateway failed"))
}
async fn forward(
    listener: TcpListener,
    target: SocketAddr,
    cancel: tokio_util::sync::CancellationToken,
) -> anyhow::Result<()> {
    let mut connections = JoinSet::new();
    let result = async {
        loop {
            tokio::select! {
                biased;
                () = cancel.cancelled() => break,
                Some(done) = connections.join_next(), if !connections.is_empty() => { done??; }
                accepted = listener.accept(), if connections.len() < 128 => {
                    let (mut incoming, source) = accepted?;
                    let destination = incoming.local_addr()?;
                    connections.spawn(async move {
                        let mut outgoing = TcpStream::connect(target).await?;
                        outgoing.write_all(format!("PROXY TCP4 {} {} {} {}\r\n", source.ip(), destination.ip(), source.port(), destination.port()).as_bytes()).await?;
                        // Peer disconnects are protocol inputs, not fixture infrastructure failures.
                        let _ = tokio::io::copy_bidirectional(&mut incoming, &mut outgoing).await;
                        Ok::<_, anyhow::Error>(())
                    });
                }
            }
        }
        Ok(())
    }.await;
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    result
}
