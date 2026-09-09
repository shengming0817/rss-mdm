//! Product process lifetime, driven by the existing RSS managed listener.
use crate::{Error, config::Config};
use rss_mdm_inventory_postgres::InventoryReader;
use rss_runtime::{
    DynManagedResource, LifecycleScope, ManagedResource, ScopeExit, ShutdownError, TotalDrainBudget,
};
use std::{sync::Arc, time::Duration};
struct ReaderResource(Arc<InventoryReader>);
impl ManagedResource for ReaderResource {
    fn name(&self) -> &str {
        "inventory-reader"
    }
    async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.0.close().await;
        Ok(())
    }
    fn shutdown_timeout(&self) -> Duration {
        Duration::from_secs(5)
    }
}
pub async fn serve(
    config: Config,
    stop: impl std::future::Future<Output = Result<(), std::io::Error>>,
) -> Result<(), Error> {
    config.validate()?;
    let mut scope = LifecycleScope::<(), Error, std::io::Error>::try_new(
        TotalDrainBudget::new(Duration::from_secs(20)).map_err(|_| Error::Configuration)?,
    )
    .map_err(|_| Error::Unavailable)?;
    let outcome = scope
        .drive(
            |mut startup| {
                Box::pin(async move {
                    let reader = Arc::new(
                        InventoryReader::connect(config.database.options()?)
                            .await
                            .map_err(|_| Error::Unavailable)?,
                    );
                    startup.stage_resource(DynManagedResource::new_box(ReaderResource(
                        reader.clone(),
                    )));
                    let app = tokio::time::timeout(
                        Duration::from_secs(15),
                        crate::application(
                            &config,
                            Arc::new(rss_identity_client::SystemClock),
                            reader,
                        ),
                    )
                    .await
                    .map_err(|_| Error::Unavailable)??;
                    let listener = tokio::net::TcpListener::bind(config.listen)
                        .await
                        .map_err(|_| Error::Unavailable)?;
                    let mut launch = startup.commit();
                    launch.stage_task_with_token(
                        rss_axum::serve_http1_registration(
                            listener,
                            app,
                            "mdm-http",
                            Duration::from_secs(10),
                        )
                        .critical(),
                    );
                    launch.finish();
                    std::future::pending().await
                })
            },
            stop,
        )
        .await
        .map_err(|_| Error::Unavailable)?;
    if !outcome.shutdown().as_ref().is_ok_and(|r| r.is_clean()) {
        return Err(Error::Unavailable);
    }
    match outcome.exit() {
        ScopeExit::StopRequested(Ok(())) => Ok(()),
        ScopeExit::Completed(Err(error)) => Err(*error),
        _ => Err(Error::Unavailable),
    }
}
pub async fn signal() -> Result<(), std::io::Error> {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! { r=tokio::signal::ctrl_c()=>r,_=term.recv()=>Ok(()) }
}
