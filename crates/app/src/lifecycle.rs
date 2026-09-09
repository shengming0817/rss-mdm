//! Product process lifetime, driven by the existing RSS managed listener.
use crate::{Error, ProcessError, config::Config};
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
) -> Result<(), ProcessError> {
    config
        .validate()
        .map_err(|e| ProcessError::at("startup.configuration", e))?;
    let mut scope = LifecycleScope::<(), ProcessError, std::io::Error>::try_new(
        TotalDrainBudget::new(Duration::from_secs(20))
            .map_err(|_| ProcessError::at("startup.budget", Error::Configuration))?,
    )
    .map_err(|_| ProcessError::at("startup.scope", Error::Unavailable))?;
    let outcome = scope
        .drive(
            |mut startup| {
                Box::pin(async move {
                    let (listener, app) = tokio::time::timeout(Duration::from_secs(15), async {
                        let reader = Arc::new(
                            InventoryReader::connect(config.database.options().map_err(|e| {
                                ProcessError::at("startup.database_configuration", e)
                            })?)
                            .await
                            .map_err(|_| {
                                ProcessError::at(
                                    "startup.reader_connection_or_admission",
                                    Error::Unavailable,
                                )
                            })?,
                        );
                        startup.stage_resource(DynManagedResource::new_box(ReaderResource(
                            reader.clone(),
                        )));
                        let app = crate::application(
                            &config,
                            Arc::new(rss_identity_client::SystemClock),
                            reader,
                        )
                        .await
                        .map_err(|e| ProcessError::at("startup.identity", e))?;
                        let listener =
                            tokio::net::TcpListener::bind(config.listen)
                                .await
                                .map_err(|e| ProcessError::Io {
                                    stage: "startup.listener_bind",
                                    kind: e.kind(),
                                })?;
                        Ok::<_, ProcessError>((listener, app))
                    })
                    .await
                    .map_err(|_| ProcessError::Stage {
                        stage: "startup",
                        kind: "total deadline exceeded",
                    })??;
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
        .map_err(|_| ProcessError::at("lifecycle.drive", Error::Unavailable))?;
    if !outcome.shutdown().as_ref().is_ok_and(|r| r.is_clean()) {
        return Err(ProcessError::Stage {
            stage: "shutdown",
            kind: "resource drain failed",
        });
    }
    match outcome.exit() {
        ScopeExit::StopRequested(Ok(())) => Ok(()),
        ScopeExit::StopRequested(Err(e)) => Err(ProcessError::Io {
            stage: "shutdown.signal",
            kind: e.kind(),
        }),
        ScopeExit::Completed(Err(error)) => Err(error.clone()),
        _ => Err(ProcessError::Stage {
            stage: "lifecycle",
            kind: "critical task or scope terminated",
        }),
    }
}
pub async fn signal() -> Result<(), std::io::Error> {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {r=tokio::signal::ctrl_c()=>r,_=term.recv()=>Ok(())}
}
