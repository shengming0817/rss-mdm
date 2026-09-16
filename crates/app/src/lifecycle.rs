//! Product process lifetime, driven by the existing RSS managed listener.
use crate::{ConfigIssue, Failure};
use crate::{Error, ProcessError, config::Config};
use rss_mdm_inventory_postgres::InventoryReader;
use rss_runtime::{
    DynManagedResource, LifecycleScope, ManagedResource, ScopeExit, ShutdownError, TotalDrainBudget,
};
use std::{sync::Arc, time::Duration};
// Product composition chooses the Tokio timer for the RSS lifecycle's time domain.
pub(crate) struct RuntimeTimer;
impl rss_request_context::Clock for RuntimeTimer {
    #[allow(
        clippy::disallowed_methods,
        reason = "concrete product runtime clock owns the Tokio time domain"
    )]
    fn now(&self) -> std::time::Instant {
        tokio::time::Instant::now().into_std()
    }
}
impl rss_request_context::ExecutionTimer for RuntimeTimer {
    async fn sleep_until(&self, deadline: rss_request_context::Deadline) {
        tokio::task::unconstrained(tokio::time::sleep_until(deadline.instant().into())).await;
    }
}
// Preparation includes five seconds of TLS and two seconds of failure audit.
// All three listeners use the same RSS owner and finite protocol budgets.
pub(crate) fn http_policy() -> rss_axum::Http1ServePolicy {
    rss_axum::Http1ServePolicy::new(
        rss_axum::ServePolicy::new(
            128,
            Duration::from_secs(8),
            Duration::from_secs(10),
            Duration::from_secs(10),
        )
        .expect("constant listener budgets are valid"),
        Duration::from_secs(10),
        64,
        32768,
    )
    .expect("constant HTTP/1 limits are valid")
}
struct AccessResource(std::sync::Arc<crate::AccessStore>);
impl ManagedResource for AccessResource {
    fn name(&self) -> &str {
        "access-store"
    }
    async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.0.close().await;
        Ok(())
    }
    fn shutdown_timeout(&self) -> Duration {
        Duration::from_secs(5)
    }
}
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
    monotonic: Arc<dyn rss_observation::Clock>,
) -> Result<(), ProcessError> {
    let readiness = Arc::new(crate::inventory_runtime::Readiness::default());
    let stop_readiness = readiness.clone();
    let stop = async move {
        let result = stop.await;
        stop_readiness.stop();
        result
    };
    let compiled = config
        .compile()
        .map_err(|e| ProcessError::at("startup.configuration", e))?;
    let mut scope = LifecycleScope::<(), ProcessError, std::io::Error>::try_new(
        TotalDrainBudget::new(Duration::from_secs(40)).map_err(|_| {
            ProcessError::at("startup.budget", Error::Configuration(ConfigIssue::Budget))
        })?,
        Arc::new(RuntimeTimer),
    )
    .map_err(|_| ProcessError::at("startup.scope", Error::Unavailable(Failure::Runtime)))?;
    let outcome = scope
        .drive(
            |mut startup| {
                Box::pin(async move {
                    let (
                        listener,
                        app,
                        enrollment_listener,
                        management_listener,
                        access,
                        tenant,
                        runtime,
                    ) = tokio::time::timeout(compiled.config.management.startup_budget(), async {
                        let reader = Arc::new(
                            InventoryReader::connect(compiled.config.database.options().map_err(
                                |e| ProcessError::at("startup.database_configuration", e),
                            )?)
                            .await
                            .map_err(|_| {
                                ProcessError::at(
                                    "startup.reader_connection_or_admission",
                                    Error::Unavailable(Failure::InventoryPool),
                                )
                            })?,
                        );
                        startup.stage_resource(DynManagedResource::new_box(ReaderResource(
                            reader.clone(),
                        )));
                        let access = Arc::new(
                            crate::AccessStore::connect(
                                compiled.config.access_database.options().map_err(|e| {
                                    ProcessError::at("startup.access_configuration", e)
                                })?,
                            )
                            .await
                            .map_err(|e| ProcessError::at("startup.access_store", e))?,
                        );
                        startup.stage_resource(DynManagedResource::new_box(AccessResource(
                            access.clone(),
                        )));
                        use crate::inventory_runtime::{
                            Clock, InventoryRuntime, ObservationResource, ProjectionResource,
                        };
                        let clock = Clock::new(monotonic.clone());
                        let runtime_options =
                            compiled.config.runtime_database.options().map_err(|e| {
                                ProcessError::at("startup.runtime_database_configuration", e)
                            })?;
                        let observation =
                            ObservationResource::open(runtime_options.clone(), clock.clone())
                                .await
                                .map_err(|e| ProcessError::at("startup.observation", e))?;
                        let observation_store = observation.store.clone();
                        startup.stage_resource(DynManagedResource::new_box(observation));
                        let projection = ProjectionResource::open(runtime_options, clock.clone())
                            .await
                            .map_err(|e| ProcessError::at("startup.projection", e))?;
                        let projection_store = projection.store.clone();
                        startup.stage_resource(DynManagedResource::new_box(projection));
                        let runtime = Arc::new(InventoryRuntime::new(
                            observation_store,
                            projection_store,
                            access.clone(),
                            rss_request_context::TenantId::parse(
                                &compiled.config.identity.tenant_id,
                            )
                            .map_err(|_| {
                                assembly_error(Error::Configuration(ConfigIssue::Tenant))
                            })?,
                            clock,
                            readiness,
                        ));
                        let management = compiled
                            .config
                            .management
                            .open(
                                rss_request_context::TenantId::parse(
                                    &compiled.config.identity.tenant_id,
                                )
                                .map_err(|_| assembly_error(Error::Malformed))?,
                                Arc::new(rss_identity_client::SystemClock),
                                |resource| {
                                    startup.stage_resource(DynManagedResource::new_box(resource))
                                },
                            )
                            .await
                            .map_err(|e| ProcessError::at("startup.management", e))?;
                        let listen = compiled.config.listen;
                        let tenant = compiled.config.identity.tenant_id.clone();
                        let app = crate::api::from_compiled(
                            compiled,
                            Arc::new(rss_identity_client::SystemClock),
                            monotonic,
                            reader,
                            access.clone(),
                            runtime.clone(),
                            management,
                        )
                        .await
                        .map_err(assembly_error)?;
                        let listener =
                            tokio::net::TcpListener::bind(listen).await.map_err(|e| {
                                ProcessError::Io {
                                    stage: "startup.listener_bind",
                                    kind: e.kind(),
                                }
                            })?;
                        let enrollment_listener =
                            tokio::net::TcpListener::bind(app.enrollment.listen)
                                .await
                                .map_err(|e| ProcessError::Io {
                                    stage: "startup.enrollment_listener",
                                    kind: e.kind(),
                                })?;
                        let management_listener =
                            tokio::net::TcpListener::bind(app.management.listen)
                                .await
                                .map_err(|e| ProcessError::Io {
                                    stage: "startup.management_listener",
                                    kind: e.kind(),
                                })?;
                        Ok::<_, ProcessError>((
                            listener,
                            app,
                            enrollment_listener,
                            management_listener,
                            access,
                            tenant,
                            runtime,
                        ))
                    })
                    .await
                    .map_err(|_| ProcessError::Stage {
                        stage: "startup",
                        kind: "total deadline exceeded",
                    })??;
                    let mut launch = startup.commit();
                    launch.stage_deferred_task_with_token(runtime.registration().critical());
                    launch.stage_task_with_token(
                        crate::windows::retention::registration(access.clone(), tenant.clone())
                            .critical(),
                    );
                    launch.stage_task_with_token(
                        rss_axum::serve_http1_registration(
                            listener,
                            app.browser,
                            rss_axum::PlainTransport,
                            "mdm-http",
                            http_policy(),
                        )
                        .critical(),
                    );
                    launch.stage_task_with_token(
                        crate::windows::tls::registration(
                            enrollment_listener,
                            app.enrollment,
                            access.clone(),
                            tenant.clone(),
                            "mdm-enrollment-tls",
                        )
                        .critical(),
                    );
                    launch.stage_task_with_token(
                        crate::windows::tls::registration(
                            management_listener,
                            app.management,
                            access,
                            tenant,
                            "mdm-management-tls",
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
        .map_err(|_| ProcessError::at("lifecycle.drive", Error::Unavailable(Failure::Runtime)))?;
    let clean = outcome.shutdown().as_ref().is_ok_and(|r| r.is_clean());
    if let Ok(receipt) = outcome.shutdown() {
        for failure in receipt.failures() {
            use rss_runtime::ShutdownFailureKind as K;
            let kind = match failure.kind {
                K::Failed(_) => "failed",
                K::TimedOut(_) => "timed_out",
                K::Panicked => "panicked",
                K::Cancelled => "cancelled",
                K::TaskUnknown => "task_unknown",
                K::DeadlineExceeded => "deadline_exceeded",
                K::BudgetExhausted => "budget_exhausted",
            };
            eprintln!(
                "{}",
                serde_json::json!({"event":"mdm_shutdown_failure","resource":failure.name,"kind":kind})
            );
        }
    }
    finish(outcome.exit(), clean)
}
fn assembly_error(error: Error) -> ProcessError {
    let stage = match error {
        Error::Configuration(ConfigIssue::EnrollmentCa) => "startup.windows_ca",
        Error::Configuration(ConfigIssue::ProtocolKey) => "startup.protocol_key",
        Error::Configuration(ConfigIssue::WindowsTls) => "startup.windows_tls",
        Error::Configuration(ConfigIssue::WindowsListeners) => "startup.windows_listeners",
        _ => "startup.identity",
    };
    ProcessError::at(stage, error)
}
fn finish(
    exit: &ScopeExit<(), ProcessError, std::io::Error>,
    clean: bool,
) -> Result<(), ProcessError> {
    match exit {
        ScopeExit::CriticalTaskExited(exit) => Err(ProcessError::CriticalTask {
            task: exit.name().into(),
            reason: exit.reason(),
            cleanup_failed: !clean,
        }),
        ScopeExit::Completed(Err(error)) => Err(error.clone()),
        _ if !clean => Err(ProcessError::Stage {
            stage: "shutdown",
            kind: "resource drain failed",
        }),
        ScopeExit::StopRequested(Ok(())) => Ok(()),
        ScopeExit::StopRequested(Err(e)) => Err(ProcessError::Io {
            stage: "shutdown.signal",
            kind: e.kind(),
        }),
        _ => Err(ProcessError::Stage {
            stage: "lifecycle",
            kind: "scope terminated",
        }),
    }
}
pub async fn signal() -> Result<(), std::io::Error> {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {r=tokio::signal::ctrl_c()=>r,_=term.recv()=>Ok(())}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn critical_listener_exit_retains_name_and_cleanup_outcome() {
        for name in ["mdm-enrollment-tls", "mdm-management-tls"] {
            let mut scope = LifecycleScope::<(), ProcessError, std::io::Error>::try_new(
                TotalDrainBudget::new(Duration::from_secs(2)).unwrap(),
                Arc::new(RuntimeTimer),
            )
            .unwrap();
            let outcome = scope
                .drive(
                    |startup| {
                        Box::pin(async move {
                            let mut launch = startup.commit();
                            let (task, _) =
                                rss_runtime::ManagedTask::prepare(name, Duration::from_secs(1));
                            launch.stage_task_with_token(
                                task.into_registration(|_| async {
                                    Err(ShutdownError::new(std::io::Error::other(
                                        "synthetic-secret",
                                    )))
                                })
                                .critical(),
                            );
                            launch.finish();
                            std::future::pending().await
                        })
                    },
                    std::future::pending(),
                )
                .await
                .unwrap();
            let diagnostic = finish(outcome.exit(), false).unwrap_err().to_string();
            assert!(diagnostic.contains(name) && diagnostic.contains("cleanup_failed=true"));
            assert!(!diagnostic.contains("synthetic-secret"));
        }
    }
    #[test]
    fn assembly_failures_identify_windows_inputs() {
        for (issue, stage) in [
            (ConfigIssue::EnrollmentCa, "startup.windows_ca"),
            (ConfigIssue::ProtocolKey, "startup.protocol_key"),
            (ConfigIssue::WindowsTls, "startup.windows_tls"),
        ] {
            assert!(
                assembly_error(Error::Configuration(issue))
                    .to_string()
                    .starts_with(stage)
            );
        }
    }
}
